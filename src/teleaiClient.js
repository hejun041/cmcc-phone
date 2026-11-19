'use strict';

/**
 * 星辰超级智能体电脑（TeleAgent）客户端
 * ---------------------------------------------------------------
 * 登录：www.teleai.com.cn UPMS 账号密码（AES-128-GCM 密码包 + RSA-OAEP 包 key + AJ-Captcha 滑块）
 * 业务：agent.teleai.com.cn /teleagent-manager/v1/*（Cookie: operationToken）
 *
 * 关键协议细节（均已实测）：
 *   - 密码明文是「裸密码串」，不是 JSON；AAD = loginName&keyId&timestamp&requestId&clientId
 *   - captchaCheckResult 必须是对象 { captchaVerification }
 *   - captchaVerification = AES-128-ECB(token + "---" + JSON.stringify({x,y:5}), secretKey)
 *   - 登录成功后 GET redirectUri 会直接下发 operationToken Cookie
 */

const crypto = require('crypto');
const { solvePuzzle } = require('./teleaiCaptcha');

const AUTH_BASE = 'https://www.teleai.com.cn';
const AGENT_BASE = 'https://agent.teleai.com.cn';
const CLIENT_ID = 'Z2veLLEHhZfq3hb5hWIwqJuPajIuasYi';
const REDIRECT_URI = `${AGENT_BASE}/superCowork/sapi/cowork/auth?appVersion=`;
const UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

class TeleaiAuthError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'TeleaiAuthError';
    this.code = code;
  }
}

class CookieJar {
  constructor() {
    this.items = [];
  }
  add(url, setCookies) {
    const host = new URL(url).hostname;
    for (const raw of setCookies || []) {
      const [pair, ...attrs] = String(raw).split(';');
      const idx = pair.indexOf('=');
      if (idx < 0) continue;
      const name = pair.slice(0, idx).trim();
      const value = pair.slice(idx + 1).trim();
      let domain = host;
      for (const attr of attrs) {
        const [k, v] = attr.split('=');
        if (/^\s*domain$/i.test(k)) domain = String(v).trim().replace(/^\./, '');
      }
      this.items = this.items.filter((c) => !(c.name === name && c.domain === domain));
      this.items.push({ name, value, domain });
    }
  }
  header(url) {
    const host = new URL(url).hostname;
    return this.items
      .filter((c) => host === c.domain || host.endsWith('.' + c.domain))
      .map((c) => `${c.name}=${c.value}`)
      .join('; ');
  }
  get(name) {
    const hit = this.items.filter((c) => c.name === name);
    return hit.length ? hit[hit.length - 1].value : null;
  }
}

function aesEcbBase64(text, key) {
  const cipher = crypto.createCipheriv(`aes-${key.length * 8}-ecb`, Buffer.from(key, 'utf8'), null);
  return Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]).toString('base64');
}

class TeleaiClient {
  constructor({ fetchImpl = fetch, timeoutMs = 20000 } = {}) {
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
  }

  async _fetch(url, options = {}, jar = null) {
    const headers = { 'User-Agent': UA, ...(options.headers || {}) };
    if (jar) {
      const cookie = jar.header(url);
      if (cookie) headers.Cookie = cookie;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(url, { ...options, headers, signal: controller.signal, redirect: 'manual' });
      if (jar && typeof res.headers.getSetCookie === 'function') {
        jar.add(url, res.headers.getSetCookie());
      }
      const text = await res.text();
      let json = null;
      try {
        json = JSON.parse(text);
      } catch (_) {
        json = null;
      }
      return { status: res.status, headers: res.headers, text, json, location: res.headers.get('location') };
    } finally {
      clearTimeout(timer);
    }
  }

  /** 1) OAuth authorize：拿到登录流程 Cookie（uc_login_flow 等） */
  async beginAuthFlow(jar = new CookieJar()) {
    const authorize = `${AUTH_BASE}/aicloud-api/upms/public/auth/authorize?redirect_uri=${encodeURIComponent(
      REDIRECT_URI
    )}&client_id=${CLIENT_ID}`;
    const first = await this._fetch(authorize, {}, jar);
    if (!first.location) throw new TeleaiAuthError('登录入口异常：未返回跳转地址', 'NO_REDIRECT');
    await this._fetch(new URL(first.location, AUTH_BASE).toString(), {}, jar);
    return jar;
  }

  /** 2) 滑块验证码：取图 → 求解 → check → captchaVerification */
  async solveCaptcha(jar, attempts = 5) {
    const headers = { 'Content-Type': 'application/json', Origin: AUTH_BASE, Referer: `${AUTH_BASE}/master-auth` };
    let lastError = '';
    for (let i = 0; i < attempts; i += 1) {
      const got = await this._fetch(`${AUTH_BASE}/teleai-api/upms/public/captcha/get`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ captchaType: 'blockPuzzle' }),
      }, jar);
      const data = got.json && got.json.repData;
      if (!data) throw new TeleaiAuthError('获取图形验证码失败：' + got.text.slice(0, 120), 'CAPTCHA_GET');

      const solved = solvePuzzle(data.originalImageBase64, data.jigsawImageBase64);
      for (const x of solved.candidates.slice(0, 2)) {
        const pointJson = aesEcbBase64(JSON.stringify({ x, y: 5 }), data.secretKey);
        const chk = await this._fetch(`${AUTH_BASE}/teleai-api/upms/public/captcha/check`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ captchaType: 'blockPuzzle', pointJson, token: data.token }),
        }, jar);
        if (chk.json && chk.json.repCode === '0000') {
          return {
            verification: aesEcbBase64(`${data.token}---${JSON.stringify({ x, y: 5 })}`, data.secretKey),
            x,
            attempts: i + 1,
          };
        }
        lastError = chk.json ? `${chk.json.repCode} ${chk.json.repMsg || ''}` : chk.status;
      }
    }
    throw new TeleaiAuthError('图形验证码未通过：' + lastError, 'CAPTCHA_FAIL');
  }

  /** 3) 账号密码登录 → operationToken（不需要浏览器） */
  async loginWithPassword(loginName, password) {
    const name = String(loginName || '').trim().toLowerCase();
    if (!name || !password) throw new TeleaiAuthError('账号和密码不能为空', 'BAD_INPUT');

    const jar = await this.beginAuthFlow();
    const captcha = await this.solveCaptcha(jar);

    const rsaRes = await this._fetch(`${AUTH_BASE}/teleai-api/upms/public/auth/getRsaPublicKey`, {
      headers: { Origin: AUTH_BASE, Referer: `${AUTH_BASE}/master-auth` },
    }, jar);
    if (!rsaRes.json || rsaRes.json.code !== '10980001') {
      throw new TeleaiAuthError('获取登录公钥失败：' + rsaRes.text.slice(0, 120), 'RSA');
    }
    const keyId = rsaRes.json.data.keyId;

    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicExponent: 0x10001,
    });
    const aesKey = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const timestamp = Date.now();
    const requestId = crypto.randomUUID();
    const aad = `loginName=${name}&keyId=${keyId}&timestamp=${timestamp}&requestId=${requestId}&clientId=${CLIENT_ID}`;

    const gcm = crypto.createCipheriv('aes-128-gcm', aesKey, iv);
    gcm.setAAD(Buffer.from(aad, 'utf8'));
    // 注意：明文是裸密码串
    const ciphertext = Buffer.concat([gcm.update(String(password), 'utf8'), gcm.final()]);
    const tag = gcm.getAuthTag();

    const serverPub = crypto.createPublicKey({
      key: Buffer.from(rsaRes.json.data.publicKey, 'base64'),
      format: 'der',
      type: 'spki',
    });
    const encryptedKeyIv = crypto
      .publicEncrypt(
        { key: serverPub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        Buffer.concat([aesKey, iv])
      )
      .toString('base64');

    const payload = {
      loginName: name,
      keyId,
      timestamp,
      requestId,
      redirectUri: REDIRECT_URI,
      clientId: CLIENT_ID,
      encryptedKeyIv,
      ciphertext: ciphertext.toString('base64'),
      tag: tag.toString('base64'),
      invitationCode: '',
      captchaCheckResult: { captchaVerification: captcha.verification },
      publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    };

    const res = await this._fetch(`${AUTH_BASE}/teleai-api/upms/public/auth/accountNameLogin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: AUTH_BASE, Referer: `${AUTH_BASE}/master-auth` },
      body: JSON.stringify(payload),
    }, jar);

    const body = res.json || {};
    if (body.code !== '10980001') {
      const err = new TeleaiAuthError(body.message || `登录失败(${body.code || res.status})`, body.code || 'LOGIN_FAIL');
      err.detail = body;
      throw err;
    }

    // 4) 跟随 redirectUri 换 operationToken Cookie
    const data = body.data || {};
    let code = null;
    try {
      code = new URL(data.redirectUri).searchParams.get('code');
    } catch (_) {
      code = null;
    }
    if (data.redirectUri) await this._fetch(data.redirectUri, {}, jar);
    let operationToken = jar.get('operationToken');
    let operToken = jar.get('operToken');
    if (!operationToken && code) {
      const sess = await this._fetch(
        `${AGENT_BASE}/superCowork/sapi/api/v1/auth/session?code=${encodeURIComponent(code)}`,
        {},
        jar
      );
      operationToken = (sess.json && (sess.json.operationToken || (sess.json.data && sess.json.data.operationToken))) || jar.get('operationToken');
      operToken = operToken || (sess.json && sess.json.oper_token);
    }
    if (!operationToken) throw new TeleaiAuthError('登录成功但未取得 operationToken', 'NO_TOKEN');

    return {
      operationToken,
      rawOperationToken: operationToken,
      operToken: operToken || '',
      aesKey: data.aesKey || '',
      aesIv: data.aesIv || '',
      aesSeq: data.aesSeq || '',
      expiresAt: data.expiresAt ? data.expiresAt * 1000 : null,
      refreshToken: data.refreshToken || '',
      code,
      loginName: name,
    };
  }

  _agentHeaders(acc, extra = {}) {
    const cookie = [`operationToken=${acc.operationToken || ''}`];
    if (acc.operToken) cookie.push(`operToken=${acc.operToken}`);
    return {
      'Content-Type': 'application/json',
      'X-Client-Platform': 'web',
      Origin: AGENT_BASE,
      Referer: `${AGENT_BASE}/teleagent`,
      Cookie: cookie.join('; '),
      ...extra,
    };
  }

  _unwrap(res, action) {
    const body = res.json;
    if (res.status === 401 || (body && String(body.code) === '4001') || (body && body.error && String(body.error.code) === '4001')) {
      throw new TeleaiAuthError('云端登录已失效，请重新登录', '4001');
    }
    if (res.status < 200 || res.status >= 300) {
      throw new Error(`实例服务请求失败（HTTP ${res.status}）`);
    }
    if (!body || typeof body !== 'object') throw new Error('实例服务响应格式异常');
    if (body.code !== undefined && !['0', '200'].includes(String(body.code))) {
      throw new Error((body.error && body.error.message) || body.message || '实例服务返回异常');
    }
    if (body.error && body.error.code !== undefined && String(body.error.code) !== '0') {
      throw new Error(body.error.message || '实例服务返回异常');
    }
    if (action === 'start' && !String(res.text || '').trim()) return null;
    return body.data !== undefined ? body.data : body;
  }

  async listInstances(acc) {
    const res = await this._fetch(`${AGENT_BASE}/teleagent-manager/v1/instance/list`, {
      headers: this._agentHeaders(acc),
    });
    const data = this._unwrap(res, 'list');
    if (!Array.isArray(data)) throw new Error('实例列表格式异常');
    return data;
  }

  /** start / restart / cancel / connect / heartbeat / refresh / create / rebuild */
  async instanceAction(acc, action, instanceId) {
    const withId = ['start', 'restart', 'cancel', 'connect', 'heartbeat', 'refresh', 'rebuild'];
    if (withId.includes(action) && !String(instanceId || '').trim()) throw new Error('实例 id 不能为空');
    const body = action === 'list' ? undefined : JSON.stringify(withId.includes(action) ? { id: instanceId } : {});
    const res = await this._fetch(`${AGENT_BASE}/teleagent-manager/v1/instance/${action}`, {
      method: action === 'list' ? 'GET' : 'POST',
      headers: this._agentHeaders(acc),
      body,
    });
    return this._unwrap(res, action);
  }

  /** 进入控制：用 connect 换一次性桌面入口 */
  async connect(acc, instanceId) {
    const data = await this.instanceAction(acc, 'connect', instanceId);
    return {
      connectURL: (data && (data.connectURL || data.connectUrl)) || '',
      previewURL: (data && (data.previewURL || data.previewUrl)) || '',
      raw: data,
    };
  }

  async validate(acc) {
    const list = await this.listInstances(acc);
    return { ok: true, instances: list };
  }

  /** 服务状态（可选，用于探活） */
  async serviceStatus(acc) {
    const res = await this._fetch(`${AGENT_BASE}/teleagent-manager/v1/service/status`, {
      headers: this._agentHeaders(acc),
    });
    return this._unwrap(res, 'status');
  }
}

module.exports = { TeleaiClient, TeleaiAuthError, CLIENT_ID, REDIRECT_URI, AUTH_BASE, AGENT_BASE };
