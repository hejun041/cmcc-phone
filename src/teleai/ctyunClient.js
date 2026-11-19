'use strict';

/**
 * 天翼云电脑（desk.ctyun.cn / pc.ctyun.cn）传输层复刻
 * 依据客户端 main.1fb514.js（版本 204000200）实现：
 *   1) GET  /api/cdserv/client/getServData
 *   2) POST /api/auth/client/negotiationEncKey  RSA-2048(PKCS1v1.5) 换 32 字节 AES key
 *   3) 请求体 {data: base64(AES-256-CBC(JSON, key=evalue, iv=0))} + CTG-REQDATA-ETYPE:2 + CTG-NEGO-EKEYID
 *   4) 响应带 ctg-rspdata-etype:2 时 body.edata 用同一 key 解密
 *   5) 登录态：CTG-TENANTID / CTG-USERID / CTG-SIGNATURESTR = md5(...).toUpperCase()
 */

const crypto = require('crypto');

const DEFAULTS = {
  base: 'https://desk.ctyun.cn:8810',
  appModel: '2',
  deviceType: '60',
  version: '204000200',
  softwareCode: 'web_client',
  origin: 'https://pc.ctyun.cn',
};

const ALNUM = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';

function randomDeviceCode() {
  let s = '';
  for (let i = 0; i < 32; i += 1) s += ALNUM[crypto.randomInt(ALNUM.length)];
  return `web_${s}`;
}

function aesEncrypt(plain, key, iv = Buffer.alloc(16)) {
  const c = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'utf8'), iv);
  return Buffer.concat([c.update(Buffer.from(plain, 'utf8')), c.final()]).toString('base64');
}

function aesDecrypt(b64, key, iv = Buffer.alloc(16)) {
  const d = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'utf8'), iv);
  return Buffer.concat([d.update(Buffer.from(b64, 'base64')), d.final()]).toString('utf8');
}

function signMd5({ deviceType, requestId, tenantId = 0, timestamp, userId = 0, version, secretKey = '' }) {
  const raw = `${deviceType}${requestId}${tenantId}${timestamp}${userId}${version}${secretKey}`;
  return crypto.createHash('md5').update(raw, 'utf8').digest('hex').toUpperCase();
}

class CtyunClient {
  constructor(opts = {}) {
    Object.assign(this, DEFAULTS);
    for (const k of Object.keys(opts)) if (opts[k] !== undefined) this[k] = opts[k];
    this.deviceCode = this.deviceCode || randomDeviceCode();
    this.eid = '';
    this.evalue = '';
    this.authData = null;
    this._seq = 0;
    this._lastReq = 0;
  }

  _requestId() {
    let v = Date.now() + this._seq;
    this._seq += 1;
    if (v <= this._lastReq) v = this._lastReq + 1;
    this._lastReq = v;
    return String(v);
  }

  _headers({ reqId, timestamp, encrypt }) {
    const h = {
      'CTG-APPMODEL': this.appModel,
      'CTG-DEVICECODE': this.deviceCode,
      'CTG-DEVICETYPE': this.deviceType,
      'CTG-REQUESTID': reqId,
      'CTG-SOFTWARECODE': this.softwareCode,
      'CTG-TIMESTAMP': String(timestamp),
      'CTG-VERSION': this.version,
      Origin: this.origin,
      Referer: `${this.origin}/`,
    };
    if (encrypt && this.eid) {
      h['CTG-REQDATA-ETYPE'] = '2';
      h['CTG-NEGO-EKEYID'] = this.eid;
    }
    if (this.authData) {
      const { tenantId = 0, userId = 0, secretKey = '', token = '' } = this.authData;
      h['CTG-TENANTID'] = String(tenantId);
      h['CTG-USERID'] = String(userId);
      h['CTG-SIGNATURESTR'] = signMd5({
        deviceType: this.deviceType,
        requestId: reqId,
        tenantId,
        timestamp,
        userId,
        version: this.version,
        secretKey,
      });
      if (token) h['X-AUTH-TOKEN'] = token;
    }
    return h;
  }

  async getServData() {
    const r = await fetch(`${this.base}/api/cdserv/client/getServData`, {
      headers: this._headers({ reqId: this._requestId(), timestamp: Date.now(), encrypt: false }),
    });
    return r.json();
  }

  /** 协商 AES key：RSA(PKCS1 v1.5) + AES-256-CBC(zero iv) */
  async negotiate() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicExponent: 0x10001,
    });
    const certData = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    const r = await fetch(`${this.base}/api/auth/client/negotiationEncKey`, {
      method: 'POST',
      headers: {
        ...this._headers({ reqId: this._requestId(), timestamp: Date.now(), encrypt: false }),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ etype: '2', certType: '2', certData }),
    });
    const j = await r.json();
    if (j.code !== 0) throw new Error(`negotiationEncKey failed: ${JSON.stringify(j)}`);
    const raw = crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING },
      Buffer.from(j.data.encKey, 'base64')
    );
    const aesKey = raw.toString('utf8');
    if (Buffer.byteLength(aesKey) !== 32) throw new Error('unexpected AES key length');
    let info;
    try {
      info = JSON.parse(aesDecrypt(j.data.encData, aesKey));
    } catch (_) {
      info = JSON.parse(raw.toString('utf8'));
    }
    this.eid = info.eid;
    this.evalue = info.evalue;
    return { eid: this.eid, evalue: this.evalue };
  }

  async request(path, { method = 'POST', data, params, anonymous = false, token, raw = false } = {}) {
    const reqId = this._requestId();
    const timestamp = Date.now();
    const h = this._headers({ reqId, timestamp, encrypt: Boolean(this.evalue) });
    if (token) h['X-AUTH-TOKEN'] = token;
    let url = `${this.base}/api/${String(path).replace(/^\/+/, '').replace(/^api\//, '')}`;
    let body;
    if (method === 'GET') {
      const q = new URLSearchParams(params || {}).toString();
      if (this.evalue && q) url += `${url.includes('?') ? '&' : '?'}eUrlParams=${encodeURIComponent(aesEncrypt(q, this.evalue))}`;
      else if (q) url += `?${q}`;
    } else {
      h['Content-Type'] = 'application/json';
      const payload = data === undefined ? {} : data;
      body = this.evalue ? JSON.stringify({ data: aesEncrypt(JSON.stringify(payload), this.evalue) }) : JSON.stringify(payload);
    }
    const res = await fetch(url, { method, headers: h, body });
    const text = await res.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch (_) {
      throw new Error(`${path} 非 JSON 响应: ${text.slice(0, 200)}`);
    }
    if (!raw && res.headers.get('ctg-rspdata-etype') === '2' && json && typeof json.edata === 'string') {
      json = JSON.parse(aesDecrypt(json.edata, this.evalue));
    }
    return { status: res.status, body: json };
  }

  /** 用 TeleAgent connectURL 里的 token 换桌面连接信息（匿名） */
  async connectByToken(connectToken, { osType = 'windows', deviceType = this.deviceType, from = '_ai_target_' } = {}) {
    const payload = { connectToken, osType, deviceType };
    if (from) payload.from = from;
    const r = await this.request('desktop/client/getConnectDataByToken', { data: payload, anonymous: true });
    return r.body;
  }
}

module.exports = { CtyunClient, randomDeviceCode, signMd5, aesEncrypt, aesDecrypt };
