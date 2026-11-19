'use strict';

const MESSAGES = {
  YUNZHI_DISABLED: '云智渠道尚未配置，请联系管理员',
  YUNZHI_AUTH_EXPIRED: '云智账号登录已失效，请重新短信验证',
  YUNZHI_UNAVAILABLE: '云智服务暂时不可用，请稍后重试',
  YUNZHI_TIMEOUT: '云智服务响应超时，请稍后重试',
  CAPABILITY_UNSUPPORTED: '云智渠道暂不支持此操作',
  CAPTCHA_EXPIRED: '安全验证已过期，请重新获取',
  INVALID_CAPTCHA: '安全验证无效，请重新获取',
  SMS_NOT_SENT: '请先完成滑块并发送短信验证码',
  SMS_CODE_INVALID: '验证码错误或已过期',
  RATE_LIMITED: '请求过于频繁，请稍后重试',
  ACCOUNT_NOT_FOUND: '未找到该云智账号或无权操作',
  ACCOUNT_BUSY: '云智账号正在执行任务，请稍后重试',
  ACCOUNT_DISABLED: '云智账号已停用，请先在云智服务中启用',
  SHARED_SCHEDULER_MANAGED: '此共享账号的签到任务由原青龙管理',
  ACCOUNT_BINDING_CHANGED: '云智账号绑定已变更，请重新验证',
  IDEMPOTENCY_CONFLICT: '任务请求已变更，请刷新后重试',
};

const BRIDGE_CODES = {
  YUNZHI_CHALLENGE_EXPIRED: 'CAPTCHA_EXPIRED', YUNZHI_SLIDER_INVALID: 'INVALID_CAPTCHA',
  YUNZHI_SMS_REQUIRED: 'SMS_NOT_SENT', YUNZHI_CODE_INVALID: 'SMS_CODE_INVALID',
  YUNZHI_VERIFY_REJECTED: 'SMS_CODE_INVALID', YUNZHI_SMS_REJECTED: 'INVALID_CAPTCHA',
  YUNZHI_RATE_LIMITED: 'RATE_LIMITED', YUNZHI_VERIFY_RATE_LIMITED: 'RATE_LIMITED',
  YUNZHI_ACCOUNT_NOT_FOUND: 'ACCOUNT_NOT_FOUND', YUNZHI_DEVICE_NOT_FOUND: 'ACCOUNT_NOT_FOUND',
  YUNZHI_JOB_NOT_FOUND: 'ACCOUNT_NOT_FOUND', YUNZHI_BINDING_CHANGED: 'ACCOUNT_BINDING_CHANGED',
  YUNZHI_PHONE_MISMATCH: 'ACCOUNT_BINDING_CHANGED', YUNZHI_ACTIVE_JOB: 'ACCOUNT_BUSY',
  YUNZHI_REQUEST_CONFLICT: 'IDEMPOTENCY_CONFLICT', YUNZHI_POWER_UNSUPPORTED: 'CAPABILITY_UNSUPPORTED',
  YUNZHI_ACCOUNT_DISABLED: 'ACCOUNT_DISABLED',
  YUNZHI_SHARED_SCHEDULER_MANAGED: 'SHARED_SCHEDULER_MANAGED',
};

function bridgeError(code, status = 502) {
  const safeCode = Object.hasOwn(MESSAGES, code) ? code : 'YUNZHI_UNAVAILABLE';
  return Object.assign(new Error(MESSAGES[safeCode]), { code: safeCode, status });
}

function reference(value) {
  const id = String(value || '');
  if (!/^[A-Za-z0-9_-]{1,160}$/.test(id)) throw new Error('云智账号或设备引用无效');
  return id;
}

function capabilities(value = {}) {
  return {
    stream: value.stream === true, touch: value.touch === true,
    power: Array.isArray(value.power) ? value.power.filter((a) => ['wakeup', 'reboot', 'shutdown'].includes(a)) : [],
    screenshot: value.screenshot === true, backgroundKeepalive: false,
  };
}

function accountMetadata(account) {
  if (!account || typeof account !== 'object') throw bridgeError('YUNZHI_UNAVAILABLE');
  return {
    id: reference(account.id),
    sharedAccount: account.sharedAccount === true,
    tokenExpiresAt: Number.isFinite(account.tokenExpiresAt) ? account.tokenExpiresAt : null,
    authStatus: account.authStatus === 'expired' ? 'expired' : 'valid',
    capabilities: capabilities(account.capabilities),
  };
}

class YunzhiClient {
  constructor({ baseUrl = process.env.YUNZHI_CONTROL_URL || '', serviceToken = process.env.YUNZHI_CONTROL_TOKEN || '',
    installationId = '', timeoutMs = 60000, fetchImpl = globalThis.fetch,
    allowPrivateHttp = process.env.YUNZHI_CONTROL_ALLOW_PRIVATE_HTTP === '1' } = {}) {
    this.serviceToken = serviceToken;
    this.installationId = installationId;
    this.timeoutMs = timeoutMs;
    this.fetchImpl = fetchImpl;
    this.baseUrl = '';
    try {
      const url = new URL(baseUrl);
      const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
      const octets = url.hostname.split('.').map(Number);
      const privateIpv4 = /^\d+\.\d+\.\d+\.\d+$/.test(url.hostname) && octets.every((n) => n >= 0 && n <= 255) &&
        (octets[0] === 10 || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) || (octets[0] === 192 && octets[1] === 168));
      if ((url.protocol === 'https:' || (url.protocol === 'http:' && (loopback || (allowPrivateHttp === true && privateIpv4)))) &&
          !url.username && !url.password && !url.search && !url.hash && url.pathname === '/') {
        this.baseUrl = url.origin;
      }
    } catch (_) {}
  }

  isConfigured() {
    return Boolean(this.baseUrl && this.serviceToken && this.installationId);
  }

  async _request(ownerId, method, endpoint, body) {
    if (!this.isConfigured()) throw bridgeError('YUNZHI_DISABLED', 503);
    if (!/^[A-Za-z0-9:._-]{1,160}$/.test(`${this.installationId}:${ownerId}`)) {
      throw bridgeError('YUNZHI_UNAVAILABLE', 400);
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(`${this.baseUrl}/internal/control/v1${endpoint}`, {
        method, redirect: 'error', signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          'X-YunZhi-Control-Token': this.serviceToken,
          'X-YunZhi-Control-Owner': `${this.installationId}:${ownerId}`,
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      let raw = '';
      const maxBytes = 4 * 1024 * 1024;
      if (res.body && typeof res.body[Symbol.asyncIterator] === 'function') {
        let bytes = 0;
        const chunks = [];
        for await (const chunk of res.body) {
          bytes += chunk.length;
          if (bytes > maxBytes) { controller.abort(); throw bridgeError('YUNZHI_UNAVAILABLE'); }
          chunks.push(Buffer.from(chunk));
        }
        raw = Buffer.concat(chunks).toString('utf8');
      } else {
        raw = await res.text();
        if (Buffer.byteLength(raw) > maxBytes) throw bridgeError('YUNZHI_UNAVAILABLE');
      }
      let data;
      try { data = JSON.parse(raw); } catch (_) { throw bridgeError('YUNZHI_UNAVAILABLE'); }
      if (!res.ok || data?.ok !== true) {
        const code = BRIDGE_CODES[data?.code] || data?.code;
        // An upstream service credential failure must never be a platform-session 401.
        const status = res.status === 401 || res.status === 403 ? 503 : res.status >= 400 ? res.status : 502;
        throw bridgeError(code, code === 'YUNZHI_AUTH_EXPIRED' ? 409 : status);
      }
      return data;
    } catch (err) {
      if (err.code && Object.hasOwn(MESSAGES, err.code)) throw err;
      throw bridgeError(controller.signal.aborted ? 'YUNZHI_TIMEOUT' : 'YUNZHI_UNAVAILABLE', controller.signal.aborted ? 504 : 502);
    } finally {
      clearTimeout(timeout);
    }
  }

  async getCaptcha({ ownerId, mobile, remoteAccountId }) {
    const data = await this._request(ownerId, 'POST', '/captcha', {
      mobile, ...(remoteAccountId ? { accountId: reference(remoteAccountId) } : {}),
    });
    const challenge = data.challenge;
    if (!challenge || !challenge.challengeId) throw bridgeError('YUNZHI_UNAVAILABLE');
    // Explicit metadata allowlist: never forward upstream authorization or slider tokens.
    return Object.fromEntries(['challengeId', 'backgroundImage', 'sliderImage', 'backgroundWidth', 'backgroundHeight',
      'sliderWidth', 'sliderHeight', 'positionX', 'sliderY', 'expiresIn'].map((key) => [key, challenge[key]]));
  }

  async sendSms({ ownerId, challengeId, sliderX }) {
    const data = await this._request(ownerId, 'POST', '/sms/send', { challengeId, sliderX });
    return { expiresIn: data.expiresIn };
  }

  async verifySms({ ownerId, challengeId, code }) {
    const data = await this._request(ownerId, 'POST', '/sms/verify', { challengeId, code });
    return { account: accountMetadata(data.account), created: data.created === true };
  }

  _accountPath(account) {
    return `/accounts/${reference(account.remoteAccountId)}`;
  }

  async getAccountDevices(account) {
    const data = await this._request(account.ownerId, 'GET', `${this._accountPath(account)}/devices`);
    if (!Array.isArray(data.devices)) throw new Error('云智实例列表响应格式无效');
    const metadata = data.account ? accountMetadata(data.account) : null;
    if (metadata && metadata.id !== account.remoteAccountId) throw bridgeError('YUNZHI_UNAVAILABLE');
    const devices = data.devices.map((item) => {
      if (!item || !item.phoneId) throw new Error('云智实例列表响应格式无效');
      return {
        provider: 'yunzhi', platformType: 'ctyun', phoneId: reference(item.phoneId),
        phoneName: String(item.phoneName || '云智手机').slice(0, 100),
        instanceStatus: String(item.instanceStatus ?? ''), validStatus: String(item.validStatus || 'VALID'),
        isExpired: item.isExpired === true, lockStatus: 0,
        expireStr: String(item.expireStr || item.endTime || '').slice(0, 100),
        endTime: String(item.endTime || '').slice(0, 100), specName: String(item.specName || '').slice(0, 100),
        capabilities: capabilities(item.capabilities),
      };
    });
    return { account: metadata, devices };
  }

  async listDevices(account) {
    return (await this.getAccountDevices(account)).devices;
  }

  async getStreamAuth(account, deviceId) {
    const data = await this._request(account.ownerId, 'POST', `${this._accountPath(account)}/stream`, { deviceId: reference(deviceId) });
    if (!data.stream || !data.stream.ticket || !data.stream.resourceId) throw bridgeError('YUNZHI_UNAVAILABLE');
    const stream = { provider: 'yunzhi', platformType: 'ctyun' };
    for (const key of ['ticket', 'resourceId', 'userId', 'userName', 'appId', 'resourceType', 'tenantId', 'expiresAt']) {
      if (['string', 'number'].includes(typeof data.stream[key])) stream[key] = data.stream[key];
    }
    return stream;
  }

  async power(account, deviceId, action) {
    if (!['wakeup', 'reboot', 'shutdown'].includes(action)) throw bridgeError('CAPABILITY_UNSUPPORTED', 400);
    await this._request(account.ownerId, 'POST', `${this._accountPath(account)}/power`, { deviceId: reference(deviceId), action });
    return { message: '云智服务已接受操作，请同步确认最终状态' };
  }

  async runAccount(account, mode, requestId) {
    if (!['smoke', 'full'].includes(mode)) throw bridgeError('CAPABILITY_UNSUPPORTED', 400);
    const data = await this._request(account.ownerId, 'POST', `${this._accountPath(account)}/run`, { mode, requestId });
    return { jobId: reference(data.jobId) };
  }

  async getJob(ownerId, jobId) {
    const data = await this._request(ownerId, 'GET', `/jobs/${reference(jobId)}`);
    if (!data.job || !data.job.id) throw bridgeError('YUNZHI_UNAVAILABLE');
    const job = {};
    for (const key of ['id', 'status', 'mode', 'createdAt', 'finishedAt', 'summary']) job[key] = data.job[key];
    return job;
  }

  async deleteAccount(account) {
    try { await this._request(account.ownerId, 'DELETE', this._accountPath(account)); }
    catch (err) { if (err.status !== 404 || err.code !== 'ACCOUNT_NOT_FOUND') throw err; }
  }
}

module.exports = { YunzhiClient, bridgeError };
