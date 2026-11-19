'use strict';

/**
 * 星辰超级智能体电脑（TeleAgent）渠道端到端测试
 * 使用假客户端，覆盖：绑定 → 同步 → 保活策略 → 开机/重启 → 进入控制 → 一键续期 → 解绑
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createApp } = require('../src/server');
const { solvePuzzle, decodePng } = require('../src/teleaiCaptcha');

class FakeTeleaiClient {
  constructor() {
    this.loginCount = 0;
    this.actions = [];
    this.instances = [{ id: 'inst-teleai-0001', status: 100, statusReason: 0, connectTimeout: 600 }];
  }

  async loginWithPassword(loginName, password) {
    if (!loginName || !password) throw Object.assign(new Error('账号和密码不能为空'), { code: 'BAD_INPUT' });
    if (password === 'wrong-pass') throw Object.assign(new Error('用户名或密码不正确'), { code: '10980039' });
    this.loginCount += 1;
    return {
      loginName: String(loginName).toLowerCase(),
      operationToken: `Em9xR4:token-${this.loginCount}`,
      operToken: `oper-${this.loginCount}`,
      aesKey: 'aes-key',
      aesIv: 'aes-iv',
      expiresAt: Date.now() + 29 * 86400 * 1000,
    };
  }

  async listInstances() {
    return this.instances.map((i) => ({ ...i }));
  }

  async instanceAction(acc, action, id) {
    this.actions.push({ action, id });
    // CLINK 取连接信息走这里：故意不带 token，保证测试不触网
    if (action === 'connect') return { connectURL: 'https://pc.ctyun.cn/#/fullview' };
    return { ok: true };
  }

  async connect(acc, id) {
    this.actions.push({ action: 'connect', id });
    return { connectURL: `https://pc.ctyun.cn/#/fullview?token=${id}`, previewURL: '' };
  }
}

test('TeleAgent channel: bind, keepalive policy, power, control, renew, unbind', async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cmcc-teleai-'));
  const teleaiClient = new FakeTeleaiClient();
  const app = createApp({ dataDir: tmpDir, teleaiClient });
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${app.server.address().port}`;

  t.after(async () => {
    app.engine.stop();
    app.teleaiEngine.stopAll();
    await new Promise((r) => app.server.close(r));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  async function call(p, { method = 'GET', token = '', body } = {}) {
    const headers = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body) headers['Content-Type'] = 'application/json';
    const res = await fetch(base + p, { method, headers, body: body ? JSON.stringify(body) : undefined });
    return { status: res.status, json: await res.json() };
  }

  // 1) 注册管理端账号
  const reg = await call('/api/auth/register', {
    method: 'POST',
    body: { username: 'tel_admin', password: 'admin12345' },
  });
  assert.equal(reg.status, 200);
  const token = reg.json.token;

  // 2) 绑定星辰账号（假客户端）
  const bind = await call('/api/teleai/login', {
    method: 'POST',
    token,
    body: { loginName: 'demo_user', password: 'secret-pass', remark: '测试号' },
  });
  assert.equal(bind.status, 200);
  assert.equal(bind.json.instanceCount, 1);
  assert.equal(bind.json.account.loginName, 'demo_user');
  assert.equal(bind.json.account.hasPassword, true);
  assert.ok(bind.json.account.tokenExpiresAt > Date.now());
  assert.equal(teleaiClient.loginCount, 1);

  // 3) 仪表盘包含星辰账号与实例
  const dash = await call('/api/dashboard', { token });
  assert.equal(dash.status, 200);
  assert.equal(dash.json.teleaiAccounts.length, 1);
  assert.equal(dash.json.teleaiInstances.length, 1);
  const inst = dash.json.teleaiInstances[0];
  assert.equal(inst.stateText, 'ready');
  assert.equal(inst.channel, 'teleai');
  assert.ok(inst.runtime);

  // 4) 保活策略
  const patch = await call(`/api/teleai/instances/${inst.id}/settings`, {
    method: 'PATCH',
    token,
    body: { keepaliveEnabled: true, autoStart: false, checkIntervalSec: 120 },
  });
  assert.equal(patch.status, 200);
  assert.equal(patch.json.instance.keepaliveEnabled, true);
  assert.equal(patch.json.instance.autoStart, false);
  assert.equal(patch.json.instance.checkIntervalSec, 120);

  const badInterval = await call(`/api/teleai/instances/${inst.id}/settings`, {
    method: 'PATCH',
    token,
    body: { checkIntervalSec: 5 },
  });
  assert.equal(badInterval.status, 400);

  // 5) 开机 / 重启
  const start = await call(`/api/teleai/instances/${inst.id}/power`, {
    method: 'POST',
    token,
    body: { action: 'start' },
  });
  assert.equal(start.status, 200);
  assert.deepEqual(teleaiClient.actions.pop(), { action: 'start', id: 'inst-teleai-0001' });

  const restart = await call(`/api/teleai/instances/${inst.id}/power`, {
    method: 'POST',
    token,
    body: { action: 'restart' },
  });
  assert.equal(restart.status, 200);
  assert.deepEqual(teleaiClient.actions.pop(), { action: 'restart', id: 'inst-teleai-0001' });

  const badAction = await call(`/api/teleai/instances/${inst.id}/power`, {
    method: 'POST',
    token,
    body: { action: 'shutdown' },
  });
  assert.equal(badAction.status, 400);

  // 6) 进入控制：拿到官方桌面入口
  const desktop = await call(`/api/teleai/instances/${inst.id}/desktop`, { token });
  assert.equal(desktop.status, 200);
  assert.match(desktop.json.connectURL, /^https:\/\/pc\.ctyun\.cn\/#\/fullview\?token=/);

  // 7) 一键续期
  const before = (await call('/api/dashboard', { token })).json.teleaiAccounts[0].tokenExpiresAt;
  const renew = await call(`/api/teleai/accounts/${bind.json.account.id}/renew`, { method: 'POST', token });
  assert.equal(renew.status, 200);
  assert.equal(renew.json.instanceCount, 1);
  assert.equal(teleaiClient.loginCount, 2);
  const after = (await call('/api/dashboard', { token })).json.teleaiAccounts[0];
  assert.ok(after.tokenExpiresAt >= before);
  assert.equal(after.authStatus, 'valid');

  // 8) 协议级保活开关（CLINK）：后台 worker 会因测试桩没有真实 token 而进入 error，但开关与生命周期可验证
  const clinkOn = await call(`/api/teleai/instances/${inst.id}/clink`, {
    method: 'POST',
    token,
    body: { action: 'start' },
  });
  assert.equal(clinkOn.status, 200);
  assert.ok(clinkOn.json.clink, '应返回 CLINK 运行态');
  assert.equal(app.clinkManager.get(inst.id) !== null, true);
  const dashClink = (await call('/api/dashboard', { token })).json.teleaiInstances[0];
  assert.equal(dashClink.clinkEnabled, true);
  assert.ok(dashClink.clink, '仪表盘应带 CLINK 快照');

  const clinkOff = await call(`/api/teleai/instances/${inst.id}/clink`, {
    method: 'POST',
    token,
    body: { action: 'stop' },
  });
  assert.equal(clinkOff.status, 200);
  assert.equal(app.clinkManager.get(inst.id), null);

  // 8.1) 解绑：账号与实例一起消失
  const del = await call(`/api/teleai/accounts/${bind.json.account.id}`, { method: 'DELETE', token });
  assert.equal(del.status, 200);
  const dash2 = await call('/api/dashboard', { token });
  assert.equal(dash2.json.teleaiAccounts.length, 0);
  assert.equal(dash2.json.teleaiInstances.length, 0);

  // 9) 错误密码 → 明确报错，不落库
  const badLogin = await call('/api/teleai/login', {
    method: 'POST',
    token,
    body: { loginName: 'demo_user', password: 'wrong-pass' },
  });
  assert.equal(badLogin.status, 400);
  assert.match(badLogin.json.error, /用户名或密码不正确/);
});

test('TeleAgent captcha: pure-JS PNG decode + puzzle solve', () => {
  // 造一张 8x4 的 RGBA PNG（纯黑底 + 左侧白色竖条），验证解码器
  const zlib = require('node:zlib');
  const width = 8;
  const height = 4;
  const raw = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y += 1) {
    const rowStart = y * (width * 4 + 1);
    raw[rowStart] = 0; // filter none
    for (let x = 0; x < width; x += 1) {
      const o = rowStart + 1 + x * 4;
      const white = x === 0;
      raw[o] = white ? 255 : 0;
      raw[o + 1] = white ? 255 : 0;
      raw[o + 2] = white ? 255 : 0;
      raw[o + 3] = 255;
    }
  }
  const crcTable = (() => {
    const t = new Int32Array(256);
    for (let n = 0; n < 256; n += 1) {
      let c = n;
      for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c;
    }
    return t;
  })();
  const crc32 = (buf) => {
    let c = 0xffffffff;
    for (const byte of buf) c = crcTable[(c ^ byte) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type, data) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(body));
    return Buffer.concat([len, body, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const png = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);

  const decoded = decodePng(png);
  assert.equal(decoded.width, 8);
  assert.equal(decoded.height, 4);
  assert.equal(decoded.data[0], 255); // (0,0) 白色
  assert.equal(decoded.data[4], 0); // (1,0) 黑色

  // 拼图块 = 左侧 2x2 全不透明块，背景 8 宽、缺口在 x=4 处白边
  const bgRaw = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y += 1) {
    const rowStart = y * (width * 4 + 1);
    for (let x = 0; x < width; x += 1) {
      const o = rowStart + 1 + x * 4;
      const white = x === 4 || x === 5;
      bgRaw[o] = white ? 255 : 0;
      bgRaw[o + 1] = white ? 255 : 0;
      bgRaw[o + 2] = white ? 255 : 0;
      bgRaw[o + 3] = 255;
    }
  }
  const bgPng = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(bgRaw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);

  const jigRaw = Buffer.alloc((2 * 4 + 1) * 2);
  for (let y = 0; y < 2; y += 1) {
    const rowStart = y * (2 * 4 + 1);
    for (let x = 0; x < 2; x += 1) {
      const o = rowStart + 1 + x * 4;
      jigRaw[o] = 255;
      jigRaw[o + 1] = 255;
      jigRaw[o + 2] = 255;
      jigRaw[o + 3] = 255;
    }
  }
  const jigIhdr = Buffer.from(ihdr);
  jigIhdr.writeUInt32BE(2, 0);
  jigIhdr.writeUInt32BE(2, 4);
  const jigPng = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', jigIhdr),
    chunk('IDAT', zlib.deflateSync(jigRaw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);

  const solved = solvePuzzle(bgPng.toString('base64'), jigPng.toString('base64'));
  assert.equal(solved.x, 4);
  assert.deepEqual(solved.size, [2, 2]);
});
