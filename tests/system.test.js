'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createApp } = require('../src/server');
const { CmccClient } = require('../src/cmccClient');

/**
 * Helper to start a lightweight RFC6455 WebSocket server supporting both:
 * - `/socket.io/` (Yun Engine.IO v3 signaling gateway)
 * - `/tcloud-cmd` (TCloud binary/text command gateway)
 */
function createMockSignalingServer() {
  const receivedTCloudHeartbeats = [];
  let yunPingCount = 0;

  const server = http.createServer((req, res) => {
    res.writeHead(200);
    res.end('ok');
  });

  function sendWsText(socket, text) {
    if (socket.destroyed) return;
    const payload = Buffer.from(text, 'utf8');
    let header;
    if (payload.length < 126) {
      header = Buffer.from([0x81, payload.length]);
    } else {
      header = Buffer.alloc(4);
      header[0] = 0x81;
      header[1] = 126;
      header.writeUInt16BE(payload.length, 2);
    }
    socket.write(Buffer.concat([header, payload]));
  }

  function decodeClientFrames(buffer, onText, onClose) {
    let offset = 0;
    while (buffer.length - offset >= 2) {
      const b0 = buffer[offset];
      const b1 = buffer[offset + 1];
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let hdr = 2;
      if (len === 126) {
        if (buffer.length - offset < 4) break;
        len = buffer.readUInt16BE(offset + 2);
        hdr = 4;
      }
      const maskLen = masked ? 4 : 0;
      if (buffer.length - offset < hdr + maskLen + len) break;
      const data = Buffer.from(buffer.subarray(offset + hdr + maskLen, offset + hdr + maskLen + len));
      if (masked) {
        const mask = buffer.subarray(offset + hdr, offset + hdr + 4);
        for (let i = 0; i < data.length; i++) data[i] ^= mask[i & 3];
      }
      offset += hdr + maskLen + len;
      if (opcode === 0x8) {
        onClose();
        break;
      } else if (opcode === 0x1) {
        onText(data.toString('utf8'));
      }
    }
    return buffer.subarray(offset);
  }

  server.on('upgrade', (req, socket) => {
    const key = req.headers['sec-websocket-key'];
    const accept = crypto
      .createHash('sha1')
      .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
      .digest('base64');
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
    );

    const isYun = req.url.startsWith('/socket.io/');
    if (isYun) {
      // Engine.IO v3 open + Socket.IO connect + authorize event
      sendWsText(socket, '0{"sid":"mock-sid-1","upgrades":[],"pingInterval":120,"pingTimeout":2000}');
      sendWsText(socket, '40');
      sendWsText(socket, '42["authorize",{"authorized":true,"code":0}]');
    }

    let buf = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      buf = decodeClientFrames(
        buf,
        (txt) => {
          if (isYun) {
            if (txt === '2') {
              yunPingCount += 1;
              sendWsText(socket, '3');
            }
          } else {
            try {
              const obj = JSON.parse(txt);
              const inner = JSON.parse(obj.msg || '{}');
              if (inner.type === 100022 || inner.cmdType === 100022) {
                receivedTCloudHeartbeats.push(obj.code);
              }
            } catch (_) {}
          }
        },
        () => socket.end()
      );
    });
  });

  return {
    server,
    getStats: () => ({ yunPingCount, tcloudBeats: receivedTCloudHeartbeats.length }),
  };
}

function encryptMockWorkKey(obj, workKey = '1234567890abcdef') {
  const iv = crypto.randomBytes(12 + 4); // CMCC uses 16-byte IV in 35b7!
  const cipher = crypto.createCipheriv('aes-128-gcm', Buffer.from(workKey, 'utf8'), iv);
  const enc = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, enc, tag]).toString('hex');
}

test('End-to-end multi-user isolation, official SMS login, x-workkey AES-GCM, keepalive & web handover', async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cmcc-mgr-test-'));
  const sigMock = createMockSignalingServer();
  await new Promise((r) => sigMock.server.listen(0, '127.0.0.1', r));
  const sigPort = sigMock.server.address().port;

  // Mock CMCC upstream HTTP fetch
  const mockFetch = async (url, opts) => {
    const u = new URL(url);
    const body = opts.body ? JSON.parse(opts.body) : {};
    const token = opts.headers.token || '';

    const jsonResp = (payload, extraHeaders = {}) => ({
      status: 200,
      headers: {
        get: (k) => extraHeaders[k.toLowerCase()] || null,
      },
      text: async () => JSON.stringify(payload),
    });

    if (u.pathname.endsWith('/user/getCaptcha')) {
      return jsonResp({
        header: { status: '0000', errMsg: null },
        data: {
          token: 'cap-tok-123',
          secretKey: '1234567890abcdef',
          originalImageBase64: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
          jigsawImageBase64: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
        },
      });
    }

    if (u.pathname.endsWith('/user/checkCaptcha')) {
      assert.equal(body.captchaType, 'blockPuzzle');
      assert.ok(body.pointJson.length > 8);
      return jsonResp({ header: { status: '0000' }, data: { result: true } });
    }

    if (u.pathname.endsWith('/user/login/sendCode')) {
      assert.equal(typeof body.verifyCode, 'number');
      return jsonResp({ header: { status: '200' }, data: { ret: 1 } });
    }

    if (u.pathname.endsWith('/user/login/validateCode')) {
      // Return encrypted response with x-workkey header just like official CMCC server
      const workKey = 'abcdef1234567890';
      const isUserB = opts.headers.deviceId && body.code !== body.mobile;
      // Distinguish token by random suffix
      const issuedTok = 'cmcc-tok-' + crypto.randomBytes(4).toString('hex');
      const plainData = {
        token: issuedTok,
        hwToken: 'hw-' + issuedTok,
        userId: 'uid-' + issuedTok.slice(-4),
        province: 'TW',
      };
      return jsonResp(
        {
          header: { status: '200', errMsg: null },
          data: encryptMockWorkKey(plainData, workKey),
        },
        { 'x-workkey': workKey }
      );
    }

    if (u.pathname.endsWith('/device/bookRecord')) {
      // User A's first account gets Yun device (platformType=1), second account gets TCloud (platformType=2)
      const isSecond = token.endsWith('b') || mockFetch._accountSeq > 1;
      if (!isSecond) {
        return jsonResp({
          header: { status: '200' },
          data: {
            phoneInstanceList: [
              {
                phoneId: 'YUN-PHONE-001',
                phoneName: 'UserA的云版云机',
                platformType: '1',
                instanceStatus: '0',
                validStatus: 'VALID',
                expireStr: '2027-12-31',
              },
            ],
          },
        });
      }
      return jsonResp({
        header: { status: '200' },
        data: {
          phoneInstanceList: [
            {
              phoneId: 'TCLOUD-PHONE-002',
              phoneName: 'UserB的T版云机',
              platformType: '2',
              instanceStatus: '0',
              validStatus: 'VALID',
              expireStr: '2027-06-30',
            },
          ],
        },
      });
    }

    if (u.pathname.endsWith('/device/instancePrepareV2')) {
      return jsonResp({
        header: { status: '200' },
        data: { devicePrepareInfos: [{ instanceId: body.instanceId, status: 0 }] },
      });
    }

    if (u.pathname.endsWith('/user/instance/auth')) {
      return jsonResp({
        header: { status: '200' },
        data: {
          deviceToken: 'dev-tok-yun-001',
          platform: 'cloudphone',
          env: 'phone580',
          resource: {
            deviceId: 'box-yun-001',
            roomSession: 'room-001',
            rtc: {
              iceSignaling: {
                signaling_url: `http://127.0.0.1:${sigPort}`,
              },
            },
          },
        },
      });
    }

    if (u.pathname.endsWith('/uniphone/into/v3')) {
      return jsonResp({
        header: { status: '200' },
        data: {
          cloudPhoneInto: {
            phoneId: 'internal-t-002',
            status: 'online',
            resolution: '720x1280',
            tokenInfo: { token3: 't-conn-tok-3' },
            connectedPhoneInfo: {
              isConnectMqtt: true,
              ipPortInfoResps: [
                { listenPort: 10001, phoneIp: '127.0.0.1', accessPort: sigPort },
                { listenPort: 10002, phoneIp: '127.0.0.1', accessPort: sigPort },
              ],
            },
          },
        },
      });
    }

    if (u.pathname.endsWith('/screencap/notification')) {
      return jsonResp({ header: { status: '200' }, data: true });
    }

    if (u.pathname.endsWith('/screencap/pict')) {
      return jsonResp({ header: { status: '200' }, data: 'https://example.com/screen.jpg' });
    }

    return jsonResp({ header: { status: '200' }, data: {} });
  };
  mockFetch._accountSeq = 0;

  const cmccClient = new CmccClient({ fetchImpl: mockFetch });
  // Override wss://api.cp.139.com to local mock ws server for TCloud test
  const origGetStreamAuth = cmccClient.getStreamAuth.bind(cmccClient);
  cmccClient.getStreamAuth = async (acc, phoneId, platformType, authId) => {
    const auth = await origGetStreamAuth(acc, phoneId, platformType, authId);
    if (String(platformType) === '2') {
      auth.cmdUrl = `ws://127.0.0.1:${sigPort}/tcloud-cmd`;
      auth.rtcUrl = `ws://127.0.0.1:${sigPort}/tcloud-rtc`;
    }
    return auth;
  };

  const app = createApp({
    dataDir: tmpDir,
    cmccClient,
    engineOptions: { yunRefreshPulseMs: 60000 },
  });
  app.engine.start();
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  const appPort = app.server.address().port;
  const base = `http://127.0.0.1:${appPort}`;

  t.after(async () => {
    app.engine.stop();
    await new Promise((r) => app.server.close(r));
    await new Promise((r) => sigMock.server.close(r));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  async function callApp(p, { method = 'GET', token = '', body } = {}) {
    const headers = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body) headers['Content-Type'] = 'application/json';
    const res = await fetch(base + p, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, json: await res.json() };
  }

  // 1. Register User A (first user -> admin) and User B (second user -> isolated user)
  const regA = await callApp('/api/auth/register', {
    method: 'POST',
    body: { username: 'alice_admin', password: 'password123' },
  });
  assert.equal(regA.status, 200);
  assert.equal(regA.json.user.role, 'admin');
  const tokenA = regA.json.token;

  const regB = await callApp('/api/auth/register', {
    method: 'POST',
    body: { username: 'bob_user', password: 'password456' },
  });
  assert.equal(regB.status, 200);
  assert.equal(regB.json.user.role, 'user');
  const tokenB = regB.json.token;

  // 2. User A binds CMCC account via full Official SMS Captcha + Code flow
  mockFetch._accountSeq = 1;
  const capA = await callApp('/api/cmcc/captcha/get', {
    method: 'POST',
    token: tokenA,
    body: { mobile: '13800138001' },
  });
  assert.equal(capA.status, 200);
  assert.ok(capA.json.captchaSessionId);

  // User B must NOT be able to use User A's captchaSessionId
  const hijackAttempt = await callApp('/api/cmcc/captcha/send-sms', {
    method: 'POST',
    token: tokenB,
    body: { captchaSessionId: capA.json.captchaSessionId, moveX: 120 },
  });
  assert.equal(hijackAttempt.status, 400);

  const sendSmsA = await callApp('/api/cmcc/captcha/send-sms', {
    method: 'POST',
    token: tokenA,
    body: { captchaSessionId: capA.json.captchaSessionId, moveX: 120 },
  });
  assert.equal(sendSmsA.status, 200);

  const loginSmsA = await callApp('/api/cmcc/login/sms', {
    method: 'POST',
    token: tokenA,
    body: {
      mobile: '13800138001',
      code: '654321',
      remark: 'Alice主力机',
      captchaSessionId: capA.json.captchaSessionId,
    },
  });
  assert.equal(loginSmsA.status, 200);
  assert.equal(loginSmsA.json.deviceCount, 1);

  // 3. User B binds their own CMCC account (TCloud platformType=2)
  mockFetch._accountSeq = 2;
  const capB = await callApp('/api/cmcc/captcha/get', {
    method: 'POST',
    token: tokenB,
    body: { mobile: '13900139002' },
  });
  await callApp('/api/cmcc/captcha/send-sms', {
    method: 'POST',
    token: tokenB,
    body: { captchaSessionId: capB.json.captchaSessionId, moveX: 150 },
  });
  const loginSmsB = await callApp('/api/cmcc/login/sms', {
    method: 'POST',
    token: tokenB,
    body: {
      mobile: '13900139002',
      code: '112233',
      remark: 'Bob挂机号',
      captchaSessionId: capB.json.captchaSessionId,
    },
  });
  assert.equal(loginSmsB.status, 200);
  assert.equal(loginSmsB.json.deviceCount, 1);

  // Wait 450ms for both Yun Engine.IO v3 & TCloud WebSocket keepalive handshakes + heartbeats
  await new Promise((r) => setTimeout(r, 450));

  // 4. Verify strict tenant isolation + active keepalive states
  const dashA = await callApp('/api/dashboard', { token: tokenA });
  assert.equal(dashA.json.accounts.length, 1);
  assert.equal(dashA.json.accounts[0].mobile, '13800138001');
  assert.equal(dashA.json.devices.length, 1);
  const devA = dashA.json.devices[0];
  assert.equal(devA.phoneId, 'YUN-PHONE-001');
  assert.equal(devA.runtime.state, 'KEEPING');
  assert.ok(devA.runtime.heartbeatCount >= 1, 'Yun Engine.IO v3 ping/pong heartbeats should increment');

  const dashB = await callApp('/api/dashboard', { token: tokenB });
  assert.equal(dashB.json.accounts.length, 1);
  assert.equal(dashB.json.accounts[0].mobile, '13900139002');
  assert.equal(dashB.json.devices.length, 1);
  const devB = dashB.json.devices[0];
  assert.equal(devB.phoneId, 'TCLOUD-PHONE-002');
  assert.equal(devB.runtime.state, 'KEEPING');
  assert.ok(devB.runtime.heartbeatCount >= 1, 'TCloud command WS heartbeats should increment');

  // Verify User B cannot access User A's device or admin panel
  const crossStream = await callApp(`/api/devices/${devA.id}/stream/open`, {
    method: 'POST',
    token: tokenB,
    body: {},
  });
  assert.equal(crossStream.status, 404);

  const nonAdminCheck = await callApp('/api/admin/users', { token: tokenB });
  assert.equal(nonAdminCheck.status, 403);

  // Verify encrypted storage on disk (plaintext token must NOT appear in store.json)
  const rawStoreText = fs.readFileSync(path.join(tmpDir, 'store.json'), 'utf8');
  assert.ok(!rawStoreText.includes('cmcc-tok-'), 'CMCC tokens must be AES-256-GCM encrypted at rest');

  // 5. Verify Web Display/Control Stream Lease Handover & Automatic Keepalive Resume
  const openStreamA = await callApp(`/api/devices/${devA.id}/stream/open`, {
    method: 'POST',
    token: tokenA,
    body: {},
  });
  assert.equal(openStreamA.status, 200);
  assert.equal(openStreamA.json.stream.boxid, 'box-yun-001');

  const dashWhileWeb = await callApp('/api/dashboard', { token: tokenA });
  assert.equal(dashWhileWeb.json.devices[0].runtime.state, 'WEB_CONTROL');

  // Close Web Viewer -> Keepalive engine must automatically resume KEEPING
  const closeStreamA = await callApp(`/api/devices/${devA.id}/stream/close`, {
    method: 'POST',
    token: tokenA,
  });
  assert.equal(closeStreamA.status, 200);

  await new Promise((r) => setTimeout(r, 250));
  const dashAfterWeb = await callApp('/api/dashboard', { token: tokenA });
  assert.equal(dashAfterWeb.json.devices[0].runtime.state, 'KEEPING');
});
