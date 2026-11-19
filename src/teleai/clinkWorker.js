'use strict';

/**
 * CLINK 单实例保活 worker（CJS 版）
 * 链路：operationToken → instance/list →(status=3 时 start)→ instance/connect
 *       → ctyun 协商 + getConnectDataByToken → CLINK MAIN/DISPLAY/INPUTS 三通道
 *       → 5s/30s 心跳 + 假鼠标（服务端视角为「正在使用」）
 *
 * 被踢保护：服务端关闭 MAIN / 认证被拒 / CLIENT_OFFLINE → 视为有人接管，
 * 等 kickWaitMs 后再回来，避免把用户手动打开的桌面顶下线。
 */

const { CtyunClient, randomDeviceCode } = require('./ctyunClient');
const { ClinkChannel, loginInfo, u8, u16, u32 } = require('./clinkCore');

const MAX_LOGS = 200;

async function fetchConn(client, account, log = () => {}) {
  const list = await client.listInstances(account);
  if (!Array.isArray(list) || list.length === 0) throw new Error('账号下没有实例');
  let inst = list[0];

  if (Number(inst.status) === 3) {
    log('实例已回收，先开机…');
    await client.instanceAction(account, 'start', inst.id).catch(() => {});
    for (let i = 0; i < 60; i += 1) {
      await new Promise((r) => setTimeout(r, 3000));
      const l = await client.listInstances(account).catch(() => null);
      const cur = l && l.find((x) => x.id === inst.id);
      if (cur && Number(cur.status) === 100) {
        inst = cur;
        break;
      }
    }
    if (Number(inst.status) !== 100) throw new Error('实例开机超时（未就绪）');
  }

  const con = await client.instanceAction(account, 'connect', inst.id);
  const connectURL = (con && (con.connectURL || con.connectUrl)) || '';
  const hash = connectURL.split('#')[1] || '';
  const token = new URLSearchParams(hash.split('?')[1] || '').get('token');
  if (!token) throw new Error('connectURL 里没有 token');

  const ctyun = new CtyunClient();
  await ctyun.negotiate();
  const r = await ctyun.request('desktop/client/getConnectDataByToken', {
    data: { connectToken: token, osType: 'windows', deviceType: '60', from: '_ai_target_' },
    anonymous: true,
  });
  if (!r.body || r.body.code !== 0) {
    throw new Error('getConnectDataByToken 失败: ' + JSON.stringify(r.body || {}).slice(0, 160));
  }
  return { ...r.body.data, instance: inst };
}

class ClinkWorker {
  constructor(opts) {
    this.id = opts.id;
    this.name = opts.name || opts.id;
    this.ownerId = opts.ownerId;
    this.client = opts.client;
    this.account = opts.account;
    this.moveSec = Math.max(4, Number(opts.moveSec || 30));
    this.kickWaitMs = Math.max(0, Number(opts.kickWaitSec === undefined ? 1800 : opts.kickWaitSec)) * 1000;
    this.onLog = opts.onLog || (() => {});
    this.onChange = opts.onChange || (() => {});
    this.deviceCode = randomDeviceCode();

    this.state = 'stopped';
    this.lastError = '';
    this.logs = [];
    this.startedAt = 0;
    this.reconnects = 0;
    this.instanceStatus = null;
    this.desktopId = null;
    this.sessionId = 0;
    this.mouseMode = 1;
    this.sentCount = 0;
    this.ackCount = 0;
    this.lastEventAt = 0;
    this.lastAllReadyAt = 0;

    this.main = null;
    this.display = null;
    this.inputs = null;
    this.mouseTimer = null;
    this.restartTimer = null;
    this.pendingChannel = new Set();
    this.stopped = true;
    this.common = null;
    this.info = null;
    this.netFailures = 0;
  }

  log(m) {
    const line = `${new Date().toISOString().slice(11, 23)} ${m}`;
    this.logs.push(line);
    if (this.logs.length > MAX_LOGS) this.logs.splice(0, this.logs.length - MAX_LOGS);
    this.lastEventAt = Date.now();
    this.onLog(line);
  }

  async start() {
    if (!this.stopped) return;
    this.stopped = false;
    this.state = 'connecting';
    this.startedAt = Date.now();
    this.onChange();
    await this.connect();
  }

  stop() {
    this.stopped = true;
    this.state = 'stopped';
    clearTimeout(this.restartTimer);
    clearInterval(this.mouseTimer);
    this.mouseTimer = null;
    this.closeChannels();
    this.main = this.display = this.inputs = null;
    this.log('已停止');
    this.onChange();
  }

  async connect() {
    try {
      this.log('[account] 获取连接凭据…');
      this.info = await fetchConn(this.client, this.account, (m) => this.log(`[account] ${m}`));
      const di = this.info.desktopInfo;
      this.desktopId = this.info.desktopId;
      this.instanceStatus = 100;
      this.common = {
        base: `wss://${di.clinkLvsOutHost || 'deskmsgz.ctyun.cn:9011'}/clinkProxy`,
        desktopId: this.desktopId,
        host: di.internalIp,
        port: di.internalPort,
        ca: di.caCert,
        cert: di.clientCert,
        key: di.clientKey,
        servername: `${di.internalIp}:${di.internalPort}`,
        mouseMode: 1,
        connectionId: 0,
        log: (m) => this.log(m),
      };
      this.lastError = '';
      this.log(`[account] desktopId=${this.desktopId} gw=${this.common.base}`);
      if (this.stopped) return;
      this.build();
      this.main.connect();
      this.state = 'connecting';
      this.onChange();
    } catch (e) {
      this.lastError = e.message;
      this.log(`[account] 连接失败: ${e.message}`);
      const kicked = /auth failed|link error 8|PERMISSION|BAD_CONNECTION_ID/.test(String(e.message));
      this.scheduleReconnect(kicked ? this.kickWaitMs : 60000, kicked ? 'kick' : 'error');
    }
  }

  scheduleReconnect(delay = 5000, kind = 'error') {
    if (this.stopped) return;
    clearTimeout(this.restartTimer);
    this.nextRetryAt = Date.now() + delay;
    this.state = kind === 'kick' ? 'paused' : 'error';
    const human = delay >= 60000 ? `${Math.round(delay / 60000)} 分钟` : `${Math.round(delay / 1000)} 秒`;
    this.log(
      kind === 'kick'
        ? `[account] 会话被接管，等待 ${human}后再重连（避免顶掉手动连接）`
        : `[account] 将在 ${human}后重试`
    );
    this.onChange();
    this.restartTimer = setTimeout(async () => {
      if (this.stopped) return;
      this.nextRetryAt = 0;
      this.reconnects += 1;
      this.log(`[account] 重连 #${this.reconnects}`);
      this.closeChannels();
      await this.connect();
    }, delay);
    if (this.restartTimer.unref) this.restartTimer.unref();
  }

  async reconnectNow() {
    this.stopped = false;
    clearTimeout(this.restartTimer);
    this.nextRetryAt = 0;
    this.reconnects += 1;
    this.log('[account] 手动立即重连');
    this.closeChannels();
    this.state = 'connecting';
    this.onChange();
    await this.connect();
  }

  closeChannels() {
    clearInterval(this.mouseTimer);
    this.mouseTimer = null;
    for (const c of [this.main, this.display, this.inputs]) {
      try {
        if (c) c.close();
      } catch (_) {
        /* ignore */
      }
    }
  }

  build() {
    const self = this;
    this.main = new ClinkChannel('MAIN', 1, {
      ...this.common,
      channelCaps: [4 + 2048],
      heartMs: 5000,
      onHeartbeat: () => self.touch(),
      onReady: (ch) => {
        self.netFailures = 0;
        self.state = 'running';
        self.checkAllReady();
        self.onChange();
        const li = loginInfo(self.desktopId, self.info.desktopInfo.token, '60', self.deviceCode, '');
        ch.send(112, li);
        ch.log(`LOGIN_INFO sent, ${li.length} bytes`);
        self.touch();
      },
      onAuthFail: (code) => {
        if (self.stopped) return;
        self.main.wasKicked = true;
        self.log(`[account] MAIN 认证被拒（code=${code}）→ 有人在用这台云电脑`);
        self.scheduleReconnect(self.kickWaitMs, 'kick');
      },
      onMessage: (ch, type, data) => {
        if (type === 103) {
          self.sessionId = data.readUInt32LE(0);
          self.mouseMode = data.readUInt32LE(12) === 2 ? 2 : 1;
          self.common.connectionId = self.sessionId;
          ch.log(`MAIN_INIT 鼠标模式=${self.mouseMode === 2 ? 'CLIENT(位置)' : 'SERVER(相对)'} session=${self.sessionId}`);
          self.display = self.makeDisplay();
          self.display.connect();
          self.inputs = self.makeInputs();
          self.inputs.connect();
        } else if (type === 107) ch.log('AGENT_CONNECTED');
        else if (type === 108) ch.log('AGENT_DISCONNECTED');
        else if (type === 119) {
          ch.wasKicked = true;
          ch.log('CLIENT_OFFLINE：会话被其他客户端接管');
        }
        self.touch();
      },
      onClose: (ch) => {
        if (self.stopped) return;
        const code = ch.closeCode;
        const clean = code === 1000 || code === 1001 || code === 1005 || code == null;
        if (clean || ch.wasKicked) {
          self.log(`[account] MAIN 被服务端关闭（code=${code}）→ 视为被接管，等待 ${Math.round(self.kickWaitMs / 1000)} 秒`);
          self.scheduleReconnect(self.kickWaitMs, 'kick');
        } else {
          self.netFailures += 1;
          const delay = Math.min(300000, 15000 * Math.pow(2, self.netFailures - 1));
          self.log(`[account] MAIN 异常断开（code=${code}）→ 退避 ${Math.round(delay / 1000)}s`);
          self.scheduleReconnect(delay, 'error');
        }
      },
    });
  }

  makeDisplay() {
    const self = this;
    return new ClinkChannel('DISPLAY', 2, {
      ...this.common,
      channelCaps: [1],
      heartMs: 30000,
      onHeartbeat: () => self.touch(),
      onReady: (ch) => {
        ch.send(101, Buffer.concat([u32(1), u32(0), u32(10485760), u32(0)]));
        self.checkAllReady();
      },
      onClose: () => self.scheduleChannelRestart('DISPLAY'),
    });
  }

  makeInputs() {
    const self = this;
    return new ClinkChannel('INPUTS', 3, {
      ...this.common,
      channelCaps: [],
      heartMs: 30000,
      onHeartbeat: () => self.touch(),
      onMessage: (ch, type) => {
        if (type === 111) {
          self.ackCount += 1;
          self.touch();
        }
      },
      onReady: (ch) => {
        ch.send(103, u16(0));
        ch.log(`INPUTS ready, 假鼠标每 ${self.moveSec}s`);
        self.startMouse(ch);
        self.checkAllReady();
      },
      onClose: () => self.scheduleChannelRestart('INPUTS'),
    });
  }

  scheduleChannelRestart(name) {
    if (this.stopped || !this.main || !this.main.ready) return;
    if (this.pendingChannel.has(name)) return;
    this.pendingChannel.add(name);
    this.log(`[account] ${name} 断开，3s 后单独重连`);
    const timer = setTimeout(() => {
      this.pendingChannel.delete(name);
      if (this.stopped || !this.main || !this.main.ready) return;
      try {
        if (name === 'DISPLAY') {
          if (this.display) this.display.close();
          this.display = this.makeDisplay();
          this.display.connect();
        }
        if (name === 'INPUTS') {
          if (this.inputs) this.inputs.close();
          this.inputs = this.makeInputs();
          this.inputs.connect();
        }
      } catch (e) {
        this.log(`[account] ${name} 重连失败: ${e.message}`);
      }
    }, 3000);
    if (timer.unref) timer.unref();
  }

  startMouse(ch) {
    clearInterval(this.mouseTimer);
    let step = 0;
    const send = () => {
      if (!ch.ready || this.stopped) return;
      const ring = [[0, 0], [20, 0], [20, 20], [0, 20]][step % 4];
      const x = 1180 + ring[0];
      const y = 680 + ring[1];
      const type = this.mouseMode === 2 ? 112 : 111;
      if (ch.send(type, Buffer.concat([u32(x), u32(y), u16(0), u8(0)]))) this.sentCount += 1;
      step += 1;
    };
    this.mouseTimer = setInterval(() => {
      for (let i = 0; i < 4; i += 1) {
        const t = setTimeout(send, i * 250);
        if (t.unref) t.unref();
      }
    }, Math.max(4, this.moveSec) * 1000);
    if (this.mouseTimer.unref) this.mouseTimer.unref();
  }

  checkAllReady() {
    const ch = [this.main, this.inputs, this.display];
    if (ch.every((c) => c && c.ready)) this.lastAllReadyAt = Date.now();
  }

  touch() {
    this.lastEventAt = Date.now();
  }

  snapshot() {
    const channels = {};
    for (const c of [this.main, this.display, this.inputs]) {
      if (c) channels[c.name] = { ready: c.ready, heartbeats: c.heartbeats, state: c.state };
    }
    return {
      id: this.id,
      name: this.name,
      state: this.state,
      instanceStatus: this.instanceStatus,
      desktopId: this.desktopId,
      mouseMode: this.mouseMode,
      sentCount: this.sentCount,
      ackCount: this.ackCount,
      reconnects: this.reconnects,
      startedAt: this.startedAt,
      lastAllReadyAt: this.lastAllReadyAt,
      kickWaitSec: Math.round(this.kickWaitMs / 1000),
      nextRetryAt: this.nextRetryAt || 0,
      uptimeSec: this.startedAt ? Math.floor((Date.now() - this.startedAt) / 1000) : 0,
      lastError: this.lastError,
      lastEventAt: this.lastEventAt,
      channels,
      moveSec: this.moveSec,
    };
  }
}

module.exports = { ClinkWorker, fetchConn };
