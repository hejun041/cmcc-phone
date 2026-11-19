'use strict';

/**
 * CLINK 协议核心（CJS 版）：二进制工具 + SPICE 票据 + 通道状态机
 * 源自 teleai-keepalive 的 clink-core.mjs，socket 层换成项目自带的零依赖 RawWebSocket。
 */

const crypto = require('crypto');
const { RawWebSocket } = require('../wsClient');

const u8 = (n) => Buffer.from([n & 0xff]);
const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n & 0xffff);
  return b;
};
const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0);
  return b;
};

const sha1 = (b) => crypto.createHash('sha1').update(b).digest();

function mgf(seed, len) {
  const buf = Buffer.alloc(len);
  let off = 0;
  let i = 0;
  while (off < len) {
    const ctr = Buffer.alloc(4);
    ctr.writeUInt32BE(i);
    i += 1;
    const h = sha1(Buffer.concat([seed, ctr]));
    const n = Math.min(h.length, len - off);
    h.copy(buf, off, 0, n);
    off += n;
  }
  return buf;
}

/** SPICE spice_encrypt_link：SHA1-OAEP 手工填充 + 裸 RSA（口令为空） */
function spiceTicket(der, password = Buffer.alloc(0)) {
  const pub = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  const jwk = pub.export({ format: 'jwk' });
  const n = BigInt('0x' + Buffer.from(jwk.n, 'base64url').toString('hex'));
  const e = BigInt('0x' + Buffer.from(jwk.e, 'base64url').toString('hex'));
  const keyLen = Math.ceil(n.toString(16).length / 2);
  const HL = 20;
  const seed = crypto.randomBytes(HL);
  const i = keyLen - 1 - HL;
  const block = Buffer.alloc(i);
  const s = i - password.length - 1;
  if (s < HL) throw new Error('password too long');
  sha1(password).copy(block, 0);
  block[s] = 1;
  password.copy(block, s + 1);
  const l = mgf(seed, i);
  for (let k = 0; k < i; k += 1) block[k] ^= l[k];
  const u = mgf(block, HL);
  for (let k = 0; k < HL; k += 1) seed[k] ^= u[k];
  const msg = Buffer.concat([Buffer.from([0]), seed, block]);
  let m = BigInt('0x' + msg.toString('hex'));
  let r = 1n;
  let base = m % n;
  let exp = e;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % n;
    base = (base * base) % n;
    exp >>= 1n;
  }
  return Buffer.from(r.toString(16).padStart(keyLen * 2, '0'), 'hex');
}

const linkHeader = (size) => Buffer.concat([Buffer.from('REDQ', 'ascii'), u32(2), u32(2), u32(size)]);
const linkMess = (type, channelId, commonCaps, channelCaps) =>
  Buffer.concat([
    u32(0),
    u8(type),
    u8(channelId),
    u32(commonCaps.length),
    u32(channelCaps.length),
    u32(18),
    ...commonCaps.map(u32),
    ...channelCaps.map(u32),
  ]);
const msg = (type, data = Buffer.alloc(0)) => Buffer.concat([u16(type), u32(data.length), data]);

const ST = {
  CONNECTING: 0,
  OPEN: 1,
  START: 2,
  LINK: 3,
  TICKET: 4,
  READY: 5,
  CLOSE: 6,
  ERROR: 7,
};

class ClinkChannel {
  constructor(name, type, opts) {
    this.name = name;
    this.type = type;
    this.cfg = opts;
    this.buf = Buffer.alloc(0);
    this.need = 0;
    this.state = ST.CONNECTING;
    this.ready = false;
    this.channelCaps = opts.channelCaps || [];
    this.heartMs = opts.heartMs || 30000;
    this.hb = null;
    this.ws = null;
    this.heartbeats = 0;
    this.closed = false;
  }

  connect() {
    const url = `${this.cfg.base}/${this.cfg.desktopId}/${this.name}`;
    this.log(`ws → ${url}`);
    const ws = new RawWebSocket(url, {
      protocols: 'binary',
      origin: 'https://pc.ctyun.cn',
      timeout: 15000,
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        Referer: 'https://pc.ctyun.cn/',
      },
    });
    this.ws = ws;
    ws.on('open', () => {
      this.log('ws open');
      this.buf = Buffer.alloc(0);
      this.need = 1;
      this.state = ST.OPEN;
      ws.send(
        JSON.stringify({
          type: this.type,
          ssl: 1,
          host: this.cfg.host,
          port: this.cfg.port,
          ca: this.cfg.ca,
          cert: this.cfg.cert,
          key: this.cfg.key,
          servername: this.cfg.servername,
          oqs: 0,
        })
      );
    });
    ws.on('message', (d) => {
      this.buf = Buffer.concat([this.buf, Buffer.isBuffer(d) ? d : Buffer.from(String(d))]);
      this.pump();
    });
    ws.on('error', (e) => this.log(`ws error: ${String((e && e.message) || e).slice(0, 160)}`));
    ws.on('close', (code) => {
      this.closeCode = code;
      if (this.hb) {
        clearInterval(this.hb);
        this.hb = null;
      }
      this.ready = false;
      this.state = ST.CLOSE;
      this.closed = true;
      this.log(`closed ${code}`);
      if (this.cfg.onClose) this.cfg.onClose(this);
    });
  }

  log(m) {
    if (this.cfg.log) this.cfg.log(`[${this.name}] ${m}`);
  }

  pump() {
    while (this.need && this.buf.length >= this.need) {
      const chunk = this.buf.subarray(0, this.need);
      this.buf = this.buf.subarray(this.need);
      this.step(chunk);
      if (this.closed) return;
    }
  }

  step(chunk) {
    if (this.state === ST.OPEN) {
      if (chunk[0] !== 1) {
        this.log(`proxy rejected: ${JSON.stringify(chunk.toString('utf8'))}`);
        return;
      }
      const mess = linkMess(this.type, this.cfg.channelId || 0, [9], this.channelCaps);
      mess.writeUInt32LE(this.cfg.connectionId || 0, 0);
      this.ws.send(Buffer.concat([linkHeader(mess.length), mess]));
      this.state = ST.START;
      this.need = 16;
      return;
    }
    if (this.state === ST.START) {
      if (chunk.toString('ascii', 0, 4) !== 'REDQ') {
        this.log('bad magic');
        return;
      }
      this.need = chunk.readUInt32LE(12);
      this.state = ST.LINK;
      return;
    }
    if (this.state === ST.LINK) {
      const err = chunk.readUInt32LE(0);
      if (err) {
        this.log(`link error ${err}`);
        return;
      }
      const der = chunk.subarray(4, 166);
      const nc = chunk.readUInt32LE(166);
      const nch = chunk.readUInt32LE(170);
      const off = chunk.readUInt32LE(174);
      const caps = [];
      for (let i = 0; i < nc + nch; i += 1) caps.push(chunk.readUInt32LE(off + i * 4));
      this.serverCaps = caps;
      const auth = Buffer.alloc(4 + 128);
      auth.writeUInt32LE(1, 0);
      spiceTicket(der).copy(auth, 4);
      this.ws.send(auth);
      this.state = ST.TICKET;
      this.need = 4;
      return;
    }
    if (this.state === ST.TICKET) {
      const code = chunk.readUInt32LE(0);
      if (code !== 0) {
        this.log(`auth failed code=${code}`);
        if (this.cfg.onAuthFail) this.cfg.onAuthFail(code, this);
        return;
      }
      this.state = ST.READY;
      this.need = 6;
      this.ready = true;
      this.log(`READY (auth ok), heartbeat ${this.heartMs}ms`);
      this.startHeartbeat();
      if (this.cfg.onReady) this.cfg.onReady(this);
      return;
    }
    if (this.state === ST.READY && chunk.length === 6) {
      const type = chunk.readUInt16LE(0);
      const size = chunk.readUInt32LE(2);
      if (size === 0) {
        this.handle(type, Buffer.alloc(0));
        this.need = 6;
        return;
      }
      this._type = type;
      this.need = size;
      this.state = 'BODY';
      return;
    }
    if (this.state === 'BODY') {
      this.handle(this._type, chunk);
      this.state = ST.READY;
      this.need = 6;
      return;
    }
  }

  handle(type, data) {
    if (type === 4) {
      this.ws.send(msg(3, data.subarray(0, 12)));
      return;
    }
    if (type === 3) {
      this.ws.send(msg(1, u32(data.readUInt32LE(0))));
      return;
    }
    if (type === 9) {
      if (this.cfg.onHeartbeat) this.cfg.onHeartbeat(this);
      return;
    }
    if (type === 7) {
      this.log(`NOTIFY: ${data.subarray(4).toString('utf8').slice(0, 80)}`);
      return;
    }
    if (this.cfg.onMessage) this.cfg.onMessage(this, type, data);
  }

  startHeartbeat() {
    if (this.hb) clearInterval(this.hb);
    this.hb = setInterval(() => {
      if (!this.ready) return;
      try {
        this.ws.send(msg(7));
        this.heartbeats += 1;
      } catch (e) {
        this.log(`heartbeat send failed: ${e.message}`);
      }
    }, this.heartMs);
    if (this.hb.unref) this.hb.unref();
  }

  send(type, data) {
    if (!this.ready) return false;
    try {
      this.ws.send(msg(type, data));
      return true;
    } catch (_) {
      return false;
    }
  }

  close() {
    if (this.hb) {
      clearInterval(this.hb);
      this.hb = null;
    }
    this.ready = false;
    this.closed = true;
    try {
      if (this.ws) {
        this.ws.terminate();
      }
    } catch (_) {
      /* ignore */
    }
  }
}

/** CLINK_MSGC_MAIN_CLIENT_LOGIN_INFO(112)：36 字节头 + 4 个 NUL 结尾串 */
function loginInfo(desktopId, token, deviceType, deviceCode, userAccount = '') {
  const parts = [token, deviceType, deviceCode, userAccount];
  let off = 36;
  const head = [u32(Number(desktopId))];
  for (const p of parts) {
    head.push(u32(p.length + 1), u32(off));
    off += p.length + 1;
  }
  return Buffer.concat([...head, ...parts.map((p) => Buffer.concat([Buffer.from(p, 'utf8'), Buffer.from([0])]))]);
}

module.exports = {
  u8,
  u16,
  u32,
  spiceTicket,
  linkHeader,
  linkMess,
  msg,
  ST,
  ClinkChannel,
  loginInfo,
};
