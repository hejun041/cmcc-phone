'use strict';

/**
 * 星辰超级智能体（TeleAgent）登录图形验证码求解
 *
 * 协议：AJ-Captcha blockPuzzle
 *   POST /teleai-api/upms/public/captcha/get  → originalImageBase64(311x155) + jigsawImageBase64(47x155)
 *   POST /teleai-api/upms/public/captcha/check {pointJson: AES-128-ECB(JSON{x,y:5}, secretKey), token}
 *
 * 求解原理：拼图块本体在 jigsaw 画布的 y=63..108 段；背景图在缺口处有白色描边。
 * 把「拼图块轮廓」在背景同一 y 带内水平滑动，白色像素命中最多处即缺口位置。
 * 纯 Node 实现（zlib 解 PNG），不依赖任何第三方库或外部进程。
 */

const zlib = require('zlib');

/* ------------------------------ PNG 解码 ------------------------------ */
function decodePng(buf) {
  if (buf.readUInt32BE(0) !== 0x89504e47) throw new Error('不是 PNG');
  let pos = 8;
  let width = 0;
  let height = 0;
  let bitDepth = 8;
  let colorType = 6;
  let interlace = 0;
  const idat = [];

  while (pos < buf.length) {
    const len = buf.readUInt32BE(pos);
    const type = buf.toString('ascii', pos + 4, pos + 8);
    const data = buf.subarray(pos + 8, pos + 8 + len);
    if (type === 'IHDR') {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      bitDepth = data[8];
      colorType = data[9];
      interlace = data[12];
    } else if (type === 'IDAT') {
      idat.push(data);
    } else if (type === 'IEND') {
      break;
    }
    pos += 12 + len;
  }
  if (bitDepth !== 8 || interlace !== 0) throw new Error('仅支持 8bit 非隔行 PNG');
  const channels = { 0: 1, 2: 3, 4: 2, 6: 4 }[colorType];
  if (!channels) throw new Error('不支持的 PNG 颜色类型 ' + colorType);

  const raw = zlib.inflateSync(Buffer.concat(idat));
  const bpp = channels;
  const stride = width * bpp;
  const out = Buffer.alloc(width * height * 4);
  const prev = Buffer.alloc(stride);
  let p = 0;

  for (let y = 0; y < height; y += 1) {
    const filter = raw[p];
    p += 1;
    const line = raw.subarray(p, p + stride);
    p += stride;
    const cur = Buffer.alloc(stride);
    for (let i = 0; i < stride; i += 1) {
      const a = i >= bpp ? cur[i - bpp] : 0;
      const b = prev[i];
      const c = i >= bpp ? prev[i - bpp] : 0;
      const x = line[i];
      let v;
      switch (filter) {
        case 0: v = x; break;
        case 1: v = x + a; break;
        case 2: v = x + b; break;
        case 3: v = x + ((a + b) >> 1); break;
        case 4: {
          const pa = Math.abs(b - c);
          const pb = Math.abs(a - c);
          const pc = Math.abs(a + b - 2 * c);
          v = x + (pa <= pb && pa <= pc ? a : pb <= pc ? b : c);
          break;
        }
        default: throw new Error('未知 PNG 过滤器 ' + filter);
      }
      cur[i] = v & 0xff;
    }
    for (let x = 0; x < width; x += 1) {
      const o = (y * width + x) * 4;
      const s = x * bpp;
      if (channels === 4) {
        out[o] = cur[s]; out[o + 1] = cur[s + 1]; out[o + 2] = cur[s + 2]; out[o + 3] = cur[s + 3];
      } else if (channels === 3) {
        out[o] = cur[s]; out[o + 1] = cur[s + 1]; out[o + 2] = cur[s + 2]; out[o + 3] = 255;
      } else if (channels === 1) {
        out[o] = out[o + 1] = out[o + 2] = cur[s]; out[o + 3] = 255;
      } else {
        out[o] = out[o + 1] = out[o + 2] = cur[s]; out[o + 3] = cur[s + 1];
      }
    }
    cur.copy(prev);
  }
  return { width, height, data: out };
}

/* ------------------------------ 缺口求解 ------------------------------ */
function solvePuzzle(originalB64, jigsawB64) {
  const orig = decodePng(Buffer.from(originalB64, 'base64'));
  const jig = decodePng(Buffer.from(jigsawB64, 'base64'));
  const { width: W, height: H } = orig;
  const O = orig.data;
  const J = jig.data;
  const JW = jig.width;
  const JH = jig.height;

  // 拼图块 bbox（alpha > 10）
  let minX = JW;
  let minY = JH;
  let maxX = -1;
  let maxY = -1;
  for (let y = 0; y < JH; y += 1) {
    for (let x = 0; x < JW; x += 1) {
      if (J[(y * JW + x) * 4 + 3] > 10) {
        if (x < minX) minX = x;
        if (x > maxX) maxX = x;
        if (y < minY) minY = y;
        if (y > maxY) maxY = y;
      }
    }
  }
  if (maxX < 0) throw new Error('拼图块为空');
  const pw = maxX - minX + 1;
  const ph = maxY - minY + 1;

  // 形状掩码
  const mask = new Uint8Array(pw * ph);
  for (let y = 0; y < ph; y += 1) {
    for (let x = 0; x < pw; x += 1) {
      mask[y * pw + x] = J[((minY + y) * JW + (minX + x)) * 4 + 3] > 10 ? 1 : 0;
    }
  }

  // 轮廓 = 掩码 - 腐蚀(2 次)
  let er = mask.slice();
  for (let it = 0; it < 2; it += 1) {
    const next = new Uint8Array(er.length);
    for (let y = 0; y < ph; y += 1) {
      for (let x = 0; x < pw; x += 1) {
        const i = y * pw + x;
        if (!er[i]) continue;
        const up = y > 0 ? er[i - pw] : 0;
        const dn = y < ph - 1 ? er[i + pw] : 0;
        const lf = x > 0 ? er[i - 1] : 0;
        const rt = x < pw - 1 ? er[i + 1] : 0;
        next[i] = up && dn && lf && rt ? 1 : 0;
      }
    }
    er = next;
  }
  const ring = [];
  for (let y = 0; y < ph; y += 1) {
    for (let x = 0; x < pw; x += 1) {
      const i = y * pw + x;
      if (mask[i] && !er[i]) ring.push([x, y]);
    }
  }
  const ringPts = ring.length > 40 ? ring : maskIndexes(mask, pw, ph);

  // 背景白色（描边）
  const isWhite = (x, y) => {
    const o = (y * W + x) * 4;
    return O[o] > 215 && O[o + 1] > 215 && O[o + 2] > 215;
  };

  const scores = new Array(Math.max(0, W - pw + 1)).fill(0);
  for (let x = 0; x < scores.length; x += 1) {
    let hit = 0;
    for (let k = 0; k < ringPts.length; k += 1) {
      const [dx, dy] = ringPts[k];
      const yy = minY + dy;
      const xx = x + dx;
      if (yy < H && xx < W && isWhite(xx, yy)) hit += 1;
    }
    scores[x] = hit;
  }

  // 取局部极大值，按分数排序后按 12px 去重
  const peaks = [];
  for (let x = 0; x < scores.length; x += 1) {
    let isPeak = true;
    for (let d = -6; d <= 6 && isPeak; d += 1) {
      if (d === 0) continue;
      const j = x + d;
      if (j >= 0 && j < scores.length && scores[j] > scores[x]) isPeak = false;
    }
    if (isPeak && scores[x] > 0) peaks.push([scores[x], x]);
  }
  peaks.sort((a, b) => b[0] - a[0]);
  const candidates = [];
  for (const [score, x] of peaks) {
    if (candidates.every((c) => Math.abs(c - x) > 12)) candidates.push(x);
    if (candidates.length >= 5) break;
  }
  if (candidates.length === 0) candidates.push(0);

  return { x: candidates[0], y: minY, candidates, scores: peaks.slice(0, 5), size: [pw, ph], imageWidth: W };
}

function maskIndexes(mask, pw, ph) {
  const out = [];
  for (let y = 0; y < ph; y += 1) for (let x = 0; x < pw; x += 1) if (mask[y * pw + x]) out.push([x, y]);
  return out;
}

module.exports = { decodePng, solvePuzzle };
