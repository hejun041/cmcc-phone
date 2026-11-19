'use strict';

/**
 * CLINK 保活任务管理：实例 → ClinkWorker 的一对一映射。
 * 默认不做任何事，只有实例上显式 clinkEnabled=true 才会建立桌面长连接。
 */

const { ClinkWorker } = require('./clinkWorker');

class ClinkManager {
  constructor({ store, client, log }) {
    this.store = store;
    this.client = client;
    this.workers = new Map(); // instanceId(store id) -> ClinkWorker
    this.writeLog = log || ((ownerId, msg, level) => store.appendLog(ownerId, { level, message: msg }));
  }

  get(id) {
    return this.workers.get(id) || null;
  }

  snapshot(id) {
    const w = this.workers.get(id);
    return w ? w.snapshot() : null;
  }

  start(inst, acc) {
    if (!inst || !acc) throw new Error('实例或账号不存在');
    const exist = this.workers.get(inst.id);
    if (exist && exist.state !== 'stopped') return exist;
    const worker = new ClinkWorker({
      id: inst.id,
      name: inst.name,
      ownerId: inst.ownerId,
      client: this.client,
      account: acc,
      moveSec: inst.moveSec || 30,
      kickWaitSec: inst.kickWaitSec === undefined ? 1800 : inst.kickWaitSec,
      onLog: (line) => {
        // 只把关键行写进平台日志，避免刷屏
        if (/READY|LOGIN_INFO|MAIN_INIT|被接管|失败|error|认证被拒|CLIENT_OFFLINE|已停止/.test(line)) {
          this.writeLog(inst.ownerId, `[CLINK] ${line}`, /失败|error|被接管|认证被拒/.test(line) ? 'warn' : 'info');
        }
      },
      onChange: () => {},
    });
    this.workers.set(inst.id, worker);
    worker.start().catch((e) => {
      this.writeLog(inst.ownerId, `[CLINK] 启动失败：${e.message}`, 'error');
    });
    return worker;
  }

  stop(id, { silent = false } = {}) {
    const w = this.workers.get(id);
    if (!w) return false;
    w.stop();
    this.workers.delete(id);
    if (!silent && w.ownerId) this.writeLog(w.ownerId, '[CLINK] 已关闭协议级保活', 'info');
    return true;
  }

  async restart(id, inst, acc) {
    this.stop(id, { silent: true });
    return this.start(inst, acc);
  }

  /** 服务启动时按 store 里 clinkEnabled 的实例拉起 */
  reconcileAll() {
    for (const inst of this.store.listAllTeleaiInstancesInternal()) {
      if (!inst.clinkEnabled) continue;
      const acc = this.store.getTeleaiAccountInternal(inst.accountId);
      if (!acc || acc.authStatus !== 'valid') continue;
      if (!this.workers.has(inst.id)) this.start(inst, acc);
    }
  }

  stopAll() {
    for (const id of Array.from(this.workers.keys())) this.stop(id, { silent: true });
  }
}

module.exports = { ClinkManager };
