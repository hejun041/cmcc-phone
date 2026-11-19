'use strict';

/**
 * 星晨超级智能体电脑（TeleAgent）保活 / 巡检引擎
 *
 * 说明：云电脑的「空闲回收」判定发生在桌面会话（CLINK）侧，manager 的 instance/list
 * 与 instance/heartbeat 都不产生活跃信号（heartbeat 只用于开机排队轮询）。
 * 因此本引擎负责的是**可用性保活**：
 *   - 按实例设定间隔巡检 instance/list；
 *   - 实例被回收（status=3 / statusReason=10）且开启 autoStart 时自动开机；
 *   - token 失效（4001）时标记账号过期并停止重试，避免无限打点；
 *   - 把最新状态写回 store，前端轮询即可看到。
 * 真正的协议级（CLINK 三通道 + 假鼠标）保活作为可选能力后续接入。
 */

class TeleaiKeepaliveEngine {
  constructor({ store, client, now = () => Date.now() }) {
    this.store = store;
    this.client = client;
    this.now = now;
    this.timers = new Map(); // instanceId -> { timer, lastRunAt, lastError, state, checks, starts }
    this.log = (ownerId, message, level = 'info', instanceId = '', name = '') =>
      store.appendLog(ownerId, { level, message, deviceId: instanceId, phoneName: name });
  }

  _runtime(id) {
    let rt = this.timers.get(id);
    if (!rt) {
      rt = { timer: null, lastRunAt: null, lastError: '', state: 'IDLE', checks: 0, starts: 0 };
      this.timers.set(id, rt);
    }
    return rt;
  }

  getRuntimeSnapshot(id) {
    const rt = this.timers.get(id);
    return {
      state: rt ? rt.state : 'IDLE',
      stateText: rt ? this._stateText(rt.state) : '未启动',
      lastRunAt: rt ? rt.lastRunAt : null,
      lastError: rt ? rt.lastError : '',
      checks: rt ? rt.checks : 0,
      starts: rt ? rt.starts : 0,
    };
  }

  _stateText(state) {
    return (
      {
        IDLE: '未启动',
        CHECKING: '巡检中',
        KEEPING: '保活中',
        STARTING: '开机中',
        AUTH_EXPIRED: '登录失效',
        ERROR: '异常',
      }[state] || state
    );
  }

  reconcileAll() {
    for (const inst of this.store.listAllTeleaiInstancesInternal()) {
      this.reconcileInstance(inst.id);
    }
  }

  reconcileInstance(id) {
    const target = this.store.listAllTeleaiInstancesInternal().find((i) => i.id === id);
    const rt = this._runtime(id);
    if (!target || !target.keepaliveEnabled) {
      this.stop(id);
      rt.state = target ? 'IDLE' : rt.state;
      return;
    }
    const interval = Math.max(15, Number(target.checkIntervalSec) || 60) * 1000;
    if (rt.timer) return; // 已在跑
    rt.state = 'KEEPING';
    rt.timer = setInterval(() => {
      this.tick(id).catch(() => {});
    }, interval);
    if (rt.timer.unref) rt.timer.unref();
    // 不在启用瞬间立刻巡检，避免刚绑定就把实例开机；首个巡检在 interval 之后
  }

  stop(id) {
    const rt = this.timers.get(id);
    if (rt && rt.timer) {
      clearInterval(rt.timer);
      rt.timer = null;
      rt.state = 'IDLE';
    }
  }

  stopAll() {
    for (const id of this.timers.keys()) this.stop(id);
  }

  async tick(id) {
    const inst = this.store.listAllTeleaiInstancesInternal().find((i) => i.id === id);
    if (!inst || !inst.keepaliveEnabled) return;
    const rt = this._runtime(id);
    if (rt.state === 'AUTH_EXPIRED') return;
    const acc = this.store.getTeleaiAccountInternal(inst.accountId);
    if (!acc) return;

    rt.state = 'CHECKING';
    rt.lastRunAt = this.now();
    try {
      const list = await this.client.listInstances(acc);
      rt.checks += 1;
      this.store.syncTeleaiInstances(acc.ownerId, acc.id, list);
      const fresh = this.store.listAllTeleaiInstancesInternal().find((i) => i.instanceId === inst.instanceId);
      if (!fresh) {
        rt.state = 'KEEPING';
        return;
      }
      if (fresh.status === 3) {
        if (fresh.autoStart) {
          rt.state = 'STARTING';
          this.log(fresh.ownerId, `实例 ${fresh.instanceId.slice(-6)} 已回收，自动开机中…`, 'info', fresh.id, fresh.name);
          await this.client.instanceAction(acc, 'start', fresh.instanceId);
          this.store.updateTeleaiInstance(fresh.id, { lastStartAt: Date.now(), lastError: '' });
          rt.starts += 1;
          this.log(fresh.ownerId, `实例 ${fresh.instanceId.slice(-6)} 开机指令已下发`, 'success', fresh.id, fresh.name);
        } else {
          this.log(fresh.ownerId, `实例 ${fresh.instanceId.slice(-6)} 已回收（未开启自动开机）`, 'warn', fresh.id, fresh.name);
        }
      }
      rt.state = 'KEEPING';
      rt.lastError = '';
    } catch (err) {
      const code = err && err.code;
      if (code === '4001') {
        rt.state = 'AUTH_EXPIRED';
        this.store.updateTeleaiAccountTokens(acc.id, { authStatus: 'expired' });
        this.log(acc.ownerId, `账号 ${acc.loginName} 云端登录已失效，请一键续期`, 'error', inst.id, inst.name);
      } else {
        rt.state = 'ERROR';
        rt.lastError = String((err && err.message) || err);
        this.store.updateTeleaiInstance(inst.id, { lastError: rt.lastError });
      }
    }
  }
}

module.exports = { TeleaiKeepaliveEngine };
