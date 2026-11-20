'use strict';

/**
 * 星晨超级智能体电脑（TeleAgent）保活 / 巡检引擎
 *
 * 说明：云电脑的「空闲回收」判定发生在桌面会话（CLINK）侧，manager 的 instance/list
 * 与 instance/heartbeat 都不产生活跃信号（heartbeat 只用于开机排队轮询）。
 * 因此本引擎负责的是**可用性保活**：
 *   - 按实例设定间隔巡检 instance/list；
 *   - 实例被回收（status=3 / statusReason=10）且开启 autoStart 时自动开机；
 *   - 账号级自动续期：operationToken 剩余天数低于阈值（默认 2 天）时用保存的密码重登换新 token；
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
    this.accountTimer = null;
    this.accountSweepMs = Number(process.env.TELEAI_ACCOUNT_SWEEP_MS) > 0
      ? Number(process.env.TELEAI_ACCOUNT_SWEEP_MS)
      : 30 * 60 * 1000; // 默认每 30 分钟扫一次账号到期情况
    this.autoRenewRetryMs = Number(process.env.TELEAI_AUTORENEW_RETRY_MS) > 0
      ? Number(process.env.TELEAI_AUTORENEW_RETRY_MS)
      : 30 * 60 * 1000; // 自动续期失败后的重试间隔
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
    this.startAccountSweep();
  }

  /** 账号级定时扫描：自动续期（不依赖实例是否存在） */
  startAccountSweep() {
    if (this.accountTimer) return;
    this.accountTimer = setInterval(() => {
      this.checkAllAccounts().catch(() => {});
    }, this.accountSweepMs);
    if (this.accountTimer.unref) this.accountTimer.unref();
    // 启动时先跑一次，避免刚重启错过续期窗口
    setTimeout(() => this.checkAllAccounts().catch(() => {}), 15 * 1000).unref?.();
  }

  stopAccountSweep() {
    if (this.accountTimer) {
      clearInterval(this.accountTimer);
      this.accountTimer = null;
    }
  }

  /**
   * 遍历账号：operationToken 剩余天数 < autoRenewDays 就用保存的密码重新登录换新 token。
   * 默认提前 2 天（可改 1~30），失败间隔 30 分钟重试，不会无限打登录接口。
   */
  async checkAllAccounts() {
    const accounts = this.store.listAllTeleaiAccountsInternal();
    for (const acc of accounts) {
      if (acc.autoRenewEnabled === false) continue;
      if (!acc.hasPassword) continue;
      const days = Number(acc.autoRenewDays) || 2;
      const exp = acc.tokenExpiresAt ? Number(acc.tokenExpiresAt) : 0;
      if (!exp) continue;
      const remainDays = (exp - Date.now()) / 86400000;
      if (remainDays > days) continue;
      // 失败按 retry 间隔重试；成功也要间隔（默认 6 小时），避免阈值设得比 token 总时长还大时反复登录
      const since = acc.lastAutoRenewAt ? Date.now() - acc.lastAutoRenewAt : Infinity;
      if (acc.lastAutoRenewOk && since < 6 * 3600 * 1000) continue;
      if (acc.lastAutoRenewAt && since < this.autoRenewRetryMs) continue;
      try {
        const data = await this.client.loginWithPassword(acc.loginName, acc.password);
        this.store.updateTeleaiAccountTokens(acc.id, {
          operationToken: data.operationToken,
          operToken: data.operToken,
          aesKey: data.aesKey,
          aesIv: data.aesIv,
          expiresAt: data.expiresAt,
          authStatus: 'valid',
          renewed: true,
        });
        this.store.markTeleaiAutoRenew(acc.id, { ok: true, message: '自动续期成功' });
        this.log(
          acc.ownerId,
          `账号 ${acc.loginName} 剩余 ${remainDays.toFixed(1)} 天，已自动续期至 ${new Date(data.expiresAt).toLocaleString('zh-CN')}`,
          'success'
        );
      } catch (e) {
        const msg = e && e.code === '10980039' ? '密码不正确，自动续期失败' : e.message;
        this.store.markTeleaiAutoRenew(acc.id, { ok: false, message: msg });
        this.log(acc.ownerId, `账号 ${acc.loginName} 自动续期失败：${msg}`, 'error');
      }
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
    this.stopAccountSweep();
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

      const status = Number(fresh.status);
      const running = status === 4 || status === 100;

      if (running) {
        // ① 活跃信标：前端在每次文件操作前都会调 instance/refresh，这才是重置「长时间未活跃」的东西
        if (fresh.refreshEnabled) {
          try {
            await this.client.refreshInstance(acc, fresh.instanceId);
            this.store.updateTeleaiInstance(fresh.id, { lastRefreshAt: Date.now() });
          } catch (e) {
            if (e && e.code === '4001') throw e;
            rt.lastError = `refresh 失败：${e.message}`;
          }
        }
        // ② 每 5 轮做一次四路健康诊断，识别「status=100 但组件没 READY」的假活
        rt.healthTick = (rt.healthTick || 0) + 1;
        if (rt.healthTick % 5 === 1) {
          const health = await this.client.instanceInfo(acc, fresh.instanceId).catch(() => null);
          if (health) {
            // 只有 apiServer / relay 异常才算"假活"；localStatus 常见 INIT（agent 侧状态），仅作展示
            const bad = [];
            if (health.apiServer && health.apiServer !== 'READY') bad.push('apiServer');
            if (health.relay && health.relay !== 'ONLINE') bad.push('relay');
            this.store.updateTeleaiInstance(fresh.id, { health, degraded: bad.length > 0 });
            if (bad.length && !rt.degradedLogged) {
              rt.degradedLogged = true;
              this.log(fresh.ownerId, `实例 ${fresh.instanceId.slice(-6)} 组件未就绪（${bad.join('/')}），建议重启`, 'warn', fresh.id, fresh.name);
            }
            if (!bad.length) rt.degradedLogged = false;
          }
        }
      } else if (fresh.autoStart) {
        rt.state = 'STARTING';
        this.log(fresh.ownerId, `实例 ${fresh.instanceId.slice(-6)} 状态 ${status}，自动开机中…`, 'info', fresh.id, fresh.name);
        await this.client.instanceAction(acc, 'start', fresh.instanceId);
        this.store.updateTeleaiInstance(fresh.id, { lastStartAt: Date.now(), lastError: '' });
        rt.starts += 1;
        this.log(fresh.ownerId, `实例 ${fresh.instanceId.slice(-6)} 开机指令已下发`, 'success', fresh.id, fresh.name);
      } else {
        this.log(fresh.ownerId, `实例 ${fresh.instanceId.slice(-6)} 状态 ${status}（未开启自动开机）`, 'warn', fresh.id, fresh.name);
      }

      // ③ 每日签到（幂等，一天只发一次）
      await this.maybeCheckin(acc);

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

  /** 每日签到：同一账号每天只发一次，失败次日重试 */
  async maybeCheckin(acc) {
    const last = acc.lastCheckinAt ? new Date(acc.lastCheckinAt) : null;
    const today = new Date();
    if (last && last.toDateString() === today.toDateString() && acc.lastCheckinOk) return;
    try {
      const r = await this.client.checkin(acc);
      this.store.markTeleaiCheckin(acc.id, { ok: r.ok, message: r.ok ? '签到成功' : JSON.stringify(r.body).slice(0, 160) });
      if (r.ok) this.log(acc.ownerId, `账号 ${acc.loginName} 每日签到完成`, 'success');
    } catch (e) {
      if (e && e.code === '4001') throw e;
      this.store.markTeleaiCheckin(acc.id, { ok: false, message: e.message });
    }
  }
}

module.exports = { TeleaiKeepaliveEngine };
