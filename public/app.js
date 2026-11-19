(function () {
  'use strict';

  const state = {
    authMode: 'login',
    user: null,
    accounts: [],
    devices: [],
    teleaiAccounts: [],
    teleaiInstances: [],
    logs: [],
    pollTimer: null,

    // SMS Captcha
    captchaSessionId: '',
    smsCountdown: 0,
    smsTimer: null,
    bindFlow: new window.CloudChannels.BindingFlow(),
    bindTicket: null,
    bindAccountId: '',
    captchaDimensions: null,
    captchaFraction: 0,
    deviceProvider: 'all',
    providers: { cmcc: true, yunzhi: false },
    yunzhiJobs: new Map(),
    jobTimers: new Set(),

    // Active Remote Viewer
    activeDeviceId: '',
    activePlatformType: '1',
    yunPlayer: null,
    tPlayer: null,
    yunzhiPlayer: null,
    viewerGeneration: 0,
    viewerMuted: true,
    leaseHeartbeatTimer: null,
  };

  const $ = (id) => document.getElementById(id);

  function showToast(msg, duration = 2400) {
    const box = $('toastBox');
    const el = document.createElement('div');
    el.className = 'toast-item';
    el.textContent = msg;
    box.appendChild(el);
    setTimeout(() => el.remove(), duration);
  }

  async function api(path, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (options.body && typeof options.body === 'object') {
      headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(options.body);
    }
    const res = await fetch(path, { credentials: 'same-origin', ...options, headers });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.ok === false) {
      if (res.status === 401 && !path.startsWith('/api/auth/') && !path.startsWith('/api/cmcc/')) {
        switchToAuthView();
      }
      throw new Error(data.error || `请求异常 (${res.status})`);
    }
    return data;
  }

  function escapeHtml(str) {
    return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function formatDuration(sec) {
    const s = Math.max(0, Math.floor(Number(sec) || 0));
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    const r = s % 60;
    if (d > 0) return `${d}天 ${h}时 ${m}分`;
    if (h > 0) return `${h}时 ${m}分 ${r}秒`;
    if (m > 0) return `${m}分 ${r}秒`;
    return `${r}秒`;
  }

  // 云智渠道的到期时间是秒（控制桥口径），星辰渠道是毫秒；统一归一化，避免出现 58899 年
  function toMillis(ts) {
    const n = Number(ts) || 0;
    if (!n) return 0;
    return n > 1e12 ? n : n * 1000;
  }

  function formatDateTime(ts) {
    const ms = toMillis(ts);
    if (!ms) return '未知';
    const d = new Date(ms);
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function formatTime(ts) {
    if (!ts) return '--:--';
    const d = new Date(ts);
    const pad = (n) => String(n).padStart(2, '0');
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  // ===== 1. Initialize =====
  async function init() {
    bindAuthEvents();
    bindDashboardEvents();
    bindBindAccountEvents();
    bindSliderEvents();
    bindAdminEvents();
    bindViewerEvents();

    try {
      const me = await api('/api/auth/me');
      state.user = me.user;
      await enterDashboard();
    } catch (_) {
      await switchToAuthView();
    }
  }

  // ===== 2. Auth View =====

  async function switchToAuthView() {
    stopPolling();
    state.user = null;
    $('viewerModal').classList.add('hidden');
    await destroyActivePlayers(false);
    state.activeDeviceId = '';
    clearBinding();
    for (const timer of state.jobTimers) clearTimeout(timer);
    state.jobTimers.clear();
    state.yunzhiJobs.clear();
    $('bindModal').classList.add('hidden');
    $('dashboardView').classList.add('hidden');
    $('authView').classList.remove('hidden');
    try {
      const boot = await api('/api/auth/bootstrap');
      setAuthMode(boot.hasAnyUser ? 'login' : 'register');
    } catch (_) {
    }
  }

  function setAuthMode(mode) {
    state.authMode = mode;
    $('authTitle').textContent = mode === 'login' ? '账号登录' : '注册管理员账号';
    $('authSubmitBtn').textContent = mode === 'login' ? '进入控制中心' : '创建并进入';
    $('authToggleBtn').textContent = mode === 'login' ? '切换注册' : '切换登录';
  }

  function bindAuthEvents() {
    $('authToggleBtn').addEventListener('click', () => {
      setAuthMode(state.authMode === 'login' ? 'register' : 'login');
    });

    $('authForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = $('authUsername').value.trim();
      const password = $('authPassword').value;
      const btn = $('authSubmitBtn');
      btn.disabled = true;
      try {
        const endpoint = state.authMode === 'register' ? '/api/auth/register' : '/api/auth/login';
        const res = await api(endpoint, {
          method: 'POST',
          body: {
            username,
            password,
          }
        });
        state.user = res.user;
        $('authPassword').value = '';
        showToast(`欢迎回来，${res.user.username}`);
        await enterDashboard();
      } catch (err) {
        showToast(err.message);
      } finally {
        btn.disabled = false;
      }
    });
  }

  // ===== 3. Dashboard =====
  async function enterDashboard() {
    const device = new URLSearchParams(location.search).get('device');
    if (location.pathname === '/control.html' && device) {
      $('authView').classList.add('hidden');
      $('dashboardView').classList.add('hidden');
      await refreshDashboard(true);
      await openWebViewer(device);
      return;
    }

    $('authView').classList.add('hidden');
    $('dashboardView').classList.remove('hidden');
    $('currentUserText').textContent = `${state.user.username} · ${state.user.role === 'admin' ? '系统管理员' : '独立租户'}`;
    $('adminBtn').classList.toggle('hidden', state.user.role !== 'admin');

    await refreshDashboard();
    stopPolling();
    state.pollTimer = setInterval(() => refreshDashboard(true).catch(() => {}), 5000);
  }

  function stopPolling() {
    if (state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  }

  async function refreshDashboard(silent = false) {
    try {
      const data = await api('/api/dashboard');
      state.user = data.user;
      state.accounts = data.accounts || [];
      state.devices = data.devices || [];
      state.teleaiAccounts = data.teleaiAccounts || [];
      state.teleaiInstances = data.teleaiInstances || [];
      state.logs = data.logs || [];
      state.providers = data.providers || { cmcc: true, yunzhi: false };
      renderOverview();
      renderAccounts();
      renderTeleaiAccounts();
      renderDevices();
      renderLogs();
    } catch (err) {
      if (!silent) showToast(err.message);
    }
  }

  function renderOverview() {
    $('kpiAccounts').textContent = `${state.accounts.length} / ${state.user.maxAccounts}`;
    $('kpiDevices').textContent = String(state.devices.length);
    const keeping = state.devices.filter(
      (d) => d.provider !== 'yunzhi' && d.runtime && (d.runtime.state === 'KEEPING' || d.runtime.state === 'WEB_CONTROL')
    ).length;
    $('kpiKeeping').textContent = String(keeping);
    const totalBeats = state.devices.reduce((acc, d) => acc + (d.runtime?.heartbeatCount || 0), 0);
    $('kpiHeartbeats').textContent = String(totalBeats);
    const tl = $('kpiTeleai');
    if (tl) tl.textContent = `${state.teleaiInstances.length} 台 / ${state.teleaiAccounts.length} 号`;
  }

  function renderAccounts() {
    const groups = window.CloudChannels.groupAccounts(state.accounts);
    for (const provider of ['cmcc', 'yunzhi']) {
      const list = $(provider === 'cmcc' ? 'accountList' : 'yunzhiAccountList');
      if (groups[provider].length === 0) {
        list.innerHTML = `<div class="channel-hint">${provider === 'yunzhi' && !state.providers.yunzhi
          ? '云智渠道尚未配置，请联系管理员' : `未绑定${provider === 'yunzhi' ? '云智手机' : '移动云手机'}账号，请点击右上角绑定`}</div>`;
        continue;
      }
      list.innerHTML = groups[provider].map((a) => {
        const isNormal = a.authStatus === 'valid';
        const badge = isNormal
          ? `<span class="badge badge-success"><span class="badge-dot"></span>有效</span>`
          : `<span class="badge badge-danger"><span class="badge-dot"></span>${a.pendingDelete ? '解绑待完成' : a.authStatus === 'disabled' ? '已停用' : '已过期'}</span>`;
        return `
          <div class="account-pill">
            <div class="account-info">
              <div class="account-phone">${escapeHtml(a.mobile || a.displayName || '云智账号')} ${badge}${a.sharedAccount ? ' <span class="badge badge-neutral">青龙共享</span>' : ''}</div>
              <div class="account-desc">${escapeHtml(a.remark || '未设置备注')} · ${provider === 'yunzhi'
                ? `登录到期：${a.tokenExpiresAt ? escapeHtml(new Date(toMillis(a.tokenExpiresAt)).toLocaleString('zh-CN', { hour12: false })) : '以官方状态为准'}`
                : `省份: ${escapeHtml(a.province || '自动')}`}</div>
              ${a.sharedAccount ? '<div class="account-desc">原青龙继续执行签到；解除关联保留原账号和凭据</div>' : ''}
            </div>
            <div class="account-actions">
              <button class="btn btn-secondary btn-sm" data-act="sync-acc" data-id="${a.id}" ${a.pendingDelete ? 'disabled' : ''}>同步</button>
              ${provider === 'yunzhi' && !a.pendingDelete && /^1[3-9]\d{9}$/.test(a.mobile || '') ? `<button class="btn btn-secondary btn-sm" data-act="renew-acc" data-id="${a.id}">登录续期</button>` : ''}
              ${provider === 'yunzhi' && !a.pendingDelete && !a.sharedAccount ? `
                <button class="btn btn-secondary btn-sm" data-act="smoke-acc" data-id="${a.id}">只读检查</button>
                <button class="btn btn-secondary btn-sm" data-act="checkin-acc" data-id="${a.id}">签到</button>` : ''}
              <button class="btn btn-danger btn-sm" data-act="del-acc" data-id="${a.id}" data-mobile="${escapeHtml(a.mobile)}">${a.pendingDelete ? '重试解绑' : a.sharedAccount ? '解除关联' : '解绑'}</button>
            </div>
          </div>
        `;
      })
      .join('');
    }
  }

  function getStatusBadge(rt) {
    if (!rt) return `<span class="badge badge-neutral"><span class="badge-dot"></span>未启动</span>`;
    if (rt.state === 'KEEPING') return `<span class="badge badge-success"><span class="badge-dot"></span>保活中</span>`;
    if (rt.state === 'WEB_CONTROL') return `<span class="badge badge-warning"><span class="badge-dot"></span>正在控制</span>`;
    if (rt.state === 'SCHEDULE_WAIT') return `<span class="badge badge-neutral"><span class="badge-dot"></span>定时等待</span>`;
    if (rt.state === 'RECONNECTING') return `<span class="badge badge-warning"><span class="badge-dot"></span>重连中</span>`;
    if (rt.state === 'ERROR') return `<span class="badge badge-danger"><span class="badge-dot"></span>异常</span>`;
    return `<span class="badge badge-neutral"><span class="badge-dot"></span>${escapeHtml(rt.stateText || '空闲')}</span>`;
  }

  function renderTeleaiAccounts() {
    const list = $('teleaiAccountList');
    if (!list) return;
    if (state.teleaiAccounts.length === 0) {
      list.innerHTML = `<div style="font-size:12px;color:var(--text-tertiary);padding:8px 0;">未绑定星辰智能体电脑账号，点击右上角「+ 绑定星辰电脑」</div>`;
      return;
    }
    list.innerHTML = state.teleaiAccounts
      .map((a) => {
        const ok = a.authStatus === 'valid';
        const badge = ok
          ? `<span class="badge badge-success"><span class="badge-dot"></span>有效</span>`
          : `<span class="badge badge-danger"><span class="badge-dot"></span>登录失效</span>`;
        const exp = formatDateTime(a.tokenExpiresAt);
        return `
          <div class="account-pill">
            <div class="account-info">
              <div class="account-phone">${escapeHtml(a.loginName)} ${badge} <span class="badge badge-neutral">星辰电脑</span></div>
              <div class="account-desc">${escapeHtml(a.remark || '未设置备注')} · Token 到期: ${exp}</div>
            </div>
            <div style="display:flex;gap:6px;">
              <button class="btn btn-secondary btn-sm" data-act="tl-renew" data-id="${a.id}" data-login="${escapeHtml(a.loginName)}">一键续期</button>
              <button class="btn btn-secondary btn-sm" data-act="tl-sync" data-id="${a.id}">同步</button>
              <button class="btn btn-danger btn-sm" data-act="tl-unbind" data-id="${a.id}" data-login="${escapeHtml(a.loginName)}">解绑</button>
            </div>
          </div>
        `;
      })
      .join('');
  }

  function teleaiCard(inst) {
    const rt = inst.runtime || {};
    const statusMap = {
      ready: ['badge-success', '运行中'],
      starting: ['badge-warning', '启动中'],
      recycled: ['badge-neutral', '已回收'],
      stopped: ['badge-neutral', '已关机'],
      unknown: ['badge-neutral', '未知'],
    };
    const [cls, text] = statusMap[inst.stateText] || ['badge-neutral', inst.stateText || '未知'];
    const cl = inst.clink;
    const clinkBadge = !inst.clinkEnabled
      ? '<span class="badge badge-neutral"><span class="badge-dot"></span>协议保活关闭</span>'
      : cl && cl.state === 'running'
        ? `<span class="badge badge-success"><span class="badge-dot"></span>CLINK 已连接</span>`
        : cl && cl.state === 'paused'
          ? '<span class="badge badge-warning"><span class="badge-dot"></span>会话被接管</span>'
          : cl && cl.state === 'connecting'
            ? '<span class="badge badge-warning"><span class="badge-dot"></span>CLINK 连接中</span>'
            : `<span class="badge badge-danger"><span class="badge-dot"></span>CLINK ${escapeHtml((cl && cl.state) || '未启动')}</span>`;
    const clinkStats = cl
      ? `心跳 ${cl.channels?.MAIN?.heartbeats || 0} · 输入 ${cl.sentCount} · ACK ${cl.ackCount} · 重连 ${cl.reconnects}`
      : '未建立桌面会话';
    const rtBadge =
      rt.state === 'AUTH_EXPIRED'
        ? `<span class="badge badge-danger"><span class="badge-dot"></span>登录失效</span>`
        : rt.state === 'STARTING'
          ? `<span class="badge badge-warning"><span class="badge-dot"></span>开机中</span>`
          : inst.keepaliveEnabled
            ? `<span class="badge badge-success"><span class="badge-dot"></span>巡检保活中</span>`
            : `<span class="badge badge-neutral"><span class="badge-dot"></span>保活关闭</span>`;
    return `
      <div class="device-card teleai-card">
        <div class="device-top">
          <div>
            <div class="device-title">${escapeHtml(inst.name)} <span class="badge badge-neutral" style="font-size:10px;">星辰电脑</span></div>
            <div class="device-subtitle">${escapeHtml(inst.instanceId)} · ${escapeHtml(inst.accountLogin || '')}</div>
          </div>
          <div style="display:flex;gap:4px;flex-direction:column;align-items:flex-end;">
            <span class="badge ${cls}"><span class="badge-dot"></span>${text}</span>
            ${rtBadge}
            ${clinkBadge}
          </div>
        </div>
        <div class="device-stats">
          <div class="device-stat-item">
            <span class="device-stat-label">巡检次数</span>
            <span class="device-stat-val">${rt.checks || 0} 次</span>
          </div>
          <div class="device-stat-item">
            <span class="device-stat-label">自动开机</span>
            <span class="device-stat-val">${inst.autoStart ? '开启' : '关闭'}</span>
          </div>
        </div>
        <div class="device-schedule-text">巡检 ${inst.checkIntervalSec || 60}s${rt.lastRunAt ? ` · 上次 ${formatTime(rt.lastRunAt)}` : ''} · CLINK ${clinkStats}${cl && cl.nextRetryAt ? ` · ${Math.max(0, Math.round((cl.nextRetryAt - Date.now()) / 1000))}s 后重连` : ''}${inst.lastError ? ` · 异常: ${escapeHtml(inst.lastError)}` : ''}</div>
        <div class="device-actions">
          <button class="btn btn-primary btn-sm" data-act="tl-open" data-id="${inst.id}">进入控制</button>
          <button class="btn btn-secondary btn-sm" data-act="tl-settings" data-id="${inst.id}">保活策略</button>
          <button class="btn btn-secondary btn-sm" data-act="tl-power" data-id="${inst.id}" data-power="start">开机</button>
          <button class="btn btn-secondary btn-sm" data-act="tl-power" data-id="${inst.id}" data-power="restart">重启</button>
          <button class="btn btn-${inst.clinkEnabled ? 'danger' : 'secondary'} btn-sm" data-act="tl-clink" data-id="${inst.id}" data-clink="${inst.clinkEnabled ? 'stop' : 'start'}">${inst.clinkEnabled ? '停协议保活' : '协议保活'}</button>
        </div>
      </div>
    `;
  }

  function renderDevices() {
    const grid = $('deviceGrid');
    const provider = state.deviceProvider || 'all';
    const teleaiHtml = provider === 'all' || provider === 'teleai'
      ? state.teleaiInstances.map(teleaiCard).join('')
      : '';
    const devices = window.CloudChannels.filterDevices(state.devices, provider);
    if (devices.length === 0 && !teleaiHtml) {
      grid.innerHTML = `<div style="grid-column:1/-1;text-align:center;padding:40px;color:var(--text-tertiary);">名下暂无云手机实例，绑定账号后将自动拉取</div>`;
      return;
    }

    grid.innerHTML = teleaiHtml + devices
      .map((d) => {
        const rt = d.runtime || {};
        const isYunzhi = d.provider === 'yunzhi';
        const plat = isYunzhi ? '云智手机' : String(d.platformType) === '2' ? 'T版' : '云版';
        const scheduleDesc =
          d.keepaliveMode === 'cycle'
            ? `循环模式：等待 ${d.waitMinutes || 5} 分钟 → 连接 ${d.connectMinutes || 5} 分钟${rt.nextConnectAt ? ` · 下次连接 ${formatTime(rt.nextConnectAt)}` : ''}`
            : '默认模式：持续长期长连接保活';

        return `
          <div class="device-card">
            <div class="device-top">
              <div>
                <div class="device-title">${escapeHtml(d.phoneName)}</div>
                <div class="device-subtitle">${escapeHtml(d.phoneId)} · ${plat}</div>
              </div>
              <div>${isYunzhi ? `<span class="badge ${d.isExpired ? 'badge-danger' : 'badge-neutral'}">${d.isExpired ? '已到期' : String(d.instanceStatus) === '2' ? '运行中' : '官方状态 ' + escapeHtml(d.instanceStatus || '未知')}</span>` : getStatusBadge(rt)}</div>
            </div>

            <div class="device-stats">
              <div class="device-stat-item">
                <span class="device-stat-label">${isYunzhi ? '所属账号' : '连续在线'}</span>
                <span class="device-stat-val">${isYunzhi ? escapeHtml(d.accountMobile || '—') : rt.state === 'KEEPING' && rt.connectedSince ? formatDuration((Date.now() - rt.connectedSince) / 1000) : '--'}</span>
              </div>
              <div class="device-stat-item">
                <span class="device-stat-label">${isYunzhi ? '到期时间' : '心跳次数'}</span>
                <span class="device-stat-val">${isYunzhi ? escapeHtml(d.expireStr || d.endTime || '以官方状态为准') : `${rt.heartbeatCount || 0} 次`}</span>
              </div>
            </div>

            <div class="device-schedule-text">${isYunzhi ? '支持画面内鼠标和触摸操作；后台保活与电源操作暂不可用' : scheduleDesc}</div>

            <div class="device-actions">
              <button class="btn btn-primary btn-sm" data-act="open-web" data-id="${d.id}" ${isYunzhi && (!d.capabilities?.stream || d.isExpired || d.accountAuthStatus !== 'valid') ? 'disabled' : ''}>进入控制</button>
              ${!isYunzhi ? `
              <button class="btn btn-secondary btn-sm" data-act="keep-settings" data-id="${d.id}">保活策略</button>
              <button class="btn btn-secondary btn-sm" data-act="wakeup" data-id="${d.id}">开机</button>
              <button class="btn btn-secondary btn-sm" data-act="reboot" data-id="${d.id}">重启</button>
              ` : ''}
            </div>
          </div>
        `;
      })
      .join('');
  }

  function renderLogs() {
    const list = $('logsContainer');
    if (state.logs.length === 0) {
      list.innerHTML = `<span style="color:var(--text-tertiary);">暂无运行日志</span>`;
      return;
    }
    list.innerHTML = state.logs
      .map((l) => {
        const color = l.level === 'error' ? 'var(--rose)' : l.level === 'warn' ? 'var(--amber)' : l.level === 'success' ? 'var(--emerald)' : 'var(--text-secondary)';
        return `
          <div style="display:flex;gap:8px;">
            <span style="color:var(--text-tertiary);">${formatTime(l.ts)}</span>
            <span style="color:${color};">${escapeHtml(l.message)}</span>
          </div>
        `;
      })
      .join('');
  }

  function bindDashboardEvents() {
    $('deviceProviderFilter').addEventListener('change', (e) => {
      state.deviceProvider = e.target.value;
      renderDevices();
    });
    $('refreshBtn').addEventListener('click', () => refreshDashboard(false).then(() => showToast('已刷新')));
    $('logoutBtn').addEventListener('click', async () => {
      await api('/api/auth/logout', { method: 'POST' }).catch(() => {});
      state.user = null;
      await switchToAuthView();
    });

    const accountClick = async (e) => {
      const btn = e.target.closest('button[data-act]');
      if (!btn) return;
      const act = btn.getAttribute('data-act');
      const id = btn.getAttribute('data-id');
      if (act === 'sync-acc') {
        btn.disabled = true;
        try {
          const r = await api(`/api/accounts/${id}/sync`, { method: 'POST' });
          showToast(`同步成功，发现 ${r.deviceCount} 台云机`);
          await refreshDashboard(true);
        } catch (err) {
          showToast(err.message);
        } finally {
          btn.disabled = false;
        }
      } else if (act === 'renew-acc') {
        openBinding('yunzhi', state.accounts.find((a) => a.id === id));
      } else if (act === 'smoke-acc' || act === 'checkin-acc') {
        btn.disabled = true;
        try {
          const result = await api(`/api/accounts/${id}/run`, { method: 'POST',
            body: { mode: act === 'smoke-acc' ? 'smoke' : 'full', requestId: crypto.randomUUID() } });
          state.yunzhiJobs.set(result.jobId, { status: 'queued', summary: '任务已提交' });
          showToast('云智任务已提交');
          pollYunzhiJob(result.jobId, state.user.id);
        } catch (err) { showToast(err.message); }
        finally { btn.disabled = false; }
      } else if (act === 'del-acc') {
        const account = state.accounts.find((a) => a.id === id);
        if (!confirm(account?.sharedAccount ? '仅解除此账号与控制中心的关联？原云智账号、凭据和青龙任务将保留。' : '确定解绑该官方账号并停止其托管任务吗？')) return;
        try {
          await api(`/api/accounts/${id}`, { method: 'DELETE' });
          showToast(account?.sharedAccount ? '关联已解除' : '账号已解绑');
          await refreshDashboard(true);
        } catch (err) {
          showToast(err.message);
        }
      }
    };
    $('accountList').addEventListener('click', accountClick);
    $('yunzhiAccountList').addEventListener('click', accountClick);

    $('deviceGrid').addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-act]');
      if (!btn) return;
      const act = btn.getAttribute('data-act');
      const id = btn.getAttribute('data-id');

      if (act === 'open-web') {
        window.open('/control.html?device=' + encodeURIComponent(id), '_blank', 'noopener,noreferrer');
      } else if (act === 'tl-open') {
        await openTeleaiDesktop(id);
      } else if (act === 'tl-settings') {
        openTeleaiSettings(id);
      } else if (act === 'tl-power') {
        const power = btn.getAttribute('data-power') || 'start';
        btn.disabled = true;
        try {
          const r = await api(`/api/teleai/instances/${id}/power`, { method: 'POST', body: { action: power } });
          showToast(power === 'restart' ? '重启指令已下发' : '开机指令已下发');
          await refreshDashboard(true);
        } catch (err) {
          showToast(err.message);
        } finally {
          btn.disabled = false;
        }
      } else if (act === 'tl-clink') {
        const clinkAction = btn.getAttribute('data-clink') || 'start';
        btn.disabled = true;
        try {
          await api(`/api/teleai/instances/${id}/clink`, { method: 'POST', body: { action: clinkAction } });
          showToast(clinkAction === 'stop' ? '已停止协议保活' : '协议保活已启动');
          await refreshDashboard(true);
        } catch (err) {
          showToast(err.message);
        } finally {
          btn.disabled = false;
        }
      } else if (act === 'keep-settings') {
        openKeepaliveSettings(id);
      } else if (act === 'wakeup' || act === 'reboot') {
        btn.disabled = true;
        try {
          const r = await api(`/api/devices/${id}/power`, { method: 'POST', body: { action: act } });
          showToast(r.message || '指令已下发');
          await refreshDashboard(true);
        } catch (err) {
          showToast(err.message);
        } finally {
          btn.disabled = false;
        }
      }
    });

    // Keepalive Settings Form
    for (const id of ['keepaliveModeSelect', 'keepaliveWaitInput', 'keepaliveDurationInput', 'keepaliveEnabledInput']) {
      $(id).addEventListener('input', updateKeepalivePreview);
    }
    $('keepaliveCancelBtn').addEventListener('click', () => $('keepaliveSettingsPanel').classList.add('hidden'));
    $('keepaliveSettingsForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const id = $('keepaliveSettingsPanel').dataset.deviceId;
      const body = {
        keepaliveEnabled: $('keepaliveEnabledInput').checked,
        keepaliveMode: $('keepaliveModeSelect').value,
      };
      if (body.keepaliveMode === 'cycle') {
        body.waitMinutes = Number($('keepaliveWaitInput').value);
        body.connectMinutes = Number($('keepaliveDurationInput').value);
      }
      try {
        await api(`/api/devices/${id}/settings`, { method: 'PATCH', body });
        $('keepaliveSettingsPanel').classList.add('hidden');
        showToast('保活策略已更新');
        await refreshDashboard(true);
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  async function pollYunzhiJob(jobId, ownerId, attempts = 0) {
    if (state.user?.id !== ownerId) return;
    try {
      const result = await api(`/api/yunzhi/jobs/${encodeURIComponent(jobId)}`);
      if (state.user?.id !== ownerId) return;
      state.yunzhiJobs.set(jobId, result.job);
      $('yunzhiJobStatus').textContent = [...state.yunzhiJobs.values()].slice(-5)
        .map((job) => `${({ queued: '等待执行', running: '执行中', success: '完成', failed: '失败' })[job.status] || job.status}：${String(job.summary || '').slice(0, 1000)}`).join('\n');
      if (['success', 'failed'].includes(result.job.status)) { await refreshDashboard(true); return; }
    } catch (err) {
      if (state.user?.id !== ownerId) return;
      $('yunzhiJobStatus').textContent = `任务状态查询暂未完成：${err.message}`;
    }
    if (attempts >= 100) return;
    const timer = setTimeout(() => { state.jobTimers.delete(timer); pollYunzhiJob(jobId, ownerId, attempts + 1); }, 3000);
    state.jobTimers.add(timer);
  }

  function openKeepaliveSettings(id) {
    const dev = state.devices.find((d) => d.id === id);
    if (!dev) return;
    const panel = $('keepaliveSettingsPanel');
    panel.dataset.deviceId = id;
    $('keepaliveSettingsName').textContent = `${dev.phoneName} (${dev.phoneId})`;
    $('keepaliveModeSelect').value = dev.keepaliveMode || 'continuous';
    $('keepaliveWaitInput').value = dev.waitMinutes || 5;
    $('keepaliveDurationInput').value = dev.connectMinutes || 5;
    $('keepaliveEnabledInput').checked = dev.keepaliveEnabled !== false;
    updateKeepalivePreview();
    panel.classList.remove('hidden');
    panel.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  function updateKeepalivePreview() {
    const cycle = $('keepaliveModeSelect').value === 'cycle';
    $('keepaliveCycleFields').classList.toggle('hidden', !cycle);
    const wait = Number($('keepaliveWaitInput').value || 5);
    const duration = Number($('keepaliveDurationInput').value || 5);
    $('keepaliveSchedulePreview').textContent = !$('keepaliveEnabledInput').checked
      ? '已暂停保活：服务不会主动建立长连接。'
      : cycle
      ? `定时策略：保存后等待 ${wait} 分钟 → 建立长连接 ${duration} 分钟 → 断开等待 ${wait} 分钟，循环执行。`
      : '持续策略：7×24 小时保持原生通道长连接；断线自动重连。进入 Web 控制时自动让位防互踢。';
  }

  // ===== 4. Bind Account (SMS / Password) =====
  function clearBinding() {
    state.bindFlow.close();
    state.bindTicket = null;
    state.captchaSessionId = '';
    state.captchaDimensions = null;
    if (state.smsTimer) clearInterval(state.smsTimer);
    state.smsTimer = null;
    state.smsCountdown = 0;
    $('getSmsBtn').disabled = false;
    $('getSmsBtn').textContent = '获取验证码';
    $('submitSmsBtn').disabled = false;
    $('bindSmsCode').value = '';
    $('sliderBox').classList.add('hidden');
    resetSlider();
  }

  function setBindingChannel(provider) {
    clearBinding();
    state.bindFlow.restart(provider, $('bindMobile').value.trim());
    $('bindProvider').value = state.bindFlow.provider;
    const yunzhi = state.bindFlow.provider === 'yunzhi';
    $('bindTitle').textContent = `${state.bindAccountId ? '续期' : '绑定'}官方${yunzhi ? '云智手机' : '移动云手机'}`;
    $('bindMobileLabel').textContent = yunzhi ? '云智账号手机号' : '中国移动手机号';
    $('bindPasswordTab').classList.toggle('hidden', yunzhi);
    $('bindSmsBox').classList.remove('hidden');
    $('bindPwdBox').classList.add('hidden');
    $('pwdPassword').value = '';
    document.querySelectorAll('.bind-tab').forEach((tab) => tab.classList.toggle('active', tab.dataset.mode === 'sms'));
    $('getSmsBtn').disabled = yunzhi && !state.providers.yunzhi;
  }

  function openBinding(provider = 'cmcc', account) {
    state.bindAccountId = account?.id || '';
    $('bindProvider').disabled = Boolean(account);
    $('bindMobile').readOnly = Boolean(account);
    $('bindMobile').value = account?.mobile || '';
    $('bindRemark').value = account?.remark || '';
    setBindingChannel(provider);
    $('bindModal').classList.remove('hidden');
  }

  function closeBinding() {
    clearBinding();
    $('bindModal').classList.add('hidden');
  }

  function bindBindAccountEvents() {
    $('addAccountBtn').addEventListener('click', () => openBinding());
    $('closeBindBtn').addEventListener('click', () => {
      closeBinding();
    });
    $('bindProvider').addEventListener('change', (e) => setBindingChannel(e.target.value));
    $('bindMobile').addEventListener('input', () => setBindingChannel(state.bindFlow.provider));

    document.querySelectorAll('.bind-tab').forEach((tab) => {
      tab.addEventListener('click', () => {
        const mode = tab.dataset.mode;
        if (state.bindFlow.provider === 'yunzhi' && mode === 'pwd') return;
        clearBinding();
        document.querySelectorAll('.bind-tab').forEach((t) => t.classList.toggle('active', t === tab));
        $('bindSmsBox').classList.toggle('hidden', mode !== 'sms');
        $('bindPwdBox').classList.toggle('hidden', mode !== 'pwd');
      });
    });

    $('getSmsBtn').addEventListener('click', loadCaptcha);
    $('reloadCaptchaBtn').addEventListener('click', loadCaptcha);

    $('submitSmsBtn').addEventListener('click', async () => {
      const ticket = state.bindTicket;
      if (!state.bindFlow.isCurrent(ticket) || !state.captchaSessionId) { showToast('请先获取并完成短信安全验证'); return; }
      const provider = ticket.provider;
      const mobile = $('bindMobile').value.trim();
      const code = $('bindSmsCode').value.trim();
      const remark = $('bindRemark').value.trim();
      const captchaSessionId = state.captchaSessionId;
      $('submitSmsBtn').disabled = true;
      try {
        const res = await api(`/api/${provider}/login/sms`, {
          method: 'POST',
          body: { mobile, code, remark, captchaSessionId },
        });
        if (!state.bindFlow.isCurrent(ticket)) return;
        showToast(res.syncWarning || `绑定成功！已同步 ${res.deviceCount} 台云手机`);
        state.deviceProvider = provider;
        $('deviceProviderFilter').value = provider;
        closeBinding();
        await refreshDashboard(true);
      } catch (err) {
        if (state.bindFlow.isCurrent(ticket)) showToast(err.message);
      } finally {
        if (state.bindFlow.isCurrent(ticket)) $('submitSmsBtn').disabled = false;
      }
    });

    $('submitPwdBtn').addEventListener('click', async () => {
      if (state.bindFlow.provider !== 'cmcc') return;
      const ticket = { provider: 'cmcc', generation: state.bindFlow.generation };
      const mobile = $('pwdMobile').value.trim();
      const password = $('pwdPassword').value;
      const remark = $('pwdRemark').value.trim();
      try {
        const res = await api('/api/cmcc/login/password', {
          method: 'POST',
          body: { mobile, password, remark },
        });
        if (!state.bindFlow.isCurrent(ticket)) return;
        showToast(`登录成功！已同步 ${res.deviceCount} 台云机`);
        state.deviceProvider = 'cmcc';
        $('deviceProviderFilter').value = 'cmcc';
        closeBinding();
        $('pwdPassword').value = '';
        await refreshDashboard(true);
      } catch (err) {
        if (state.bindFlow.isCurrent(ticket)) showToast(err.message);
      }
    });
 
    bindTeleaiEvents();
  }

  function bindTeleaiEvents() {
    const modal = $('teleaiModal');
    if (!modal) return;
    $('addTeleaiBtn').addEventListener('click', () => modal.classList.remove('hidden'));
    $('closeTeleaiBtn').addEventListener('click', () => modal.classList.add('hidden'));

    $('submitTeleaiBtn').addEventListener('click', async () => {
      const btn = $('submitTeleaiBtn');
      const loginName = $('teleaiLoginName').value.trim();
      const password = $('teleaiPassword').value;
      const remark = $('teleaiRemark').value.trim();
      if (!loginName || !password) return showToast('请填写星辰账号和密码');
      btn.disabled = true;
      btn.textContent = '登录中（自动过滑块）…';
      try {
        const res = await api('/api/teleai/login', { method: 'POST', body: { loginName, password, remark } });
        showToast(`绑定成功，已同步 ${res.instanceCount} 台星辰电脑`);
        modal.classList.add('hidden');
        $('teleaiPassword').value = '';
        await refreshDashboard(true);
      } catch (err) {
        showToast(err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = '登录并同步实例';
      }
    });

    $('teleaiAccountList').addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-act]');
      if (!btn) return;
      const act = btn.getAttribute('data-act');
      const id = btn.getAttribute('data-id');
      if (act === 'tl-renew') {
        btn.disabled = true;
        btn.textContent = '续期中…';
        try {
          const r = await api(`/api/teleai/accounts/${id}/renew`, { method: 'POST' });
          showToast(r.expiresAt ? `续期成功，有效期至 ${formatDateTime(r.expiresAt)}` : '续期成功');
          await refreshDashboard(true);
        } catch (err) {
          showToast(err.message);
        } finally {
          btn.disabled = false;
          btn.textContent = '一键续期';
        }
      } else if (act === 'tl-sync') {
        btn.disabled = true;
        try {
          const r = await api(`/api/teleai/accounts/${id}/sync`, { method: 'POST' });
          showToast(`同步成功，${r.instanceCount} 台实例`);
          await refreshDashboard(true);
        } catch (err) {
          showToast(err.message);
        } finally {
          btn.disabled = false;
        }
      } else if (act === 'tl-unbind') {
        const name = btn.getAttribute('data-login') || '';
        if (!confirm(`确定解绑星辰账号 ${name} 并停止其巡检保活吗？`)) return;
        try {
          await api(`/api/teleai/accounts/${id}`, { method: 'DELETE' });
          showToast('已解绑');
          await refreshDashboard(true);
        } catch (err) {
          showToast(err.message);
        }
      }
    });

    $('closeTlSettingsBtn').addEventListener('click', () => $('tlSettingsModal').classList.add('hidden'));
    $('tlSettingsCancelBtn').addEventListener('click', () => $('tlSettingsModal').classList.add('hidden'));
    $('tlSettingsSaveBtn').addEventListener('click', async () => {
      const id = $('tlSettingsModal').dataset.instanceId;
      try {
        await api(`/api/teleai/instances/${id}/settings`, {
          method: 'PATCH',
          body: {
            keepaliveEnabled: $('tlKeepaliveInput').checked,
            autoStart: $('tlAutoStartInput').checked,
            checkIntervalSec: Number($('tlIntervalInput').value) || 60,
            clinkEnabled: $('tlClinkInput').checked,
            moveSec: Number($('tlMoveSecInput').value) || 30,
            kickWaitSec: Number($('tlKickWaitInput').value),
          },
        });
        $('tlSettingsModal').classList.add('hidden');
        showToast('保活策略已更新');
        await refreshDashboard(true);
      } catch (err) {
        showToast(err.message);
      }
    });

    $('tlDesktopCloseBtn').addEventListener('click', () => {
      $('tlDesktopFrame').src = 'about:blank';
      $('tlDesktopModal').classList.add('hidden');
    });
    $('tlDesktopReloadBtn').addEventListener('click', () => openTeleaiDesktop($('tlDesktopModal').dataset.instanceId));
    $('tlDesktopNewTabBtn').addEventListener('click', () => {
      const url = $('tlDesktopModal').dataset.connectUrl;
      if (url) window.open(url, '_blank', 'noopener,noreferrer');
    });
  }

  function openTeleaiSettings(id) {
    const inst = state.teleaiInstances.find((i) => i.id === id);
    if (!inst) return;
    const modal = $('tlSettingsModal');
    modal.dataset.instanceId = id;
    $('tlSettingsName').textContent = `${inst.name} (${inst.instanceId})`;
    $('tlKeepaliveInput').checked = inst.keepaliveEnabled !== false;
    $('tlAutoStartInput').checked = inst.autoStart !== false;
    $('tlIntervalInput').value = inst.checkIntervalSec || 60;
    $('tlClinkInput').checked = Boolean(inst.clinkEnabled);
    $('tlMoveSecInput').value = inst.moveSec || 30;
    $('tlKickWaitInput').value = inst.kickWaitSec === undefined ? 1800 : inst.kickWaitSec;
    modal.classList.remove('hidden');
  }

  async function openTeleaiDesktop(id) {
    const inst = state.teleaiInstances.find((i) => i.id === id);
    const modal = $('tlDesktopModal');
    modal.dataset.instanceId = id;
    $('tlDesktopName').textContent = inst ? inst.name : '星辰电脑';
    $('tlDesktopStatus').textContent = '正在获取入口…';
    modal.classList.remove('hidden');
    try {
      const r = await api(`/api/teleai/instances/${id}/desktop`);
      modal.dataset.connectUrl = r.connectURL || '';
      $('tlDesktopFrame').src = r.connectURL || 'about:blank';
      $('tlDesktopStatus').textContent = '已连接官方控制台';
    } catch (err) {
      $('tlDesktopStatus').textContent = err.message;
      showToast(err.message);
    }
  }

  async function loadCaptcha() {
    const provider = state.bindFlow.provider;
    const mobile = $('bindMobile').value.replace(/\s+/g, '');
    if (!/^1\d{10}$/.test(mobile)) {
      showToast('请输入有效的 11 位手机号');
      return;
    }
    clearBinding();
    const ticket = state.bindFlow.restart(provider, mobile);
    state.bindTicket = ticket;
    $('getSmsBtn').disabled = true;
    try {
      const res = await api(`/api/${provider}/captcha/get`, { method: 'POST',
        body: { mobile, ...(provider === 'yunzhi' && state.bindAccountId ? { accountId: state.bindAccountId } : {}) } });
      if (!state.bindFlow.isCurrent(ticket)) return;
      state.captchaSessionId = res.captchaSessionId;
      const image = (value) => /^(data:image\/(png|jpeg|webp);base64,|https:\/\/)/.test(value || '') ? value : 'data:image/png;base64,' + value;
      $('puzzleBg').src = image(res.originalImageBase64);
      $('puzzleJigsaw').src = image(res.jigsawImageBase64);
      state.captchaDimensions = provider === 'yunzhi' ? {
        width: Number(res.backgroundWidth) || 300, height: Number(res.backgroundHeight) || 180,
        pieceWidth: Number(res.sliderWidth) || 62, pieceHeight: Number(res.sliderHeight) || 62,
        y: Number(res.sliderY) || 0,
      } : null;
      const stage = $('puzzleBg').parentElement;
      stage.classList.toggle('yunzhi-captcha', provider === 'yunzhi');
      stage.style.height = '';
      for (const key of ['width', 'height', 'top']) $('puzzleJigsaw').style[key] = '';
      $('sliderBox').classList.remove('hidden');
      if (state.captchaDimensions) renderCloudCaptcha();
    } catch (err) {
      if (state.bindFlow.isCurrent(ticket)) showToast(err.message);
    } finally {
      if (state.bindFlow.isCurrent(ticket)) $('getSmsBtn').disabled = false;
    }
  }

  function resetSlider() {
    state.captchaFraction = 0;
    $('sliderHandle').style.left = '0px';
    $('puzzleJigsaw').style.left = '0px';
    $('sliderFill').style.width = '0px';
    $('sliderHint').textContent = '按住滑块向右拖动';
  }

  function renderCloudCaptcha() {
    const stage = $('puzzleBg').parentElement;
    const track = $('sliderTrack');
    const handle = $('sliderHandle');
    const offset = state.captchaFraction * Math.max(1, track.clientWidth - handle.offsetWidth);
    const geometry = window.CloudChannels.captchaGeometry(state.captchaDimensions, stage.clientWidth,
      track.clientWidth, handle.offsetWidth, offset);
    stage.style.height = `${geometry.height}px`;
    Object.assign($('puzzleJigsaw').style, { width: `${geometry.pieceWidth}px`, height: `${geometry.pieceHeight}px`,
      left: `${geometry.left}px`, top: `${geometry.top}px` });
    handle.style.left = `${offset}px`;
    $('sliderFill').style.width = `${offset + handle.offsetWidth / 2}px`;
    return geometry;
  }

  function bindSliderEvents() {
    const handle = $('sliderHandle');
    const jigsaw = $('puzzleJigsaw');
    const fill = $('sliderFill');
    let dragging = false;
    let startX = 0;
    let currentLeft = 0;
    let dragTicket = null;

    handle.addEventListener('pointerdown', (e) => {
      if (!state.captchaSessionId) return;
      e.preventDefault();
      handle.setPointerCapture(e.pointerId);
      dragging = true;
      startX = e.clientX;
      currentLeft = 0;
      dragTicket = state.bindTicket;
    });

    handle.addEventListener('pointermove', (e) => {
      if (!dragging) return;
      e.preventDefault();
      if (!state.bindFlow.isCurrent(dragTicket)) { dragging = false; return; }
      const maxOffset = Math.max(1, $('sliderTrack').clientWidth - handle.offsetWidth);
      const dx = Math.max(0, Math.min(maxOffset, e.clientX - startX));
      currentLeft = dx;
      handle.style.left = `${dx}px`;
      const c = state.captchaDimensions;
      state.captchaFraction = dx / maxOffset;
      if (c) renderCloudCaptcha();
      else jigsaw.style.left = `${dx}px`;
      fill.style.width = `${dx + 22}px`;
    });

    const finish = async () => {
      if (!dragging) return;
      dragging = false;
      const ticket = dragTicket;
      const captchaSessionId = state.captchaSessionId;
      if (!state.bindFlow.isCurrent(ticket)) return;
      if (currentLeft < 5) {
        resetSlider();
        return;
      }
      $('sliderHint').textContent = '正在验证…';
      try {
        const maxOffset = Math.max(1, $('sliderTrack').clientWidth - handle.offsetWidth);
        const moveX = state.captchaDimensions ? renderCloudCaptcha().moveX : currentLeft;
        await api(`/api/${ticket.provider}/captcha/send-sms`, {
          method: 'POST',
          body: { captchaSessionId, moveX: Math.round(moveX) },
        });
        if (!state.bindFlow.isCurrent(ticket)) return;
        showToast('短信验证码已下发');
        $('sliderBox').classList.add('hidden');
        startCountdown();
        $('bindSmsCode').focus();
      } catch (err) {
        if (!state.bindFlow.isCurrent(ticket)) return;
        showToast(err.message);
        await loadCaptcha();
      }
    };

    handle.addEventListener('pointerup', finish);
    handle.addEventListener('pointercancel', () => { dragging = false; resetSlider(); });
    window.addEventListener('resize', () => {
      if (state.captchaDimensions && !$('sliderBox').classList.contains('hidden')) renderCloudCaptcha();
    });
  }

  function startCountdown() {
    state.smsCountdown = 60;
    const btn = $('getSmsBtn');
    btn.disabled = true;
    btn.textContent = `${state.smsCountdown}s`;
    if (state.smsTimer) clearInterval(state.smsTimer);
    state.smsTimer = setInterval(() => {
      state.smsCountdown -= 1;
      if (state.smsCountdown <= 0) {
        clearInterval(state.smsTimer);
        btn.disabled = false;
        btn.textContent = '获取验证码';
      } else {
        btn.textContent = `${state.smsCountdown}s`;
      }
    }, 1000);
  }

  // ===== 5. Admin Management =====
  function bindAdminEvents() {
    $('adminBtn').addEventListener('click', async () => {
      $('adminModal').classList.remove('hidden');
      await loadAdminUsers();
    });
    $('closeAdminBtn').addEventListener('click', () => $('adminModal').classList.add('hidden'));

    $('createAdminUserBtn').addEventListener('click', async () => {
      const username = $('newAdminUser').value.trim();
      const password = $('newAdminPass').value;
      const maxAccounts = Number($('newAdminQuota').value || 10);
      try {
        await api('/api/admin/users', { method: 'POST', body: { username, password, maxAccounts } });
        $('newAdminUser').value = '';
        $('newAdminPass').value = '';
        showToast('用户创建成功');
        await loadAdminUsers();
      } catch (err) {
        showToast(err.message);
      }
    });

    $('adminUsersTbody').addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-uact]');
      if (!btn) return;
      const act = btn.dataset.uact;
      const uid = btn.dataset.uid;
      if (act === 'del-user') {
        if (!confirm('确定删除该用户吗？名下账号与云机保活将同步清理。')) return;
        try {
          await api(`/api/admin/users/${uid}`, { method: 'DELETE' });
          showToast('用户已删除');
          await loadAdminUsers();
        } catch (err) {
          showToast(err.message);
        }
      }
    });
  }

  async function loadAdminUsers() {
    try {
      const res = await api('/api/admin/users');
      $('adminUsersTbody').innerHTML = (res.users || [])
        .map((u) => {
          const isSelf = u.id === state.user.id;
          return `
            <tr style="border-bottom:1px solid var(--border-subtle);">
              <td style="padding:8px 6px;">${escapeHtml(u.username)}</td>
              <td style="padding:8px 6px;">${u.role === 'admin' ? '管理员' : '租户'}</td>
              <td style="padding:8px 6px;">${u.accountCount} / ${u.maxAccounts}</td>
              <td style="padding:8px 6px;">
                ${isSelf ? '<span style="color:var(--text-tertiary);">当前账号</span>' : `<button class="btn btn-danger btn-sm" data-uact="del-user" data-uid="${u.id}">删除</button>`}
              </td>
            </tr>
          `;
        })
        .join('');
    } catch (err) {
      showToast(err.message);
    }
  }

  // ===== 6. Web Remote Control Viewer =====
  async function openWebViewer(deviceId) {
    await destroyActivePlayers(true);
    state.activeDeviceId = deviceId;
    const dev = state.devices.find((d) => d.id === deviceId);
    setViewerProvider(dev?.provider === 'yunzhi');
    $('viewerPhoneName').textContent = dev ? dev.phoneName : '移动云手机';
    $('viewerRtt').textContent = '-- ms';
    $('viewerOverlay').classList.remove('hidden');
    $('viewerStatusText').textContent = '正在准备串流环境…';
    $('viewerModal').classList.remove('hidden');

    await connectViewerStream();
  }

  function stopViewerHeartbeat() {
    if (state.leaseHeartbeatTimer) clearInterval(state.leaseHeartbeatTimer);
    state.leaseHeartbeatTimer = null;
  }

  function startViewerHeartbeat(deviceId, generation) {
    stopViewerHeartbeat();
    state.leaseHeartbeatTimer = setInterval(() => {
      if (generation !== state.viewerGeneration || deviceId !== state.activeDeviceId) return;
      api(`/api/devices/${deviceId}/stream/heartbeat`, { method: 'POST' }).catch((err) => {
        if (err.status >= 400 && err.status < 500) stopViewerHeartbeat();
      });
    }, 20000);
  }

  function releaseFailedCloudViewer() {
    stopViewerHeartbeat();
    if (state.activeDeviceId) api(`/api/devices/${state.activeDeviceId}/stream/close`, { method: 'POST' }).catch(() => {});
  }

  async function connectViewerStream() {
    if (!state.activeDeviceId) return;
    const deviceId = state.activeDeviceId;
    const generation = ++state.viewerGeneration;
    stopViewerHeartbeat();
    try {
      const res = await api(`/api/devices/${deviceId}/stream/open`, { method: 'POST', body: {} });
      if (generation !== state.viewerGeneration || deviceId !== state.activeDeviceId) return;
      await refreshDashboard(true);
      if (generation !== state.viewerGeneration || deviceId !== state.activeDeviceId) return;
      if (res.stream.provider !== 'yunzhi') startViewerHeartbeat(deviceId, generation);
      state.activePlatformType = String(res.stream.platformType || '1');
      const isYunzhi = res.stream.provider === 'yunzhi';
      setViewerProvider(isYunzhi);
      if (isYunzhi) {
        startYunzhiViewer(res.stream);
      } else if (state.activePlatformType === '2') {
        startTCloudViewer(res.stream);
      } else {
        startYunViewer(res.stream);
      }
    } catch (err) {
      if (generation !== state.viewerGeneration || deviceId !== state.activeDeviceId) return;
      stopViewerHeartbeat();
      $('viewerStatusText').textContent = `连接失败：${err.message}`;
      showToast(err.message);
    }
  }

  function startYunzhiViewer(stream) {
    const mount = $('player');
    mount.innerHTML = '';
    const player = new window.YunzhiWebPlayer(mount, stream, {
      onState: (text) => { $('viewerOverlay').classList.remove('hidden'); $('viewerStatusText').textContent = text; },
      onPlaying: () => { $('viewerOverlay').classList.add('hidden'); player.setMuted(state.viewerMuted); },
      onError: (text) => { releaseFailedCloudViewer(); $('viewerOverlay').classList.remove('hidden'); $('viewerStatusText').textContent = text; },
      onDisconnected: releaseFailedCloudViewer,
    });
    state.yunzhiPlayer = player;
    player.start();
  }

  function setViewerProvider(isYunzhi) {
    for (const id of ['navTaskBtn', 'navHomeBtn', 'navBackBtn', 'viewerRtt']) $(id).classList.toggle('hidden', isYunzhi);
    $('navHomeBtn').parentElement.classList.toggle('hidden', isYunzhi);
  }

  function startYunViewer(stream) {
    if (!window.CloudPhoneClient) {
      $('viewerStatusText').textContent = '本地播放器组件未就绪';
      return;
    }
    const mount = $('player');
    mount.innerHTML = '';
    const player = window.CloudPhoneClient.createCloudPhonePlayer('player', {
      noOperationThreshold: 0,
      sessionKeepingTime: 60,
      disRotate: true,
      mode: 'screen_share',
      role: 'master',
      userToken: stream.hwToken || '',
      instanceId: stream.phoneId,
      enableAllAspect: true,
      enableClipboard: true,
      enableWheel2Touch: true,
      disableAutoReconnect: false,
    });
    state.yunPlayer = player;

    player.on('statechange', (ev) => {
      if (ev?.state === 'playing') {
        $('viewerOverlay').classList.add('hidden');
        player.setMuted(state.viewerMuted);
      }
    });
    player.on('qos', (q) => {
      if (q?.rtt != null) $('viewerRtt').textContent = `${q.rtt} ms`;
    });
    player.on('exit', () => {
      $('viewerOverlay').classList.remove('hidden');
      $('viewerStatusText').textContent = '串流已断开，可点击重连';
    });

    player.disableBeforeunload(true);
    player.open({
      boxid: stream.boxid,
      token: stream.token,
      roomsession: stream.roomsession || '',
      signaling_url: stream.signaling_url,
      uuid: stream.uuid,
      sessionid: stream.sessionid || stream.token,
      platform: stream.platform || 'cloudphone',
      env: stream.env || 'phone580',
      profile: 2,
      muted: state.viewerMuted,
    });
  }

  function startTCloudViewer(stream) {
    const mount = $('player');
    const tp = new window.TCloudWebPlayer(mount, stream, {
      onState: (txt) => { $('viewerStatusText').textContent = txt; },
      onPlaying: () => {
        $('viewerOverlay').classList.add('hidden');
        tp.setMuted(state.viewerMuted);
      },
      onRtt: (rtt) => { $('viewerRtt').textContent = `${rtt} ms`; },
      onError: (msg) => {
        $('viewerOverlay').classList.remove('hidden');
        $('viewerStatusText').textContent = msg;
      },
    });
    state.tPlayer = tp;
    tp.start();
  }

  async function destroyActivePlayers(releaseServerLease = true) {
    state.viewerGeneration++;
    if (state.leaseHeartbeatTimer) {
      clearInterval(state.leaseHeartbeatTimer);
      state.leaseHeartbeatTimer = null;
    }
    if (state.yunPlayer) {
      try { state.yunPlayer.close(); state.yunPlayer.destroy(); } catch (_) {}
      state.yunPlayer = null;
    }
    if (state.tPlayer) {
      try { state.tPlayer.destroy(); } catch (_) {}
      state.tPlayer = null;
    }
    if (state.yunzhiPlayer) {
      state.yunzhiPlayer.destroy();
      state.yunzhiPlayer = null;
    }
    $('player').innerHTML = '';

    const prevId = state.activeDeviceId;
    if (releaseServerLease && prevId) {
      state.activeDeviceId = '';
      await api(`/api/devices/${prevId}/stream/close`, { method: 'POST' }).catch(() => {});
      await refreshDashboard(true);
    }
  }

  function bindViewerEvents() {
    $('viewerCloseBtn').addEventListener('click', async () => {
      $('viewerModal').classList.add('hidden');
      await destroyActivePlayers(true);
      showToast('已退出控制');
      if (location.pathname === '/control.html') { window.close(); location.replace('/'); }
    });

    $('viewerReconnectBtn').addEventListener('click', async () => {
      const id = state.activeDeviceId;
      if (!id) return;
      await destroyActivePlayers(false);
      state.activeDeviceId = id;
      await connectViewerStream();
    });

    $('viewerMuteBtn').addEventListener('click', () => {
      state.viewerMuted = !state.viewerMuted;
      $('viewerMuteBtn').textContent = state.viewerMuted ? '静音' : '声音开';
      if (state.yunPlayer) state.yunPlayer.setMuted(state.viewerMuted);
      if (state.tPlayer) state.tPlayer.setMuted(state.viewerMuted);
      if (state.yunzhiPlayer) state.yunzhiPlayer.setMuted(state.viewerMuted);
    });

    $('navTaskBtn').addEventListener('click', () => {
      if (state.yunPlayer) state.yunPlayer.emitAppSwitch();
      if (state.tPlayer) state.tPlayer.emitAppSwitch();
    });

    $('navHomeBtn').addEventListener('click', () => {
      if (state.yunPlayer) state.yunPlayer.emitHome();
      if (state.tPlayer) state.tPlayer.emitHome();
    });

    $('navBackBtn').addEventListener('click', () => {
      if (state.yunPlayer) state.yunPlayer.emitBack();
      if (state.tPlayer) state.tPlayer.emitBack();
    });
  }

  window.addEventListener('pagehide', () => {
    state.viewerGeneration++;
    if (state.yunzhiPlayer) state.yunzhiPlayer.destroy();
    if (state.activeDeviceId) navigator.sendBeacon(`/api/devices/${state.activeDeviceId}/stream/close`, '{}');
  });
  document.addEventListener('DOMContentLoaded', init);
})();
