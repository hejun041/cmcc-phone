'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function providerCapabilities(provider, value = {}) {
  if (provider !== 'yunzhi') {
    return { stream: true, touch: true, power: ['wakeup', 'reboot'], screenshot: true, backgroundKeepalive: true };
  }
  return {
    stream: value.stream === true,
    touch: value.touch === true,
    power: Array.isArray(value.power) ? value.power.filter((a) => ['wakeup', 'reboot', 'shutdown'].includes(a)) : [],
    screenshot: value.screenshot === true,
    backgroundKeepalive: false,
  };
}

class MultiTenantStore {
  constructor(dataDir) {
    this.dataDir = dataDir;
    fs.mkdirSync(this.dataDir, { recursive: true });
    this.keyPath = path.join(this.dataDir, '.master.key');
    this.dbPath = path.join(this.dataDir, 'store.json');
    // installationId 单独落一个文件：即使 store.json 被旧版本代码重写（旧版本没有该字段），
    // 云智控制桥（青龙侧）按 installationId:ownerId 绑定账号，丢了就会全部 ACCOUNT_NOT_FOUND
    this.installationIdPath = path.join(this.dataDir, 'installation.id');
    this.masterKey = this._loadOrCreateMasterKey();
    this.state = {
      installationId: this._readInstallationId() || crypto.randomUUID(),
      users: [],
      sessions: [],
      accounts: [],
      devices: [],
      teleaiAccounts: [],
      teleaiInstances: [],
    };
    this.logsByUser = new Map(); // userId -> array of log items (ring buffer)
    this._load();
  }

  get installationId() {
    return this.state.installationId;
  }

  _readInstallationId() {
    try {
      if (!fs.existsSync(this.installationIdPath)) return '';
      const id = fs.readFileSync(this.installationIdPath, 'utf8').trim();
      return /^[A-Za-z0-9-]{8,64}$/.test(id) ? id : '';
    } catch (_) {
      return '';
    }
  }

  _writeInstallationId(id) {
    try {
      if (this._readInstallationId() === id) return;
      fs.writeFileSync(this.installationIdPath, id + '\n', { mode: 0o600 });
    } catch (_) {
      /* 只读卷等场景忽略 */
    }
  }

  _loadOrCreateMasterKey() {
    if (fs.existsSync(this.keyPath)) {
      const hex = fs.readFileSync(this.keyPath, 'utf8').trim();
      if (hex.length === 64) {
        return Buffer.from(hex, 'hex');
      }
    }
    const key = crypto.randomBytes(32);
    fs.writeFileSync(this.keyPath, key.toString('hex'), { mode: 0o600 });
    return key;
  }

  encryptSecret(plain) {
    if (!plain) return '';
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.masterKey, iv);
    const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${tag.toString('hex')}:${enc.toString('hex')}`;
  }

  decryptSecret(packed) {
    if (!packed) return '';
    const parts = String(packed).split(':');
    if (parts.length !== 3) return '';
    const [ivHex, tagHex, encHex] = parts;
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.masterKey, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    return Buffer.concat([decipher.update(Buffer.from(encHex, 'hex')), decipher.final()]).toString('utf8');
  }

  _load() {
    if (!fs.existsSync(this.dbPath)) {
      this._save();
      return;
    }
    try {
      const raw = JSON.parse(fs.readFileSync(this.dbPath, 'utf8'));
      const fileId = this._readInstallationId();
      this.state.installationId = fileId || raw.installationId || this.state.installationId;
      this._writeInstallationId(this.state.installationId);
      this.state.users = Array.isArray(raw.users) ? raw.users : [];
      this.state.sessions = Array.isArray(raw.sessions) ? raw.sessions : [];
      this.state.accounts = Array.isArray(raw.accounts) ? raw.accounts : [];
      this.state.devices = Array.isArray(raw.devices) ? raw.devices : [];
      for (const account of this.state.accounts) account.provider = account.provider || 'cmcc';
      for (const device of this.state.devices) {
        device.provider = device.provider || this.state.accounts.find((a) => a.id === device.accountId)?.provider || 'cmcc';
      }
      this.state.teleaiAccounts = Array.isArray(raw.teleaiAccounts) ? raw.teleaiAccounts : [];
      this.state.teleaiInstances = Array.isArray(raw.teleaiInstances) ? raw.teleaiInstances : [];
      if (!raw.installationId) this._save();
    } catch (err) {
      const backup = `${this.dbPath}.corrupt.${Date.now()}`;
      fs.copyFileSync(this.dbPath, backup);
      this._save();
    }
  }

  _save() {
    this._writeInstallationId(this.state.installationId);
    const tmp = `${this.dbPath}.tmp.${process.pid}`;
    fs.writeFileSync(tmp, JSON.stringify(this.state, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.dbPath);
  }

  static hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    const hash = crypto.pbkdf2Sync(String(password), salt, 120000, 32, 'sha256').toString('hex');
    return `${salt}:${hash}`;
  }

  static verifyPassword(password, stored) {
    const [salt, expectedHex] = String(stored || '').split(':');
    if (!salt || !expectedHex) return false;
    const actualHex = crypto.pbkdf2Sync(String(password), salt, 120000, 32, 'sha256').toString('hex');
    return crypto.timingSafeEqual(Buffer.from(actualHex, 'hex'), Buffer.from(expectedHex, 'hex'));
  }

  // ===== User & Auth Isolation =====

  hasAnyUser() {
    return this.state.users.length > 0;
  }

  registerUser({ username, password, role, maxAccounts }) {
    const cleanName = String(username || '').trim();
    if (!/^[a-zA-Z0-9_\u4e00-\u9fa5.-]{2,32}$/.test(cleanName)) {
      throw new Error('用户名需为 2~32 位字母、数字、中文或下划线');
    }
    if (!password || String(password).length < 6) {
      throw new Error('密码长度至少为 6 位');
    }
    const exists = this.state.users.find((u) => u.username.toLowerCase() === cleanName.toLowerCase());
    if (exists) {
      throw new Error('该用户名已被注册');
    }
    const isFirst = this.state.users.length === 0;
    const user = {
      id: crypto.randomUUID(),
      username: cleanName,
      passwordHash: MultiTenantStore.hashPassword(password),
      role: role || (isFirst ? 'admin' : 'user'),
      disabled: false,
      maxAccounts: Number.isFinite(Number(maxAccounts)) ? Number(maxAccounts) : (isFirst ? 100 : 10),
      createdAt: Date.now(),
      lastLoginAt: null,
    };
    this.state.users.push(user);
    this._save();
    return this.sanitizeUser(user);
  }

  authenticateUser(username, password) {
    const cleanName = String(username || '').trim().toLowerCase();
    const user = this.state.users.find((u) => u.username.toLowerCase() === cleanName);
    if (!user || !MultiTenantStore.verifyPassword(password, user.passwordHash)) {
      throw new Error('用户名或密码错误');
    }
    if (user.disabled) {
      throw new Error('当前账户已被管理员禁用');
    }
    user.lastLoginAt = Date.now();
    const token = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    // Prune expired sessions
    this.state.sessions = this.state.sessions.filter((s) => s.expiresAt > now);
    this.state.sessions.push({
      tokenHash: crypto.createHash('sha256').update(token).digest('hex'),
      userId: user.id,
      createdAt: now,
      expiresAt: now + 30 * 24 * 3600 * 1000, // 30 days
    });
    this._save();
    return { token, user: this.sanitizeUser(user) };
  }

  getUserBySessionToken(token) {
    if (!token) return null;
    const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex');
    const now = Date.now();
    const session = this.state.sessions.find((s) => s.tokenHash === tokenHash && s.expiresAt > now);
    if (!session) return null;
    const user = this.state.users.find((u) => u.id === session.userId && !u.disabled);
    return user ? this.sanitizeUser(user) : null;
  }

  revokeSession(token) {
    if (!token) return;
    const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex');
    this.state.sessions = this.state.sessions.filter((s) => s.tokenHash !== tokenHash);
    this._save();
  }

  sanitizeUser(u) {
    return {
      id: u.id,
      username: u.username,
      role: u.role,
      disabled: Boolean(u.disabled),
      maxAccounts: u.maxAccounts,
      createdAt: u.createdAt,
      lastLoginAt: u.lastLoginAt,
    };
  }

  listUsersForAdmin() {
    return this.state.users.map((u) => {
      const accCount = this.state.accounts.filter((a) => a.ownerId === u.id).length;
      const devCount = this.state.devices.filter((d) => d.ownerId === u.id).length;
      return {
        ...this.sanitizeUser(u),
        accountCount: accCount,
        deviceCount: devCount,
      };
    });
  }

  updateUserByAdmin(targetUserId, patch = {}) {
    const user = this.state.users.find((u) => u.id === targetUserId);
    if (!user) throw new Error('目标用户不存在');
    if (patch.disabled !== undefined) {
      user.disabled = Boolean(patch.disabled);
      if (user.disabled) {
        this.state.sessions = this.state.sessions.filter((s) => s.userId !== user.id);
      }
    }
    if (patch.maxAccounts !== undefined) {
      const m = Number(patch.maxAccounts);
      if (Number.isFinite(m) && m >= 1 && m <= 500) {
        user.maxAccounts = Math.floor(m);
      }
    }
    if (patch.newPassword) {
      if (String(patch.newPassword).length < 6) {
        throw new Error('新密码长度至少 6 位');
      }
      user.passwordHash = MultiTenantStore.hashPassword(patch.newPassword);
      this.state.sessions = this.state.sessions.filter((s) => s.userId !== user.id);
    }
    this._save();
    return this.sanitizeUser(user);
  }

  deleteUserByAdmin(targetUserId) {
    const idx = this.state.users.findIndex((u) => u.id === targetUserId);
    if (idx === -1) throw new Error('目标用户不存在');
    const removedAccountIds = this.state.accounts
      .filter((a) => a.ownerId === targetUserId)
      .map((a) => a.id);
    const removedDeviceIds = this.state.devices
      .filter((d) => d.ownerId === targetUserId)
      .map((d) => d.id);
    this.state.users.splice(idx, 1);
    this.state.sessions = this.state.sessions.filter((s) => s.userId !== targetUserId);
    this.state.accounts = this.state.accounts.filter((a) => a.ownerId !== targetUserId);
    this.state.devices = this.state.devices.filter((d) => d.ownerId !== targetUserId);
    this.logsByUser.delete(targetUserId);
    this._save();
    return { removedAccountIds, removedDeviceIds };
  }

  // ===== CMCC Accounts (Strictly Scoped to ownerId) =====

  upsertCmccAccount(ownerId, { mobile, remark, token, hwToken, cmccUserId, province, fingerprint }) {
    const user = this.state.users.find((u) => u.id === ownerId);
    if (!user) throw new Error('所属平台用户不存在');

    let acc = this.state.accounts.find((a) => a.ownerId === ownerId && a.mobile === mobile && (a.provider || 'cmcc') === 'cmcc');
    if (!acc) {
      const currentCount = this.state.accounts.filter((a) => a.ownerId === ownerId).length;
      if (currentCount >= user.maxAccounts) {
        throw new Error(`已达到当前用户可绑定移动账号上限 (${user.maxAccounts} 个)`);
      }
      acc = {
        id: crypto.randomUUID(),
        provider: 'cmcc',
        ownerId,
        mobile,
        remark: remark || '',
        tokenEnc: this.encryptSecret(token),
        hwTokenEnc: this.encryptSecret(hwToken || ''),
        cmccUserId: cmccUserId || '',
        province: province || '',
        fingerprint,
        authStatus: 'valid',
        lastCheckAt: Date.now(),
        createdAt: Date.now(),
      };
      this.state.accounts.push(acc);
    } else {
      if (remark !== undefined && remark !== '') acc.remark = remark;
      acc.tokenEnc = this.encryptSecret(token);
      if (hwToken) acc.hwTokenEnc = this.encryptSecret(hwToken);
      if (cmccUserId) acc.cmccUserId = cmccUserId;
      if (province) acc.province = province;
      if (fingerprint) acc.fingerprint = fingerprint;
      acc.authStatus = 'valid';
      acc.lastCheckAt = Date.now();
    }
    this._save();
    return this.hydrateAccount(acc);
  }

  importLegacyYunzhiAccounts(ownerId, metadata) {
    const user = this.state.users.find((u) => u.id === ownerId && !u.disabled && u.role === 'admin');
    const expectedOwner = `${this.installationId}:${ownerId}`;
    if (!user || !metadata || typeof metadata !== 'object' || Array.isArray(metadata) || metadata.owner !== expectedOwner) {
      throw new Error('原账号迁移归属不匹配');
    }
    const records = metadata.records;
    if (!Array.isArray(records)) throw new Error('原账号迁移记录无效');
    const previous = this.state.accounts;
    const next = previous.map((account) => ({ ...account }));
    const seen = new Set();
    for (const record of records) {
      const { remoteAccountId, displayName = '', mobile = '' } = record || {};
      if (record?.sharedAccount !== true || !/^[A-Za-z0-9_-]{1,160}$/.test(remoteAccountId || '') ||
          (mobile !== '' && !/^1[3-9]\d{9}$/.test(mobile)) || seen.has(remoteAccountId)) throw new Error('原账号迁移信息无效');
      seen.add(remoteAccountId);
      let account = next.find((a) => a.ownerId === ownerId && a.provider === 'yunzhi' && a.remoteAccountId === remoteAccountId);
      if (account?.pendingDelete) throw new Error('账号正在解绑，不能迁移');
      if (account && account.sharedAccount !== true) throw new Error('原账号引用已有非共享账号，拒绝迁移');
      if (!account) {
        if (mobile && next.some((a) => a.ownerId === ownerId && a.provider === 'yunzhi' && a.mobile === mobile)) throw new Error('迁移账号与已有绑定冲突');
        account = { id: crypto.randomUUID(), ownerId, provider: 'yunzhi', createdAt: Date.now() };
        next.push(account);
      }
      Object.assign(account, { remoteAccountId, mobile, displayName: String(displayName).slice(0, 80),
        remark: account.remark || String(displayName).slice(0, 80), sharedAccount: true,
        tokenEnc: '', hwTokenEnc: '', tokenExpiresAt: record.tokenExpiresAt ?? null,
        capabilities: providerCapabilities('yunzhi', record.capabilities || account.capabilities),
        authStatus: record.enabled === false ? 'disabled' : account.authStatus || 'valid', lastCheckAt: Date.now() });
    }
    if (next.filter((a) => a.ownerId === ownerId).length > user.maxAccounts) throw new Error('迁移后账号数量超过管理员配额上限');
    this.state.accounts = next;
    try { this._save(); } catch (err) { this.state.accounts = previous; throw err; }
    return this.listAccountsByOwner(ownerId).filter((a) => a.provider === 'yunzhi');
  }

  upsertYunzhiAccount(ownerId, { mobile, remark = '', remoteAccountId, tokenExpiresAt = null, capabilities = {}, authStatus = 'valid', sharedAccount = false, displayName = '' }) {
    const user = this.state.users.find((u) => u.id === ownerId && !u.disabled);
    if (!user) throw new Error('所属平台用户不存在或已停用');
    const byReference = this.state.accounts.find((a) => a.ownerId === ownerId && a.provider === 'yunzhi' && a.remoteAccountId === remoteAccountId);
    if ((!/^1[3-9]\d{9}$/.test(String(mobile || '')) && !(mobile === '' && byReference?.sharedAccount)) || !remoteAccountId || String(remoteAccountId).length > 160) {
      throw new Error('云智账号信息无效');
    }
    let acc = byReference || this.state.accounts.find((a) => a.ownerId === ownerId && a.mobile === mobile && a.provider === 'yunzhi');
    if (acc?.pendingDelete) throw new Error('云智账号正在解绑，请先完成解绑');
    const previous = acc ? { ...acc } : null;
    if (!acc) {
      if (this.state.accounts.filter((a) => a.ownerId === ownerId).length >= user.maxAccounts) {
        throw new Error(`已达到当前用户可绑定官方账号上限 (${user.maxAccounts} 个)`);
      }
      acc = { id: crypto.randomUUID(), ownerId, mobile, provider: 'yunzhi', createdAt: Date.now() };
      this.state.accounts.push(acc);
    }
    Object.assign(acc, {
      mobile, sharedAccount: Boolean(acc.sharedAccount || sharedAccount),
      displayName: String(displayName || acc.displayName || '').slice(0, 80),
      remoteAccountId: String(remoteAccountId), remark: String(remark).slice(0, 80),
      tokenExpiresAt, capabilities: providerCapabilities('yunzhi', capabilities),
      tokenEnc: '', hwTokenEnc: '', authStatus: authStatus === 'expired' ? 'expired' : 'valid', lastCheckAt: Date.now(),
    });
    try {
      this._save();
    } catch (err) {
      if (previous) Object.assign(acc, previous);
      else this.state.accounts = this.state.accounts.filter((a) => a !== acc);
      throw err;
    }
    return this.hydrateAccount(acc);
  }

  updateAccountTokens(accountId, { token, hwToken, authStatus }) {
    const acc = this.state.accounts.find((a) => a.id === accountId);
    if (!acc) return null;
    if (token) acc.tokenEnc = this.encryptSecret(token);
    if (hwToken !== undefined && hwToken !== '') acc.hwTokenEnc = this.encryptSecret(hwToken);
    if (authStatus) acc.authStatus = authStatus;
    acc.lastCheckAt = Date.now();
    this._save();
    return this.hydrateAccount(acc);
  }

  hydrateAccount(acc) {
    if (!acc) return null;
    return {
      id: acc.id,
      ownerId: acc.ownerId,
      provider: acc.provider || 'cmcc',
      remoteAccountId: acc.remoteAccountId || '',
      sharedAccount: Boolean(acc.sharedAccount),
      displayName: acc.displayName || '',
      pendingDelete: Boolean(acc.pendingDelete),
      tokenExpiresAt: acc.tokenExpiresAt ?? null,
      capabilities: providerCapabilities(acc.provider || 'cmcc', acc.capabilities),
      mobile: acc.mobile,
      remark: acc.remark || '',
      token: this.decryptSecret(acc.tokenEnc),
      hwToken: this.decryptSecret(acc.hwTokenEnc),
      cmccUserId: acc.cmccUserId || '',
      province: acc.province || '',
      fingerprint: acc.fingerprint,
      authStatus: acc.pendingDelete ? 'deleting' : acc.authStatus || 'valid',
      lastCheckAt: acc.lastCheckAt,
      createdAt: acc.createdAt,
    };
  }

  sanitizeAccount(acc) {
    return {
      id: acc.id,
      ownerId: acc.ownerId,
      provider: acc.provider || 'cmcc',
      sharedAccount: Boolean(acc.sharedAccount),
      displayName: acc.displayName || '',
      pendingDelete: Boolean(acc.pendingDelete),
      tokenExpiresAt: acc.tokenExpiresAt ?? null,
      capabilities: providerCapabilities(acc.provider || 'cmcc', acc.capabilities),
      mobile: acc.mobile,
      remark: acc.remark || '',
      cmccUserId: acc.cmccUserId || '',
      province: acc.province || '',
      authStatus: acc.pendingDelete ? 'deleting' : acc.authStatus || 'valid',
      lastCheckAt: acc.lastCheckAt,
      createdAt: acc.createdAt,
    };
  }

  listAccountsByOwner(ownerId) {
    return this.state.accounts.filter((a) => a.ownerId === ownerId).map((a) => this.sanitizeAccount(a));
  }

  getHydratedAccountForOwner(ownerId, accountId) {
    const acc = this.state.accounts.find((a) => a.id === accountId && a.ownerId === ownerId);
    return acc ? this.hydrateAccount(acc) : null;
  }

  getHydratedAccountInternal(accountId) {
    const acc = this.state.accounts.find((a) => a.id === accountId);
    return acc ? this.hydrateAccount(acc) : null;
  }

  getAllHydratedAccounts() {
    return this.state.accounts.map((a) => this.hydrateAccount(a));
  }

  setAccountPendingDelete(ownerId, accountId, pendingDelete) {
    const account = this.state.accounts.find((a) => a.id === accountId && a.ownerId === ownerId && a.provider === 'yunzhi');
    if (!account) throw new Error('未找到该云智账号或无权操作');
    const previous = account.pendingDelete;
    account.pendingDelete = Boolean(pendingDelete);
    try { this._save(); } catch (err) { account.pendingDelete = previous; throw err; }
  }

  deleteAccountForOwner(ownerId, accountId) {
    const idx = this.state.accounts.findIndex((a) => a.id === accountId && a.ownerId === ownerId);
    if (idx === -1) throw new Error('未找到该官方账号或无权操作');
    const previousAccounts = [...this.state.accounts];
    const previousDevices = [...this.state.devices];
    const removedDeviceIds = this.state.devices
      .filter((d) => d.accountId === accountId && d.ownerId === ownerId)
      .map((d) => d.id);
    this.state.accounts.splice(idx, 1);
    this.state.devices = this.state.devices.filter((d) => !(d.accountId === accountId && d.ownerId === ownerId));
    try { this._save(); }
    catch (err) { this.state.accounts = previousAccounts; this.state.devices = previousDevices; throw err; }
    return { removedDeviceIds };
  }

  // ===== CloudPhone Devices (Strictly Scoped to ownerId) =====

  syncDevicesForAccount(ownerId, accountId, remoteDevices) {
    const account = this.state.accounts.find((a) => a.id === accountId && a.ownerId === ownerId);
    if (!account) throw new Error('未找到该账号或无权操作');
    if (!Array.isArray(remoteDevices)) throw new Error('实例列表响应格式无效');
    if (remoteDevices.some((d) => !d || !d.phoneId)) throw new Error('实例列表响应格式无效');
    const previousDevices = this.state.devices.map((device) => ({ ...device }));
    const provider = account.provider || 'cmcc';
    const now = Date.now();
    const seenIds = new Set();
    const updated = [];

    for (const rd of remoteDevices) {
      seenIds.add(rd.phoneId);
      let dev = this.state.devices.find(
        (d) => d.ownerId === ownerId && d.accountId === accountId && d.phoneId === rd.phoneId
      );
      if (!dev) {
        dev = {
          id: crypto.randomUUID(),
          ownerId,
          accountId,
          provider,
          phoneId: rd.phoneId,
          phoneName: rd.phoneName,
          platformType: provider === 'yunzhi' ? 'ctyun' : rd.platformType || '1',
          capabilities: providerCapabilities(provider, rd.capabilities || account.capabilities),
          instanceStatus: rd.instanceStatus,
          validStatus: rd.validStatus,
          lockStatus: rd.lockStatus || 0,
          isExpired: Boolean(rd.isExpired),
          expireStr: rd.expireStr || '',
          endTime: rd.endTime || '',
          specName: rd.specName || '',
          keepaliveEnabled: provider === 'cmcc',
          autoWakeup: provider === 'cmcc',
          screenshotCache: '',
          screenshotUpdatedAt: null,
          updatedAt: now,
        };
        this.state.devices.push(dev);
      } else {
        dev.phoneName = rd.phoneName || dev.phoneName;
        dev.provider = provider;
        dev.platformType = provider === 'yunzhi' ? 'ctyun' : rd.platformType || dev.platformType || '1';
        dev.capabilities = providerCapabilities(provider, rd.capabilities || account.capabilities);
        if (provider === 'yunzhi') { dev.keepaliveEnabled = false; dev.autoWakeup = false; }
        dev.instanceStatus = rd.instanceStatus;
        dev.validStatus = rd.validStatus;
        dev.lockStatus = rd.lockStatus || 0;
        dev.isExpired = Boolean(rd.isExpired);
        dev.expireStr = rd.expireStr || dev.expireStr;
        dev.endTime = rd.endTime || dev.endTime;
        dev.specName = rd.specName || dev.specName;
        dev.updatedAt = now;
      }
      updated.push(dev);
    }

    // Remove devices no longer returned under this account
    this.state.devices = this.state.devices.filter(
      (d) => !(d.ownerId === ownerId && d.accountId === accountId && !seenIds.has(d.phoneId))
    );
    try { this._save(); }
    catch (err) { this.state.devices = previousDevices; throw err; }
    return updated;
  }

  listDevicesByOwner(ownerId) {
    return this.state.devices.filter((d) => d.ownerId === ownerId).map((d) => ({ ...d }));
  }

  listAllDevicesInternal() {
    return this.state.devices.map((d) => ({ ...d }));
  }

  getDeviceForOwner(ownerId, deviceId) {
    const dev = this.state.devices.find((d) => d.id === deviceId && d.ownerId === ownerId);
    return dev ? { ...dev } : null;
  }

  getDeviceInternal(deviceId) {
    const dev = this.state.devices.find((d) => d.id === deviceId);
    return dev ? { ...dev } : null;
  }

  updateDeviceSettingsForOwner(ownerId, deviceId, patch = {}) {
    const dev = this.state.devices.find((d) => d.id === deviceId && d.ownerId === ownerId);
    if (!dev) throw new Error('未找到该云手机设备或无权操作');
    if (dev.provider === 'yunzhi' && ['keepaliveEnabled', 'keepaliveMode', 'autoWakeup', 'waitMinutes', 'connectMinutes'].some((key) => patch[key] !== undefined)) {
      throw new Error('云智渠道暂不支持后台长连接保活');
    }
    if (patch.keepaliveEnabled !== undefined) dev.keepaliveEnabled = Boolean(patch.keepaliveEnabled);
    if (patch.autoWakeup !== undefined) dev.autoWakeup = Boolean(patch.autoWakeup);
    if (patch.keepaliveMode !== undefined) {
      if (!['continuous', 'cycle'].includes(patch.keepaliveMode)) throw new Error('无效保活模式');
      dev.keepaliveMode = patch.keepaliveMode;
    }
    for (const field of ['waitMinutes', 'connectMinutes']) {
      if (patch[field] !== undefined) {
        const value = Number(patch[field]);
        if (!Number.isFinite(value) || value < 1 || value > 10080) throw new Error('分钟数必须为 1~10080');
        dev[field] = value;
      }
    }
    if (['keepaliveMode','waitMinutes','connectMinutes','keepaliveEnabled'].some(k => patch[k] !== undefined)) dev.scheduleStartedAt = Date.now();
    dev.updatedAt = Date.now();
    this._save();
    return { ...dev };
  }

  updateDeviceScreenshot(deviceId, screenshotUrlOrData) {
    const dev = this.state.devices.find((d) => d.id === deviceId);
    if (!dev) return null;
    dev.screenshotCache = screenshotUrlOrData || '';
    dev.screenshotUpdatedAt = Date.now();
    this._save();
    return { ...dev };
  }

  // ===== Per-User Isolated Logs =====

  appendLog(ownerId, { level = 'info', deviceId = '', phoneName = '', message }) {
    if (!ownerId) return;
    const logRecord = { ts: Date.now(), level, ownerId, deviceId, phoneName, message: String(message || '').slice(0,1500) };
    fs.appendFileSync(path.join(this.dataDir, 'runtime.jsonl'), JSON.stringify(logRecord) + '\n', { mode: 0o600 });
    let list = this.logsByUser.get(ownerId);
    if (!list) {
      list = [];
      this.logsByUser.set(ownerId, list);
    }
    list.push({
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      ts: Date.now(),
      level,
      deviceId,
      phoneName,
      message,
    });
    if (list.length > 400) {
      list.splice(0, list.length - 400);
    }
  }

  getLogsForOwner(ownerId, limit = 120) {
    const list = this.logsByUser.get(ownerId) || [];
    return list.slice(-limit).reverse();
  }

  /* ================= 星晨超级智能体电脑（TeleAgent）渠道 ================= */

  static teleaiState(status, statusReason) {
    const s = Number(status);
    if (s === 3) return statusReason === 10 ? 'recycled' : 'stopped';
    if (s === 100) return 'ready';
    if (s === 0) return 'unknown';
    return 'starting';
  }

  static teleaiStatusText(status, statusReason) {
    const s = Number(status);
    if (s === 3) return statusReason === 10 ? '已回收' : '已关机';
    if (s === 100) return '运行中';
    if (s === 5) return '排队中';
    if (s === 2) return '创建中';
    if (s === 4) return '初始化';
    return '未知';
  }

  upsertTeleaiAccount(ownerId, { loginName, password, remark, operationToken, operToken, aesKey, aesIv, expiresAt }) {
    const user = this.state.users.find((u) => u.id === ownerId);
    if (!user) throw new Error('所属平台用户不存在');
    const name = String(loginName || '').trim().toLowerCase();
    if (!name) throw new Error('账号不能为空');

    let acc = this.state.teleaiAccounts.find((a) => a.ownerId === ownerId && a.loginName === name);
    const now = Date.now();
    if (!acc) {
      const total = this.state.accounts.filter((a) => a.ownerId === ownerId).length
        + this.state.teleaiAccounts.filter((a) => a.ownerId === ownerId).length;
      if (total >= user.maxAccounts) {
        throw new Error(`已达到当前用户可绑定账号上限 (${user.maxAccounts} 个)`);
      }
      acc = {
        id: crypto.randomUUID(),
        ownerId,
        channel: 'teleai',
        loginName: name,
        remark: remark || '',
        operationTokenEnc: this.encryptSecret(operationToken || ''),
        operTokenEnc: this.encryptSecret(operToken || ''),
        aesKeyEnc: this.encryptSecret(aesKey || ''),
        aesIv: aesIv || '',
        tokenExpiresAt: expiresAt || null,
        passwordEnc: password ? this.encryptSecret(password) : '',
        authStatus: 'valid',
        lastCheckAt: now,
        lastRenewAt: now,
        createdAt: now,
      };
      this.state.teleaiAccounts.push(acc);
    } else {
      if (remark !== undefined && remark !== '') acc.remark = remark;
      if (operationToken) acc.operationTokenEnc = this.encryptSecret(operationToken);
      if (operToken) acc.operTokenEnc = this.encryptSecret(operToken);
      if (aesKey) acc.aesKeyEnc = this.encryptSecret(aesKey);
      if (aesIv) acc.aesIv = aesIv;
      if (expiresAt) acc.tokenExpiresAt = expiresAt;
      if (password) acc.passwordEnc = this.encryptSecret(password);
      acc.authStatus = 'valid';
      acc.lastCheckAt = now;
      acc.lastRenewAt = now;
    }
    this._save();
    return this.hydrateTeleaiAccount(acc);
  }

  updateTeleaiAccountTokens(accountId, patch = {}) {
    const acc = this.state.teleaiAccounts.find((a) => a.id === accountId);
    if (!acc) return null;
    if (patch.operationToken) acc.operationTokenEnc = this.encryptSecret(patch.operationToken);
    if (patch.operToken !== undefined && patch.operToken !== '') acc.operTokenEnc = this.encryptSecret(patch.operToken);
    if (patch.aesKey) acc.aesKeyEnc = this.encryptSecret(patch.aesKey);
    if (patch.aesIv) acc.aesIv = patch.aesIv;
    if (patch.expiresAt) acc.tokenExpiresAt = patch.expiresAt;
    if (patch.password) acc.passwordEnc = this.encryptSecret(patch.password);
    if (patch.authStatus) acc.authStatus = patch.authStatus;
    if (patch.remark !== undefined) acc.remark = patch.remark;
    acc.lastCheckAt = Date.now();
    if (patch.renewed) acc.lastRenewAt = Date.now();
    this._save();
    return this.hydrateTeleaiAccount(acc);
  }

  hydrateTeleaiAccount(acc) {
    if (!acc) return null;
    return {
      id: acc.id,
      ownerId: acc.ownerId,
      channel: 'teleai',
      loginName: acc.loginName,
      mobile: acc.loginName,
      remark: acc.remark || '',
      operationToken: this.decryptSecret(acc.operationTokenEnc),
      operToken: this.decryptSecret(acc.operTokenEnc),
      aesKey: this.decryptSecret(acc.aesKeyEnc),
      aesIv: acc.aesIv || '',
      password: this.decryptSecret(acc.passwordEnc),
      hasPassword: Boolean(acc.passwordEnc),
      tokenExpiresAt: acc.tokenExpiresAt || null,
      authStatus: acc.authStatus || 'valid',
      lastCheckAt: acc.lastCheckAt,
      lastRenewAt: acc.lastRenewAt || null,
      createdAt: acc.createdAt,
    };
  }

  sanitizeTeleaiAccount(acc) {
    const h = this.hydrateTeleaiAccount(acc);
    if (!h) return null;
    return {
      id: h.id,
      channel: 'teleai',
      loginName: h.loginName,
      mobile: h.loginName,
      remark: h.remark,
      hasPassword: h.hasPassword,
      tokenExpiresAt: h.tokenExpiresAt,
      authStatus: h.authStatus,
      lastCheckAt: h.lastCheckAt,
      lastRenewAt: h.lastRenewAt,
      createdAt: h.createdAt,
    };
  }

  listTeleaiAccountsByOwner(ownerId) {
    return this.state.teleaiAccounts
      .filter((a) => a.ownerId === ownerId)
      .map((a) => this.sanitizeTeleaiAccount(a));
  }

  listAllTeleaiAccountsInternal() {
    return this.state.teleaiAccounts.map((a) => this.hydrateTeleaiAccount(a));
  }

  getTeleaiAccountForOwner(ownerId, accountId) {
    const acc = this.state.teleaiAccounts.find((a) => a.id === accountId && a.ownerId === ownerId);
    return acc ? this.hydrateTeleaiAccount(acc) : null;
  }

  getTeleaiAccountInternal(accountId) {
    const acc = this.state.teleaiAccounts.find((a) => a.id === accountId);
    return acc ? this.hydrateTeleaiAccount(acc) : null;
  }

  deleteTeleaiAccountForOwner(ownerId, accountId) {
    const before = this.state.teleaiAccounts.length;
    this.state.teleaiAccounts = this.state.teleaiAccounts.filter(
      (a) => !(a.id === accountId && a.ownerId === ownerId)
    );
    this.state.teleaiInstances = this.state.teleaiInstances.filter(
      (i) => !(i.accountId === accountId && i.ownerId === ownerId)
    );
    const changed = before !== this.state.teleaiAccounts.length;
    if (changed) this._save();
    return changed;
  }

  syncTeleaiInstances(ownerId, accountId, remoteInstances) {
    const now = Date.now();
    const seen = new Set();
    const out = [];
    for (const ri of remoteInstances || []) {
      if (!ri || !ri.id) continue;
      seen.add(ri.id);
      let inst = this.state.teleaiInstances.find(
        (i) => i.ownerId === ownerId && i.accountId === accountId && i.instanceId === ri.id
      );
      const stateText = MultiTenantStore.teleaiState(ri.status, ri.statusReason);
      if (!inst) {
        inst = {
          id: crypto.randomUUID(),
          ownerId,
          accountId,
          channel: 'teleai',
          instanceId: ri.id,
          name: `星辰电脑 ${String(ri.id).slice(-6)}`,
          status: Number(ri.status) || 0,
          statusReason: Number(ri.statusReason) || 0,
          stateText,
          connectTimeout: ri.connectTimeout || 600,
          keepaliveEnabled: true,
          autoStart: true,
          checkIntervalSec: 60,
          clinkEnabled: false,
          moveSec: 30,
          kickWaitSec: 1800,
          connectURL: '',
          connectURLAt: null,
          lastStartAt: null,
          lastError: '',
          updatedAt: now,
        };
        this.state.teleaiInstances.push(inst);
      } else {
        // 老数据兼容：补齐 CLINK 相关默认值
        if (inst.clinkEnabled === undefined) inst.clinkEnabled = false;
        if (inst.moveSec === undefined) inst.moveSec = 30;
        if (inst.kickWaitSec === undefined) inst.kickWaitSec = 1800;
        inst.status = Number(ri.status) || 0;
        inst.statusReason = Number(ri.statusReason) || 0;
        inst.stateText = stateText;
        inst.connectTimeout = ri.connectTimeout || inst.connectTimeout;
        inst.updatedAt = now;
      }
      out.push({ ...inst });
    }
    this.state.teleaiInstances = this.state.teleaiInstances.filter(
      (i) => !(i.ownerId === ownerId && i.accountId === accountId && !seen.has(i.instanceId))
    );
    this._save();
    return out;
  }

  listTeleaiInstancesByOwner(ownerId) {
    return this.state.teleaiInstances.filter((i) => i.ownerId === ownerId).map((i) => ({ ...i }));
  }

  listAllTeleaiInstancesInternal() {
    return this.state.teleaiInstances.map((i) => ({ ...i }));
  }

  getTeleaiInstanceForOwner(ownerId, id) {
    const inst = this.state.teleaiInstances.find((i) => i.id === id && i.ownerId === ownerId);
    return inst ? { ...inst } : null;
  }

  updateTeleaiInstance(id, patch = {}) {
    const inst = this.state.teleaiInstances.find((i) => i.id === id);
    if (!inst) return null;
    for (const key of ['keepaliveEnabled', 'autoStart', 'clinkEnabled']) {
      if (patch[key] !== undefined) inst[key] = Boolean(patch[key]);
    }
    for (const key of ['moveSec', 'kickWaitSec']) {
      if (patch[key] !== undefined) {
        const v = Number(patch[key]);
        if (!Number.isFinite(v) || v < 0 || v > 86400) throw new Error(`${key} 取值超出范围`);
        inst[key] = v;
      }
    }
    if (patch.checkIntervalSec !== undefined) {
      const v = Number(patch.checkIntervalSec);
      if (!Number.isFinite(v) || v < 15 || v > 86400) throw new Error('巡检间隔需在 15~86400 秒');
      inst.checkIntervalSec = v;
    }
    if (patch.connectURL !== undefined) {
      inst.connectURL = patch.connectURL;
      inst.connectURLAt = Date.now();
    }
    if (patch.lastStartAt !== undefined) inst.lastStartAt = patch.lastStartAt;
    if (patch.lastError !== undefined) inst.lastError = patch.lastError;
    if (patch.name !== undefined && String(patch.name).trim()) inst.name = String(patch.name).trim().slice(0, 40);
    inst.updatedAt = Date.now();
    this._save();
    return { ...inst };
  }
}

module.exports = { MultiTenantStore };
