'use strict';

const crypto = require('crypto');
const { bridgeError } = require('./yunzhiClient');

function createYunzhiRoutes({ store, engine, client, readJsonBody, sendJson }) {
  const challenges = new Map();
  const reservations = new Map();

  function reject(message, status = 400, code) {
    throw Object.assign(new Error(message), { status, code });
  }
  function configured() {
    if (!client.isConfigured()) throw bridgeError('YUNZHI_DISABLED', 503);
  }
  function session(ownerId, id) {
    const item = challenges.get(id);
    if (!item || item.ownerId !== ownerId || item.expiresAt <= Date.now()) reject('安全验证会话已失效，请重新获取', 400);
    return item;
  }
  function reserve(ownerId, mobile, existing) {
    const key = `${ownerId}:${mobile}`;
    if (reservations.has(key)) reject('该云智账号正在验证，请稍后重试', 409);
    const user = store.state.users.find((u) => u.id === ownerId && !u.disabled);
    if (!user) reject('平台账号已停用，请重新登录', 403);
    const pending = [...reservations.values()].filter((r) => r.ownerId === ownerId && r.newAccount).length;
    if (!existing && store.listAccountsByOwner(ownerId).length + pending >= user.maxAccounts) {
      reject(`已达到当前用户可绑定官方账号上限 (${user.maxAccounts} 个)`);
    }
    reservations.set(key, { ownerId, newAccount: !existing });
    return () => reservations.delete(key);
  }

  async function syncAccount(account) {
    configured();
    if (account.pendingDelete) reject('云智账号正在解绑，请先完成解绑', 409);
    try {
      const result = await client.getAccountDevices(account);
      if (!Array.isArray(result.devices)) reject('云智实例列表响应格式无效', 502);
      const current = store.getHydratedAccountForOwner(account.ownerId, account.id);
      if (!current || current.remoteAccountId !== account.remoteAccountId) reject('账号绑定已变更，请刷新后重试', 409);
      if (result.account) {
        store.upsertYunzhiAccount(account.ownerId, { ...current,
          tokenExpiresAt: result.account.tokenExpiresAt, capabilities: result.account.capabilities,
          authStatus: result.account.authStatus });
      }
      const devices = store.syncDevicesForAccount(account.ownerId, account.id, result.devices);
      engine.reconcileAllDevices();
      return devices;
    } catch (err) {
      if (err.code === 'YUNZHI_AUTH_EXPIRED') store.updateAccountTokens(account.id, { authStatus: 'expired' });
      if (err.code === 'ACCOUNT_DISABLED') store.updateAccountTokens(account.id, { authStatus: 'disabled' });
      store.appendLog(account.ownerId, { level: 'warn', message: '云智实例同步暂未完成，已保留上次列表，请稍后重试' });
      throw err;
    }
  }

  async function removeAccount(account) {
    configured();
    store.setAccountPendingDelete(account.ownerId, account.id, true);
    try { await client.deleteAccount(account); }
    catch (err) { store.setAccountPendingDelete(account.ownerId, account.id, false); throw err; }
    store.deleteAccountForOwner(account.ownerId, account.id);
    engine.reconcileAllDevices();
  }

  async function handle(req, res, pathname, currentUser, sid) {
    const ownerId = currentUser.id;
    if (pathname.startsWith('/api/yunzhi/')) {
      configured();
      if (req.method === 'POST' && pathname === '/api/yunzhi/captcha/get') {
        for (const [key, item] of challenges) if (item.expiresAt <= Date.now()) challenges.delete(key);
        const body = await readJsonBody(req);
        const mobile = String(body.mobile || '').replace(/\s+/g, '');
        if (!/^1[3-9]\d{9}$/.test(mobile)) reject('请输入有效的 11 位手机号');
        const existing = body.accountId
          ? store.getHydratedAccountForOwner(ownerId, body.accountId)
          : store.getAllHydratedAccounts().find((a) => a.ownerId === ownerId && a.provider === 'yunzhi' && a.mobile === mobile);
        if (body.accountId && (!existing || existing.provider !== 'yunzhi')) reject('未找到该云智账号或无权操作', 404);
        if (existing && existing.mobile !== mobile) reject('续期手机号必须与已绑定云智账号一致');
        if (existing?.pendingDelete) reject('云智账号正在解绑，请先完成解绑', 409);
        const challenge = await client.getCaptcha({ ownerId, mobile, remoteAccountId: existing?.remoteAccountId });
        const captchaSessionId = crypto.randomUUID();
        challenges.set(captchaSessionId, {
          ownerId, mobile, accountId: existing?.id, remoteAccountId: existing?.remoteAccountId,
          challengeId: challenge.challengeId, smsSent: false, verifying: false,
          expiresAt: Date.now() + Math.max(1, Math.min(Number(challenge.expiresIn) || 300, 600)) * 1000,
        });
        sendJson(res, 200, { ok: true, captchaSessionId,
          originalImageBase64: challenge.backgroundImage, jigsawImageBase64: challenge.sliderImage,
          backgroundWidth: challenge.backgroundWidth, backgroundHeight: challenge.backgroundHeight,
          sliderWidth: challenge.sliderWidth, sliderHeight: challenge.sliderHeight,
          sliderY: challenge.sliderY, positionX: challenge.positionX });
        return true;
      }
      if (req.method === 'POST' && pathname === '/api/yunzhi/captcha/send-sms') {
        const body = await readJsonBody(req);
        const item = session(ownerId, body.captchaSessionId);
        if (item.sending || item.smsSent) reject('验证码已发送或正在发送，请稍后重试', 429);
        item.sending = true;
        try {
          const result = await client.sendSms({ ownerId, challengeId: item.challengeId, sliderX: body.moveX });
          session(ownerId, body.captchaSessionId);
          item.smsSent = true;
          sendJson(res, 200, { ok: true, expiresIn: result.expiresIn });
        } finally { item.sending = false; }
        return true;
      }
      if (req.method === 'POST' && pathname === '/api/yunzhi/login/sms') {
        const body = await readJsonBody(req);
        const item = session(ownerId, body.captchaSessionId);
        if (String(body.mobile || '').replace(/\s+/g, '') !== item.mobile) reject('手机号与本次安全验证不一致');
        if (!item.smsSent) reject('请先完成安全验证并获取短信验证码');
        if (!/^\d{6}$/.test(String(body.code || ''))) reject('请输入 6 位短信验证码');
        if (item.verifying) reject('正在验证，请勿重复提交', 409);
        const existing = store.listAccountsByOwner(ownerId).find((a) => a.provider === 'yunzhi' && a.mobile === item.mobile);
        const release = reserve(ownerId, item.mobile, existing);
        item.verifying = true;
        let verified;
        let localSaved = false;
        try {
          verified = await client.verifySms({ ownerId, challengeId: item.challengeId, code: String(body.code) });
          const renewalTarget = item.accountId ? store.getHydratedAccountForOwner(ownerId, item.accountId) : null;
          if (item.accountId && (!renewalTarget || renewalTarget.remoteAccountId !== item.remoteAccountId ||
              verified.account.id !== item.remoteAccountId)) {
            throw bridgeError('ACCOUNT_BINDING_CHANGED', 409);
          }
          let account;
          try {
            account = store.upsertYunzhiAccount(ownerId, { mobile: item.mobile,
              remark: body.remark === undefined ? existing?.remark || '' : String(body.remark),
              remoteAccountId: verified.account.id, tokenExpiresAt: verified.account.tokenExpiresAt,
              capabilities: verified.account.capabilities });
          } catch (_) { reject('云智登录已完成，但控制中心保存失败，请重试', 400); }
          localSaved = true;
          let devices = [];
          let syncWarning = '';
          try { devices = await syncAccount(account); }
          catch (_) { syncWarning = '账号已绑定，实例同步暂未完成，请稍后点击同步'; }
          store.appendLog(ownerId, { level: syncWarning ? 'warn' : 'success',
            message: syncWarning || `云智账号认证成功，同步 ${devices.length} 台实例` });
          sendJson(res, 200, { ok: true, account: store.sanitizeAccount(store.getHydratedAccountForOwner(ownerId, account.id)),
            deviceCount: devices.length, ...(syncWarning ? { syncWarning } : {}) });
        } catch (err) {
          if (verified?.created && !localSaved) {
            try { await client.deleteAccount({ ownerId, remoteAccountId: verified.account.id }); }
            catch (_) { store.appendLog(ownerId, { level: 'warn', message: '云智账号本地保存失败，远端清理未确认，请重新绑定或联系管理员' }); }
          }
          throw err;
        } finally {
          if (verified) challenges.delete(body.captchaSessionId);
          item.verifying = false;
          release();
        }
        return true;
      }
      const job = pathname.match(/^\/api\/yunzhi\/jobs\/([A-Za-z0-9_-]{1,160})$/);
      if (req.method === 'GET' && job) {
        sendJson(res, 200, { ok: true, job: await client.getJob(ownerId, job[1]) });
        return true;
      }
      sendJson(res, 404, { ok: false, error: '未找到云智接口' });
      return true;
    }

    const accountMatch = pathname.match(/^\/api\/accounts\/([a-f0-9-]+)(?:\/(sync|run))?$/i);
    if (accountMatch) {
      const account = store.getHydratedAccountForOwner(ownerId, accountMatch[1]);
      if (!account) { sendJson(res, 404, { ok: false, error: '未找到该账号或无权操作' }); return true; }
      if (account.provider !== 'yunzhi') return false;
      if (req.method === 'POST' && accountMatch[2] === 'sync') {
        const devices = await syncAccount(account);
        sendJson(res, 200, { ok: true, deviceCount: devices.length });
        return true;
      }
      if (req.method === 'POST' && accountMatch[2] === 'run') {
        if (account.pendingDelete) reject('云智账号正在解绑，请先完成解绑', 409);
        if (account.sharedAccount) throw bridgeError('SHARED_SCHEDULER_MANAGED', 409);
        const body = await readJsonBody(req);
        if (!['smoke', 'full'].includes(body.mode)) reject('不支持的云智任务模式');
        if (!/^[a-f0-9-]{36}$/i.test(String(body.requestId || ''))) reject('缺少有效任务请求编号');
        const result = await client.runAccount(account, body.mode, body.requestId);
        sendJson(res, 200, { ok: true, ...result });
        return true;
      }
      if (req.method === 'DELETE' && !accountMatch[2]) {
        await removeAccount(account);
        sendJson(res, 200, { ok: true });
        return true;
      }
      return false;
    }

    const deviceMatch = pathname.match(/^\/api\/devices\/([a-f0-9-]+)\/(settings|power|screenshot|stream\/open)$/i);
    if (!deviceMatch) return false;
    const device = store.getDeviceForOwner(ownerId, deviceMatch[1]);
    if (!device) { sendJson(res, 404, { ok: false, error: '未找到该云手机设备或无权访问' }); return true; }
    if (device.provider !== 'yunzhi') return false;
    const account = store.getHydratedAccountForOwner(ownerId, device.accountId);
    if (!account) reject('关联的云智账号不存在', 404);
    const action = deviceMatch[2];
    if (req.method === 'PATCH' && action === 'settings') {
      const updated = store.updateDeviceSettingsForOwner(ownerId, device.id, await readJsonBody(req));
      sendJson(res, 200, { ok: true, device: { ...updated, runtime: engine.getRuntimeSnapshot(device.id) } });
      return true;
    }
    if (req.method !== 'POST') return false;
    if (action === 'power') {
      const body = await readJsonBody(req);
      if (!device.capabilities?.power?.includes(body.action)) throw bridgeError('CAPABILITY_UNSUPPORTED', 501);
      sendJson(res, 200, { ok: true, ...await client.power(account, device.phoneId, body.action) });
      return true;
    }
    if (action === 'screenshot') throw bridgeError('CAPABILITY_UNSUPPORTED', 501);
    if (action === 'stream/open') {
      if (!device.capabilities?.stream) throw bridgeError('CAPABILITY_UNSUPPORTED', 501);
      if (account.authStatus === 'expired') throw bridgeError('YUNZHI_AUTH_EXPIRED', 409);
      if (account.pendingDelete) reject('云智账号正在解绑，请先完成解绑', 409);
      if (device.isExpired) reject('云智实例已到期，请先续期', 409);
      await readJsonBody(req);
      const stream = await client.getStreamAuth(account, device.phoneId);
      if (!store.getHydratedAccountForOwner(ownerId, account.id)) reject('账号绑定已变更，请刷新后重试', 409);
      // The official standalone window owns its connection lifecycle.
      sendJson(res, 200, { ok: true, device: { id: device.id, provider: 'yunzhi', platformType: 'ctyun', phoneName: device.phoneName }, stream });
      return true;
    }
    return false;
  }

  return { handle, syncAccount, removeAccount };
}

module.exports = { createYunzhiRoutes };
