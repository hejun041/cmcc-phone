(function (root) {
  'use strict';
  const providerOf = (record) => record?.provider === 'yunzhi' ? 'yunzhi' : 'cmcc';
  function filterDevices(devices, provider) {
    return devices.filter((device) => provider === 'all' || providerOf(device) === provider);
  }
  function groupAccounts(accounts) {
    return { cmcc: accounts.filter((a) => providerOf(a) === 'cmcc'), yunzhi: accounts.filter((a) => providerOf(a) === 'yunzhi') };
  }
  function captchaGeometry(challenge, stageWidth, trackWidth, handleWidth, offset) {
    const width = Math.max(1, Number(challenge.width) || 300);
    const height = Math.max(1, Number(challenge.height) || 180);
    const pieceWidth = Math.min(width, Math.max(1, Number(challenge.pieceWidth) || 62));
    const pieceHeight = Math.min(height, Math.max(1, Number(challenge.pieceHeight) || 62));
    const fraction = Math.max(0, Math.min(1, offset / Math.max(1, trackWidth - handleWidth)));
    const moveX = fraction * (width - pieceWidth);
    const scale = stageWidth / width;
    return { moveX, height: height * scale, pieceWidth: pieceWidth * scale, pieceHeight: pieceHeight * scale,
      left: moveX * scale, top: Math.max(0, (Number(challenge.y) || 0) - 2) * scale };
  }
  class BindingFlow {
    constructor() { this.generation = 0; this.provider = 'cmcc'; }
    restart(provider, mobile = '') {
      this.provider = provider === 'yunzhi' ? 'yunzhi' : 'cmcc';
      this.generation++;
      this.mobile = mobile;
      return { provider: this.provider, generation: this.generation };
    }
    isCurrent(ticket) { return Boolean(ticket && ticket.provider === this.provider && ticket.generation === this.generation); }
    close() { this.generation++; }
  }
  const api = { BindingFlow, providerOf, filterDevices, groupAccounts, captchaGeometry };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.CloudChannels = api;
})(typeof window === 'object' ? window : globalThis);
