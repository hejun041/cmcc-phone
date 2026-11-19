(function () {
  'use strict';

  // The current official runtime reads window.top.__wxjs_environment before
  // connecting. It must run in the control tab itself to avoid a cross-origin
  // SecurityError; pointer/touch handling stays in the official runtime.
  class YunzhiWebPlayer {
    constructor(container, stream, callbacks = {}) {
      this.container = container;
      this.stream = stream;
      this.callbacks = callbacks;
      this.destroyed = false;
    }

    async start() {
      if (this.destroyed) return;
      if (typeof this.stream?.ticket !== 'string' || !this.stream.ticket.trim() ||
          typeof this.stream?.resourceId !== 'string' || !this.stream.resourceId.trim()) {
        this.callbacks.onError?.('云智运行凭证无效，请重新连接');
        return;
      }
      try {
        const query = new URLSearchParams({
          code: this.stream.resourceId, ticket: this.stream.ticket,
          sdk: '1', session: `yunzhi-${window.crypto.randomUUID()}`,
        });
        // Pin the origin. Runtime credentials stay in the URL fragment and are
        // never accepted as a caller-controlled navigation destination.
        const runtime = new URL('https://pm.ctyun.cn/');
        runtime.hash = `/sdk?${query.toString()}`;
        this.callbacks.onState?.('正在打开云智独立控制窗口…');
        window.location.replace(runtime.toString());
      } catch (_) {
        this.callbacks.onError?.('云智控制窗口打开失败，请重新进入控制');
      }
    }

    // Audio and connection controls belong to the official standalone window.
    setMuted() {}

    destroy() {
      if (this.destroyed) return;
      this.destroyed = true;
      this.stream = null;
      this.container.innerHTML = '';
    }
  }

  window.YunzhiWebPlayer = YunzhiWebPlayer;
})();
