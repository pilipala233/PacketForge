import { EventEmitter } from 'node:events';

export class FlowMonitor extends EventEmitter {
  constructor(platform = process.platform) {
    super();
    this.platform = platform;
    this.impl = null;
  }

  async initialize() {
    if (this.impl) {
      return;
    }
    if (this.platform === 'win32') {
      const { Win32FlowMonitor } = await import('./platform/win32/flow-monitor.js');
      this.impl = new Win32FlowMonitor();
      this.impl.on('flow', (flow) => this.emit('flow', flow));
      return;
    }
    throw new Error(`Platform ${this.platform} not supported`);
  }

  async start(options) {
    await this.initialize();
    return this.impl.start(options);
  }

  async stop(options = {}) {
    if (!this.impl) {
      return { running: false };
    }
    return this.impl.stop(options);
  }

  status() {
    if (!this.impl) {
      return { running: false };
    }
    return this.impl.status();
  }
}
