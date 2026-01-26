import { EventEmitter } from 'node:events';

export class TrafficShaper extends EventEmitter {
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
      const { Win32TrafficShaper } = await import('./platform/win32/traffic-shaper.js');
      this.impl = new Win32TrafficShaper();
      this.impl.on('stats', (stats) => this.emit('stats', stats));
      return;
    }
    throw new Error(`Platform ${this.platform} not supported`);
  }

  async start(options) {
    await this.initialize();
    return this.impl.start(options);
  }

  async stop() {
    if (!this.impl) {
      return { running: false };
    }
    return this.impl.stop();
  }

  status() {
    if (!this.impl) {
      return { running: false };
    }
    return this.impl.status();
  }
}
