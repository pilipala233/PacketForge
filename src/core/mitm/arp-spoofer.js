/**
 * ARP 欺骗抽象层
 * 提供平台无关的 ARP 欺骗接口
 */

import { EventEmitter } from 'node:events';

export class ArpSpoofer extends EventEmitter {
  constructor(platform = process.platform) {
    super();
    this.platform = platform;
    this.impl = null;
  }

  /**
   * 初始化平台特定的实现
   */
  async initialize() {
    if (this.platform === 'win32') {
      const { Win32ArpSpoofer } = await import('./platform/win32/arp.js');
      this.impl = new Win32ArpSpoofer();
    } else if (this.platform === 'darwin') {
      // TODO: 实现 macOS 版本
      throw new Error('macOS ARP spoofing not implemented yet');
    } else {
      throw new Error(`Platform ${this.platform} not supported`);
    }

    // 转发事件
    this.impl.on('started', () => this.emit('started'));
    this.impl.on('stopped', () => this.emit('stopped'));
  }

  /**
   * 开始 ARP 欺骗
   */
  async startSpoofing(options) {
    if (!this.impl) {
      await this.initialize();
    }
    return this.impl.startSpoofing(options);
  }

  /**
   * 停止 ARP 欺骗
   */
  async stopSpoofing() {
    if (!this.impl) {
      return;
    }
    return this.impl.stopSpoofing();
  }

  /**
   * 添加目标
   */
  async addTarget(target) {
    if (!this.impl) {
      throw new Error('ARP spoofer not initialized');
    }
    return this.impl.addTarget(target);
  }

  /**
   * 移除目标
   */
  async removeTarget(targetIp) {
    if (!this.impl) {
      throw new Error('ARP spoofer not initialized');
    }
    return this.impl.removeTarget(targetIp);
  }
}
