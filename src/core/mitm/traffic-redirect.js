/**
 * 流量重定向抽象层
 * 提供平台无关的流量重定向接口
 */

export class TrafficRedirect {
  constructor(platform = process.platform) {
    this.platform = platform;
    this.impl = null;
  }

  /**
   * 初始化平台特定的实现
   */
  async initialize() {
    if (this.platform === 'win32') {
      const { Win32Redirect } = await import('./platform/win32/redirect-improved.js');
      this.impl = new Win32Redirect();
    } else if (this.platform === 'darwin') {
      // TODO: 实现 macOS 版本
      throw new Error('macOS traffic redirect not implemented yet');
    } else {
      throw new Error(`Platform ${this.platform} not supported`);
    }
  }

  /**
   * 启用 IP 转发
   */
  async enableIpForwarding(options = {}) {
    if (!this.impl) {
      await this.initialize();
    }
    return this.impl.enableIpForwarding(options);
  }

  /**
   * 禁用 IP 转发
   */
  async disableIpForwarding(options = {}) {
    if (!this.impl) {
      return;
    }
    return this.impl.disableIpForwarding(options);
  }

  /**
   * 设置端口重定向
   */
  async setupRedirect(options) {
    if (!this.impl) {
      await this.initialize();
    }
    return this.impl.setupRedirect(options);
  }

  /**
   * 清除端口重定向
   */
  async clearRedirect() {
    if (!this.impl) {
      return;
    }
    return this.impl.clearRedirect();
  }

  /**
   * 获取状态
   */
  async status() {
    if (!this.impl) {
      return { enabled: false };
    }
    return this.impl.status();
  }
}
