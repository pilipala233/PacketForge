/**
 * Windows 流量重定向实现
 * 使用 netsh 和注册表配置 IP 转发和端口重定向
 */

import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const execAsync = promisify(exec);

export class Win32Redirect {
  constructor() {
    this.enabled = false;
    this.redirectRules = [];
  }

  /**
   * 启用 IP 转发
   */
  async enableIpForwarding() {
    try {
      console.log('[redirect] Enabling IP forwarding...');

      // 方法 1: 使用 netsh (临时)
      console.log('[redirect] Setting interface forwarding via netsh...');
      const netshResult = await execAsync(
        'netsh interface ipv4 set interface "Ethernet" forwarding=enabled',
        { windowsHide: true }
      );
      console.log('[redirect] netsh result:', netshResult.stdout || 'OK');

      // 方法 2: 修改注册表 (永久)
      console.log('[redirect] Setting IPEnableRouter registry key...');
      const regResult = await execAsync(
        'reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f',
        { windowsHide: true }
      );
      console.log('[redirect] Registry result:', regResult.stdout || 'OK');

      console.log('[redirect] ✓ IP forwarding enabled successfully');
    } catch (error) {
      console.error('[redirect] ✗ Failed to enable IP forwarding:', error.message);
      console.error('[redirect] Error details:', error);
      throw error;
    }
  }

  /**
   * 禁用 IP 转发
   */
  async disableIpForwarding() {
    try {
      console.log('[redirect] Disabling IP forwarding...');

      console.log('[redirect] Disabling interface forwarding via netsh...');
      await execAsync(
        'netsh interface ipv4 set interface "Ethernet" forwarding=disabled',
        { windowsHide: true }
      );

      console.log('[redirect] Resetting IPEnableRouter registry key...');
      await execAsync(
        'reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 0 /f',
        { windowsHide: true }
      );

      console.log('[redirect] ✓ IP forwarding disabled successfully');
    } catch (error) {
      console.error('[redirect] ✗ Failed to disable IP forwarding:', error.message);
      console.error('[redirect] Error details:', error);
    }
  }

  /**
   * 设置端口重定向
   * 注意：netsh portproxy 不适合透明代理，这里仅作为示例
   * 实际应使用 WinDivert 进行数据包级别的重定向
   *
   * @param {Object} options
   * @param {number} options.httpPort - HTTP 端口 (默认 80)
   * @param {number} options.httpsPort - HTTPS 端口 (默认 443)
   * @param {number} options.proxyPort - 代理端口
   */
  async setupRedirect({ httpPort = 80, httpsPort = 443, proxyPort }) {
    try {
      console.log('[redirect] Setting up port redirection...');
      console.log('[redirect] Configuration:', {
        httpPort,
        httpsPort,
        proxyPort,
        method: 'netsh portproxy'
      });

      // 警告：netsh portproxy 会改变目标地址，不适合透明代理
      // 这里仅作为临时方案，完整实现需要 WinDivert
      console.warn('[redirect] ⚠ Using netsh portproxy (limited functionality)');
      console.warn('[redirect] ⚠ For full transparent proxy, use WinDivert');

      // 重定向 HTTP
      console.log(`[redirect] Redirecting port ${httpPort} -> ${proxyPort} (HTTP)...`);
      const httpCommand = `netsh interface portproxy add v4tov4 listenport=${httpPort} listenaddress=0.0.0.0 connectport=${proxyPort} connectaddress=127.0.0.1`;
      await execAsync(httpCommand, { windowsHide: true });
      this.redirectRules.push({ port: httpPort, type: 'http' });
      console.log(`[redirect] ✓ HTTP redirect added`);

      // 重定向 HTTPS
      console.log(`[redirect] Redirecting port ${httpsPort} -> ${proxyPort} (HTTPS)...`);
      const httpsCommand = `netsh interface portproxy add v4tov4 listenport=${httpsPort} listenaddress=0.0.0.0 connectport=${proxyPort} connectaddress=127.0.0.1`;
      await execAsync(httpsCommand, { windowsHide: true });
      this.redirectRules.push({ port: httpsPort, type: 'https' });
      console.log(`[redirect] ✓ HTTPS redirect added`);

      this.enabled = true;
      console.log('[redirect] ✓ Port redirection enabled successfully');
      console.log('[redirect] Active rules:', this.redirectRules);
    } catch (error) {
      console.error('[redirect] ✗ Failed to setup redirect:', error.message);
      console.error('[redirect] Error details:', error);
      throw error;
    }
  }

  /**
   * 清除端口重定向
   */
  async clearRedirect() {
    try {
      console.log('[redirect] Clearing port redirection...');
      console.log('[redirect] Rules to clear:', this.redirectRules);

      for (const rule of this.redirectRules) {
        console.log(`[redirect] Removing redirect for port ${rule.port} (${rule.type})...`);
        const command = `netsh interface portproxy delete v4tov4 listenport=${rule.port} listenaddress=0.0.0.0`;
        await execAsync(command, { windowsHide: true });
        console.log(`[redirect] ✓ Removed redirect for port ${rule.port}`);
      }

      this.redirectRules = [];
      this.enabled = false;
      console.log('[redirect] ✓ Port redirection cleared successfully');
    } catch (error) {
      console.error('[redirect] ✗ Failed to clear redirect:', error.message);
      console.error('[redirect] Error details:', error);
    }
  }

  /**
   * 检查重定向状态
   */
  async status() {
    try {
      console.log('[redirect] Checking redirect status...');
      const { stdout } = await execAsync('netsh interface portproxy show all', {
        windowsHide: true
      });
      console.log('[redirect] Current portproxy rules:', stdout || '(none)');
      return {
        enabled: this.enabled,
        rules: this.redirectRules,
        raw: stdout
      };
    } catch (error) {
      console.error('[redirect] Failed to get status:', error.message);
      return {
        enabled: false,
        rules: [],
        error: error.message
      };
    }
  }
}

/**
 * 流量重定向抽象层
 */
export class TrafficRedirect {
  constructor(platform = process.platform) {
    if (platform === 'win32') {
      this.impl = new Win32Redirect();
    } else {
      throw new Error(`Platform ${platform} not supported yet`);
    }
  }

  async enableIpForwarding() {
    return this.impl.enableIpForwarding();
  }

  async disableIpForwarding() {
    return this.impl.disableIpForwarding();
  }

  async setupRedirect(options) {
    return this.impl.setupRedirect(options);
  }

  async clearRedirect() {
    return this.impl.clearRedirect();
  }

  async status() {
    return this.impl.status();
  }
}
