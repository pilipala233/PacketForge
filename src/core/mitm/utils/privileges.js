/**
 * 权限管理模块
 * 检测和提升管理员权限
 */

import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const execAsync = promisify(exec);

/**
 * 检查当前进程是否具有管理员权限
 * @returns {Promise<boolean>}
 */
export async function isElevated() {
  if (process.platform === 'win32') {
    try {
      // Windows: 尝试读取需要管理员权限的注册表项
      await execAsync('net session', { windowsHide: true });
      return true;
    } catch {
      return false;
    }
  }

  if (process.platform === 'darwin' || process.platform === 'linux') {
    // macOS/Linux: 检查 EUID
    return process.getuid?.() === 0;
  }

  return false;
}

/**
 * 请求管理员权限
 * @param {string} reason - 请求权限的原因
 * @returns {Promise<{success: boolean, error?: string}>}
 */
export async function requestElevation(reason = 'PacketForge requires administrator privileges') {
  try {
    const sudoPrompt = await import('sudo-prompt');
    const options = {
      name: 'PacketForge',
      icns: undefined
    };

    return new Promise((resolve) => {
      // 执行一个简单的命令来触发权限提升对话框
      const command = process.platform === 'win32' ? 'echo elevated' : 'echo elevated';

      sudoPrompt.exec(command, options, (error) => {
        if (error) {
          resolve({ success: false, error: error.message });
        } else {
          resolve({ success: true });
        }
      });
    });
  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * 检查权限状态
 * @returns {Promise<{elevated: boolean, reason?: string}>}
 */
export async function checkPrivileges() {
  const elevated = await isElevated();
  if (elevated) {
    return { elevated: true };
  }

  const platform = process.platform;
  let reason = 'Administrator privileges required for network operations';

  if (platform === 'win32') {
    reason = 'Run as Administrator required for ARP spoofing and traffic redirection';
  } else if (platform === 'darwin') {
    reason = 'sudo privileges required for ARP spoofing and pfctl';
  }

  return { elevated: false, reason };
}
