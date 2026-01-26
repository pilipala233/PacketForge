/**
 * 网络扫描模块
 * 枚举网络接口、扫描局域网设备、检测网关
 */

import os from 'node:os';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import { getSubnetIps, ipToInt, isValidIp, isValidMac, normalizeMac } from './utils/ip-utils.js';

const execAsync = promisify(exec);

function getInterfaceIpv4(interfaceName) {
  if (!interfaceName) {
    return null;
  }
  const interfaces = os.networkInterfaces();
  const addresses = interfaces[interfaceName];
  if (!addresses) {
    return null;
  }
  const ipv4 = addresses.find((addr) => addr.family === 'IPv4' && !addr.internal);
  if (!ipv4) {
    return null;
  }
  return { ip: ipv4.address, netmask: ipv4.netmask };
}

function cidrToNetmask(prefix) {
  const bits = Number.parseInt(prefix, 10);
  if (!Number.isFinite(bits) || bits < 0 || bits > 32) {
    return null;
  }
  if (bits === 0) {
    return '0.0.0.0';
  }
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return [
    (mask >>> 24) & 0xff,
    (mask >>> 16) & 0xff,
    (mask >>> 8) & 0xff,
    mask & 0xff
  ].join('.');
}

function parseSubnet(subnet) {
  if (!subnet || typeof subnet !== 'string') {
    return null;
  }
  const match = subnet.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!match) {
    return null;
  }
  const ip = match[1];
  if (!isValidIp(ip)) {
    return null;
  }
  const netmask = cidrToNetmask(match[2]);
  if (!netmask) {
    return null;
  }
  return { ip, netmask };
}

function resolveSubnetInfo(interfaceName, subnet) {
  const parsed = parseSubnet(subnet);
  if (parsed) {
    return parsed;
  }
  return getInterfaceIpv4(interfaceName);
}

function isInSubnet(ip, networkIp, netmask) {
  if (!ip || !networkIp || !netmask) {
    return false;
  }
  const ipInt = ipToInt(ip);
  const netInt = ipToInt(networkIp);
  const maskInt = ipToInt(netmask);
  return (ipInt & maskInt) === (netInt & maskInt);
}

async function pingIp(ip, timeoutMs = 250) {
  const timeout = Math.max(1, Math.floor(timeoutMs));
  const command =
    process.platform === 'win32'
      ? `ping -n 1 -w ${timeout} ${ip}`
      : process.platform === 'darwin'
        ? `ping -c 1 -W ${timeout} ${ip}`
        : `ping -c 1 -W ${Math.max(1, Math.ceil(timeout / 1000))} ${ip}`;
  try {
    await execAsync(command, { windowsHide: true });
  } catch {
    // Ignore ping failures; ARP cache might still update.
  }
}

async function pingSweep(ips, { concurrency = 32, timeoutMs = 250 } = {}) {
  if (!Array.isArray(ips) || ips.length === 0) {
    return;
  }
  let index = 0;
  const limit = Math.min(concurrency, ips.length);
  const workers = Array.from({ length: limit }, async () => {
    while (true) {
      const current = index++;
      if (current >= ips.length) {
        break;
      }
      await pingIp(ips[current], timeoutMs);
    }
  });
  await Promise.all(workers);
}

async function readArpTable() {
  const command = process.platform === 'win32' ? 'arp -a' : 'arp -a';
  const { stdout } = await execAsync(command, { windowsHide: true });

  const devices = [];
  const lines = stdout.split('\n');

  for (const line of lines) {
    const ipMatch = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    const macMatch = line.match(/([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})/);

    if (ipMatch && macMatch) {
      const ip = ipMatch[0];
      const mac = normalizeMac(macMatch[0]);

      if (isValidIp(ip) && isValidMac(mac)) {
        devices.push({
          ip,
          mac,
          hostname: null,
          vendor: null
        });
      }
    }
  }

  return devices;
}

/**
 * 获取所有网络接口
 * @returns {Promise<Array>}
 */
export async function listInterfaces() {
  const interfaces = os.networkInterfaces();
  const result = [];

  for (const [name, addresses] of Object.entries(interfaces)) {
    if (!addresses) {
      continue;
    }

    for (const addr of addresses) {
      // 只返回 IPv4 地址
      if (addr.family !== 'IPv4' || addr.internal) {
        continue;
      }

      result.push({
        name,
        ip: addr.address,
        mac: normalizeMac(addr.mac),
        netmask: addr.netmask,
        cidr: addr.cidr,
        isUp: !addr.internal
      });
    }
  }

  return result;
}

/**
 * 获取默认网关
 * @param {string} interfaceName - 网络接口名称
 * @returns {Promise<{ip: string, mac?: string} | null>}
 */
export async function getGateway(interfaceName) {
  try {
    if (process.platform === 'win32') {
      return await getGatewayWindows(interfaceName);
    }
    if (process.platform === 'darwin') {
      return await getGatewayDarwin(interfaceName);
    }
    return null;
  } catch (error) {
    console.error('[scanner] Failed to get gateway:', error);
    return null;
  }
}

/**
 * Windows: 获取网关
 */
async function getGatewayWindows(interfaceName) {
  const { stdout } = await execAsync('route print 0.0.0.0', { windowsHide: true });
  const lines = stdout.split('\n');

  // 查找默认路由 (0.0.0.0)
  for (const line of lines) {
    if (line.includes('0.0.0.0') && line.includes('0.0.0.0')) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3) {
        const gatewayIp = parts[2];
        if (isValidIp(gatewayIp)) {
          // 尝试获取网关 MAC 地址
          const mac = await getMacAddress(gatewayIp);
          return { ip: gatewayIp, mac };
        }
      }
    }
  }

  return null;
}

/**
 * macOS: 获取网关
 */
async function getGatewayDarwin(interfaceName) {
  const { stdout } = await execAsync(`route -n get default`);
  const lines = stdout.split('\n');

  let gatewayIp = null;
  for (const line of lines) {
    if (line.includes('gateway:')) {
      const parts = line.split(':');
      if (parts.length >= 2) {
        gatewayIp = parts[1].trim();
        break;
      }
    }
  }

  if (gatewayIp && isValidIp(gatewayIp)) {
    const mac = await getMacAddress(gatewayIp);
    return { ip: gatewayIp, mac };
  }

  return null;
}

/**
 * 通过 ARP 表获取 MAC 地址
 * @param {string} ip
 * @returns {Promise<string | null>}
 */
async function getMacAddress(ip) {
  try {
    const command = process.platform === 'win32' ? `arp -a ${ip}` : `arp -n ${ip}`;
    const { stdout } = await execAsync(command, { windowsHide: true });

    // 解析 ARP 输出
    const macPattern = /([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})/;
    const match = stdout.match(macPattern);

    if (match && match[0]) {
      return normalizeMac(match[0]);
    }
  } catch (error) {
    // ARP 表中可能没有该 IP
  }

  return null;
}

/**
 * 扫描子网中的设备
 * @param {string} interfaceName - 网络接口名称
 * @param {string} subnet - 子网 CIDR (如 192.168.1.0/24)
 * @returns {Promise<Array>}
 */
export async function scanSubnet(interfaceName, subnet) {
  try {
    const subnetInfo = resolveSubnetInfo(interfaceName, subnet);
    const subnetIps =
      subnetInfo && subnetInfo.netmask ? getSubnetIps(subnetInfo.ip, subnetInfo.netmask) : [];

    if (subnetIps.length > 0) {
      await pingSweep(subnetIps, { concurrency: 32, timeoutMs: 250 });
    }

    const devices = await readArpTable();
    const filtered = subnetInfo
      ? devices.filter((device) => isInSubnet(device.ip, subnetInfo.ip, subnetInfo.netmask))
      : devices;

    const seen = new Set();
    return filtered.filter((device) => {
      if (seen.has(device.ip)) {
        return false;
      }
      seen.add(device.ip);
      return true;
    });
  } catch (error) {
    console.error('[scanner] Failed to scan subnet:', error);
    return [];
  }
}

/**
 * NetworkScanner 类
 */
export class NetworkScanner {
  /**
   * 列出所有网络接口
   */
  async listInterfaces() {
    return listInterfaces();
  }

  /**
   * 扫描子网
   */
  async scanSubnet(interfaceName, subnet) {
    return scanSubnet(interfaceName, subnet);
  }

  /**
   * 获取网关
   */
  async getGateway(interfaceName) {
    return getGateway(interfaceName);
  }
}
