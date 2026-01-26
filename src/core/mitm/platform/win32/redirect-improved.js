/**
 * Windows 流量重定向实现（改进版）
 * 使用 WinDivert 进行真正的透明代理
 */

import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import {
  parseIpHeader,
  parseTcpHeader,
  redirectPacket,
  rewritePacket,
  shouldRedirect
} from './packet-utils.js';
import { buildPortFilter, hasPortSpec, parsePortSpec } from '../../utils/ports.js';

const execAsync = promisify(exec);

const ADDR_FLAG_SNIFFED = 0x01;
const ADDR_FLAG_OUTBOUND = 0x02;
const ADDR_FLAG_LOOPBACK = 0x04;
const ADDR_FLAG_IMPOSTOR = 0x08;

function readAddrFlags(addr) {
  if (!Buffer.isBuffer(addr) || addr.length < 11) {
    return null;
  }
  const flags = addr[10];
  return {
    sniffed: (flags & ADDR_FLAG_SNIFFED) !== 0,
    outbound: (flags & ADDR_FLAG_OUTBOUND) !== 0,
    loopback: (flags & ADDR_FLAG_LOOPBACK) !== 0,
    impostor: (flags & ADDR_FLAG_IMPOSTOR) !== 0
  };
}

function writeAddrFlags(addr, updates = {}) {
  if (!Buffer.isBuffer(addr) || addr.length < 11) {
    return false;
  }
  let flags = addr[10];
  if (typeof updates.sniffed === 'boolean') {
    flags = updates.sniffed ? flags | ADDR_FLAG_SNIFFED : flags & ~ADDR_FLAG_SNIFFED;
  }
  if (typeof updates.outbound === 'boolean') {
    flags = updates.outbound ? flags | ADDR_FLAG_OUTBOUND : flags & ~ADDR_FLAG_OUTBOUND;
  }
  if (typeof updates.loopback === 'boolean') {
    flags = updates.loopback ? flags | ADDR_FLAG_LOOPBACK : flags & ~ADDR_FLAG_LOOPBACK;
  }
  if (typeof updates.impostor === 'boolean') {
    flags = updates.impostor ? flags | ADDR_FLAG_IMPOSTOR : flags & ~ADDR_FLAG_IMPOSTOR;
  }
  addr[10] = flags;
  return true;
}

function quoteNetshName(name) {
  return `"${name.replace(/"/g, '""')}"`;
}

async function resolveInterfaceIndex(interfaceName) {
  const trimmed = interfaceName?.trim();
  if (!trimmed) {
    return null;
  }

  try {
    const { stdout } = await execAsync('netsh interface ipv4 show interfaces', {
      windowsHide: true
    });
    const needle = trimmed.toLowerCase();

    for (const line of stdout.split('\n')) {
      const match = line.trim().match(/^(\d+)\s+\d+\s+\d+\s+\S+\s+(.+)$/);
      if (!match) {
        continue;
      }
      const name = match[2].trim();
      if (name.toLowerCase() === needle) {
        return Number.parseInt(match[1], 10);
      }
    }
  } catch (error) {
    console.warn('[redirect] Failed to resolve interface index:', error.message);
  }

  return null;
}

async function getNetshInterfaceArg(interfaceName) {
  const index = await resolveInterfaceIndex(interfaceName);
  if (Number.isInteger(index)) {
    return String(index);
  }

  const trimmed = interfaceName?.trim();
  if (trimmed) {
    console.warn('[redirect] Interface not found, falling back to name:', trimmed);
    return quoteNetshName(trimmed);
  }

  return quoteNetshName('Ethernet');
}

export class Win32Redirect {
  constructor() {
    this.enabled = false;
    this.windivert = null;
    this.useWinDivert = false;
    this.redirectHandle = null;
    this.redirectThread = null;
    this.responseThread = null;
    this.httpPortSpec = parsePortSpec(80);
    this.httpsPortSpec = parsePortSpec(443);
    this.proxyPort = 8888;
    this.localIp = null;
    this.localHandle = null;
    this.targetIps = [];
    this.connectionMap = new Map();
    this.connectionTtlMs = 5 * 60 * 1000;
    this.lastCleanup = 0;
    this.packetCount = 0;
    this.redirectCount = 0;
    this.netshPorts = [];
  }

  /**
   * 初始化 WinDivert（如果可用）
   */
  async initializeWinDivert() {
    try {
      if (process.env.PACKETFORGE_DISABLE_WINDIVERT === '1') {
        console.warn('[redirect] WinDivert disabled via env');
        this.useWinDivert = false;
        return false;
      }
      console.log('[redirect] Initializing WinDivert...');
      const WinDivert = await import('windivert');
      this.windivert = WinDivert.default || WinDivert;
      this.useWinDivert = true;
      console.log('[redirect] ✓ WinDivert loaded successfully');
      console.log('[redirect] Using WinDivert for traffic redirection');
      return true;
    } catch (error) {
      console.warn('[redirect] ⚠ WinDivert not available:', error.message);
      console.warn('[redirect] Falling back to netsh portproxy');
      this.useWinDivert = false;
      return false;
    }
  }

  /**
   * 启用 IP 转发
   */
  async enableIpForwarding({ interfaceName } = {}) {
    try {
      // 方法 1: 使用 netsh (临时)
      const interfaceArg = await getNetshInterfaceArg(interfaceName);
      await execAsync(
        `netsh interface ipv4 set interface ${interfaceArg} forwarding=enabled`,
        { windowsHide: true }
      );

      // 方法 2: 修改注册表 (永久)
      await execAsync(
        'reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f',
        { windowsHide: true }
      );

      console.log('[redirect] IP forwarding enabled');
    } catch (error) {
      console.error('[redirect] Failed to enable IP forwarding:', error.message);
      throw error;
    }
  }

  /**
   * 禁用 IP 转发
   */
  async disableIpForwarding({ interfaceName } = {}) {
    try {
      const interfaceArg = await getNetshInterfaceArg(interfaceName);
      await execAsync(
        `netsh interface ipv4 set interface ${interfaceArg} forwarding=disabled`,
        { windowsHide: true }
      );

      await execAsync(
        'reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 0 /f',
        { windowsHide: true }
      );

      console.log('[redirect] IP forwarding disabled');
    } catch (error) {
      console.error('[redirect] Failed to disable IP forwarding:', error.message);
    }
  }

  /**
   * 设置端口重定向
   * @param {Object} options
   * @param {number} options.httpPort - HTTP 端口 (默认 80)
   * @param {number} options.httpsPort - HTTPS 端口 (默认 443)
   * @param {number} options.proxyPort - 代理端口
   */
  async setupRedirect({
    httpPort = 80,
    httpsPort = 443,
    httpPorts,
    httpsPorts,
    proxyPort,
    localIp,
    targets = []
  }) {
    console.log('[redirect] Setting up redirect...');
    console.log('[redirect] Configuration:', {
      httpPort,
      httpsPort,
      httpPorts,
      httpsPorts,
      proxyPort,
      localIp
    });

    // 保存配置
    this.httpPortSpec = parsePortSpec(httpPorts ?? httpPort);
    this.httpsPortSpec = parsePortSpec(httpsPorts ?? httpsPort);
    this.proxyPort = proxyPort;
    this.localIp = localIp ?? this.localIp;
    this.targetIps = Array.isArray(targets)
      ? targets.map((target) => target?.ip).filter((ip) => typeof ip === 'string' && ip.length > 0)
      : [];
    if (!this.localIp) {
      console.warn('[redirect] Local IP not set; packets may not reach proxy');
    }
    if (!hasPortSpec(this.httpPortSpec) && !hasPortSpec(this.httpsPortSpec)) {
      throw new Error('No redirect ports configured');
    }

    // 初始化 WinDivert
    await this.initializeWinDivert();

    if (this.useWinDivert) {
      await this.setupRedirectWinDivert({ proxyPort });
    } else {
      await this.setupRedirectNetsh({ proxyPort });
    }

    this.enabled = true;
    console.log('[redirect] ✓ Redirect setup complete');
  }

  /**
   * 使用 WinDivert 设置重定向（推荐）
   */
  async setupRedirectWinDivert({ proxyPort }) {
    try {
      console.log('[redirect] Setting up WinDivert redirection...');

      const portClauses = [];
      const httpClause = buildPortFilter('tcp.DstPort', this.httpPortSpec);
      const httpsClause = buildPortFilter('tcp.DstPort', this.httpsPortSpec);
      if (httpClause) {
        portClauses.push(httpClause);
      }
      if (httpsClause) {
        portClauses.push(httpsClause);
      }
      if (portClauses.length === 0) {
        throw new Error('No redirect ports configured');
      }
      const portClause =
        portClauses.length === 1 ? portClauses[0] : `(${portClauses.join(' or ')})`;
      const forwardFilterParts = ['!impostor', `(${portClause})`];
      if (this.targetIps.length > 0) {
        const targetClause = this.targetIps.map((ip) => `ip.SrcAddr == ${ip}`).join(' or ');
        forwardFilterParts.push(`(${targetClause})`);
      }
      if (this.localIp) {
        forwardFilterParts.push(`ip.SrcAddr != ${this.localIp}`);
      }
      const forwardFilter = forwardFilterParts.join(' and ');
      console.log('[redirect] WinDivert filter:', forwardFilter);

      console.log('[redirect] Opening WinDivert forward handle...');
      if (!this.windivert?.createWindivert) {
        throw new Error('WinDivert module missing createWindivert API');
      }
      const forwardLayer =
        this.windivert.LAYERS?.NETWORK_FORWARD ?? this.windivert.LAYERS?.NETWORK ?? 0;
      this.redirectHandle = await this.windivert.createWindivert(
        forwardFilter,
        forwardLayer,
        this.windivert.FLAGS?.DEFAULT ?? 0
      );
      if (typeof this.redirectHandle?.open !== 'function') {
        throw new Error('WinDivert handle does not support open()');
      }
      this.redirectHandle.open();
      console.log('[redirect] ? WinDivert forward handle opened');

      const responseFilterParts = ['outbound', '!loopback', '!impostor', `tcp.SrcPort == ${proxyPort}`];
      if (this.localIp) {
        responseFilterParts.push(`ip.SrcAddr == ${this.localIp}`);
      }
      const responseFilter = responseFilterParts.join(' and ');
      console.log('[redirect] WinDivert response filter:', responseFilter);

      console.log('[redirect] Opening WinDivert response handle...');
      const responseLayer = this.windivert.LAYERS?.NETWORK ?? forwardLayer;
      this.localHandle = await this.windivert.createWindivert(
        responseFilter,
        responseLayer,
        this.windivert.FLAGS?.DEFAULT ?? 0
      );
      if (typeof this.localHandle?.open !== 'function') {
        throw new Error('WinDivert response handle does not support open()');
      }
      this.localHandle.open();
      console.log('[redirect] ? WinDivert response handle opened');

      console.log('[redirect] Starting redirect loop...');
      this.redirectThread = this.startRedirectLoop(proxyPort);
      console.log('[redirect] Redirect loop started');

      console.log('[redirect] Starting response loop...');
      this.responseThread = this.startResponseLoop();
      console.log('[redirect] Response loop started');
    } catch (error) {
      console.error('[redirect] ? Failed to setup WinDivert:', error.message);
      throw error;
    }
  }

  sendPacket(handle, packet, addr, flags) {
    if (!handle || typeof handle.send !== 'function') {
      return false;
    }
    if (!Buffer.isBuffer(packet) || !Buffer.isBuffer(addr)) {
      return false;
    }
    const sendAddr = Buffer.from(addr);
    if (!writeAddrFlags(sendAddr, flags)) {
      return false;
    }
    try {
      if (typeof handle.HelperCalcChecksums === 'function') {
        handle.HelperCalcChecksums({ packet }, 0);
      }
      handle.send({ packet, addr: sendAddr });
      return true;
    } catch (error) {
      console.error('[redirect] Packet send failed:', error.message);
      return false;
    }
  }

  startRedirectLoop(proxyPort) {
    const addReceiveListener = this.windivert?.addReceiveListener;
    if (typeof addReceiveListener !== 'function') {
      console.warn('[redirect] WinDivert addReceiveListener not available');
      return null;
    }

    const localIp = this.localIp ?? '127.0.0.1';

    addReceiveListener(this.redirectHandle, (packet, addr) => {
      try {
        const addrFlags = readAddrFlags(addr);
        if (addrFlags?.loopback || addrFlags?.impostor) {
          return false;
        }

        const ipHeader = parseIpHeader(packet);
        if (ipHeader.protocol !== 6) {
          return undefined;
        }
        const tcpHeader = parseTcpHeader(packet, ipHeader.ihl);
        if (!shouldRedirect(packet, this.httpPortSpec, this.httpsPortSpec)) {
          return undefined;
        }

        this.packetCount++;
        const now = Date.now();
        const clientKey = `${ipHeader.srcIp}:${tcpHeader.srcPort}`;
        this.connectionMap.set(clientKey, {
          serverIp: ipHeader.dstIp,
          serverPort: tcpHeader.dstPort,
          lastSeen: now
        });
        this.cleanupConnections(now);

        this.redirectCount++;
        if (this.redirectCount % 100 === 0) {
          console.log(
            `[redirect] Stats: ${this.redirectCount} redirected / ${this.packetCount} total packets`
          );
        }

        const redirected = redirectPacket(packet, proxyPort, localIp);
        const sent = this.sendPacket(this.localHandle, redirected, addr, {
          outbound: false,
          loopback: false,
          impostor: true
        });
        return sent ? false : undefined;
      } catch (error) {
        console.error('[redirect] ? Redirect loop error:', error.message);
        return undefined;
      }
    });

    return true;
  }

  startResponseLoop() {
    const addReceiveListener = this.windivert?.addReceiveListener;
    if (typeof addReceiveListener !== 'function') {
      console.warn('[redirect] WinDivert addReceiveListener not available');
      return null;
    }

    addReceiveListener(this.localHandle, (packet, addr) => {
      try {
        const addrFlags = readAddrFlags(addr);
        if (addrFlags?.loopback || addrFlags?.impostor) {
          return false;
        }

        const ipHeader = parseIpHeader(packet);
        if (ipHeader.protocol !== 6) {
          return undefined;
        }
        const tcpHeader = parseTcpHeader(packet, ipHeader.ihl);
        if (tcpHeader.srcPort !== this.proxyPort) {
          return undefined;
        }

        const clientKey = `${ipHeader.dstIp}:${tcpHeader.dstPort}`;
        const mapping = this.connectionMap.get(clientKey);
        if (!mapping) {
          return undefined;
        }

        const now = Date.now();
        mapping.lastSeen = now;
        this.cleanupConnections(now);

        const rewritten = rewritePacket(packet, {
          srcIp: mapping.serverIp,
          srcPort: mapping.serverPort
        });
        const sent = this.sendPacket(this.localHandle, rewritten, addr, {
          outbound: true,
          loopback: false,
          impostor: true
        });
        return sent ? false : undefined;
      } catch (error) {
        console.error('[redirect] ? Return loop error:', error.message);
        return undefined;
      }
    });

    return true;
  }

  cleanupConnections(now = Date.now()) {
    if (now - this.lastCleanup < 10000) {
      return;
    }
    for (const [key, value] of this.connectionMap.entries()) {
      if (now - value.lastSeen > this.connectionTtlMs) {
        this.connectionMap.delete(key);
      }
    }
    this.lastCleanup = now;
  }

  /**
   * 使用 netsh 设置重定向（回退方案）
   */
  async setupRedirectNetsh({ proxyPort }) {
    try {
      console.log('[redirect] Using netsh portproxy (limited functionality)');

      const ports = this.collectNetshPorts();
      for (const port of ports) {
        const command = `netsh interface portproxy add v4tov4 listenport=${port} listenaddress=0.0.0.0 connectport=${proxyPort} connectaddress=127.0.0.1`;
        await execAsync(command, { windowsHide: true });
      }
      this.netshPorts = ports;

      console.log('[redirect] netsh port redirection enabled');
    } catch (error) {
      console.error('[redirect] Failed to setup netsh redirect:', error.message);
      throw error;
    }
  }

  /**
   * 清除端口重定向
   */
  async clearRedirect() {
    this.enabled = false;
    console.log('[redirect] Clearing redirect...');

    if (this.useWinDivert && this.redirectHandle) {
      try {
        console.log('[redirect] Closing WinDivert handle...');
        // 关闭 WinDivert 句柄
        if (typeof this.redirectHandle.close === 'function') {
          this.redirectHandle.close();
        }
        this.redirectHandle = null;
        this.redirectThread = null;
        this.responseThread = null;
        if (this.localHandle && typeof this.localHandle.close === 'function') {
          this.localHandle.close();
        }
        this.localHandle = null;
        console.log('[redirect] ✓ WinDivert redirection cleared');
        console.log(
          `[redirect] Final stats: ${this.redirectCount} redirected / ${this.packetCount} total packets`
        );
      } catch (error) {
        console.error('[redirect] ✗ Failed to close WinDivert:', error.message);
      }
    } else {
      // 清除 netsh 规则
      try {
        console.log('[redirect] Clearing netsh rules...');
        const ports = this.netshPorts.length > 0 ? this.netshPorts : [80];
        for (const port of ports) {
          await execAsync(
            `netsh interface portproxy delete v4tov4 listenport=${port} listenaddress=0.0.0.0`,
            { windowsHide: true }
          );
        }
        console.log('[redirect] ✓ netsh port redirection cleared');
      } catch (error) {
        console.error('[redirect] ✗ Failed to clear netsh redirect:', error.message);
      }
    }

    // 重置计数器
    this.connectionMap.clear();
    this.packetCount = 0;
    this.redirectCount = 0;
    this.netshPorts = [];
  }

  collectNetshPorts() {
    const ports = [];
    const addPorts = (spec) => {
      for (const port of spec?.ports || []) {
        if (!ports.includes(port)) {
          ports.push(port);
        }
      }
      for (const range of spec?.ranges || []) {
        const size = range.end - range.start + 1;
        if (size > 256) {
          throw new Error('netsh portproxy does not support large ranges');
        }
        for (let port = range.start; port <= range.end; port += 1) {
          if (!ports.includes(port)) {
            ports.push(port);
          }
        }
      }
    };

    if (hasPortSpec(this.httpPortSpec)) {
      addPorts(this.httpPortSpec);
    }
    if (hasPortSpec(this.httpsPortSpec)) {
      addPorts(this.httpsPortSpec);
    }

    if (ports.length === 0) {
      throw new Error('No ports available for netsh redirection');
    }
    return ports;
  }

  /**
   * 检查重定向状态
   */
  async status() {
    return {
      enabled: this.enabled,
      method: this.useWinDivert ? 'WinDivert' : 'netsh',
      windivertAvailable: this.useWinDivert,
      httpPorts: this.httpPortSpec,
      httpsPorts: this.httpsPortSpec,
      stats: {
        packetCount: this.packetCount,
        redirectCount: this.redirectCount
      }
    };
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
