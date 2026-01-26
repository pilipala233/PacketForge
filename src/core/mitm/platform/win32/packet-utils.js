import { bytesToIp, ipToBytes } from '../../utils/ip-utils.js';
import { hasPortSpec, portMatches } from '../../utils/ports.js';

function toBuffer(packet) {
  return Buffer.isBuffer(packet) ? packet : Buffer.from(packet);
}

export function parseIpHeader(packet) {
  const buffer = toBuffer(packet);
  if (buffer.length < 20) {
    throw new Error('IP packet too short');
  }
  const versionIhl = buffer[0];
  const version = versionIhl >> 4;
  const ihl = (versionIhl & 0x0f) * 4;
  if (version !== 4 || ihl < 20 || buffer.length < ihl) {
    throw new Error('Invalid IPv4 header');
  }
  const protocol = buffer[9];
  const srcIp = bytesToIp(Array.from(buffer.slice(12, 16)));
  const dstIp = bytesToIp(Array.from(buffer.slice(16, 20)));
  return { version, ihl, protocol, srcIp, dstIp };
}

export function parseTcpHeader(packet, ipHeaderLength) {
  const buffer = toBuffer(packet);
  const offset =
    Number.isFinite(ipHeaderLength) && ipHeaderLength >= 20
      ? ipHeaderLength
      : (buffer[0] & 0x0f) * 4;
  if (buffer.length < offset + 20) {
    throw new Error('TCP packet too short');
  }
  const srcPort = buffer.readUInt16BE(offset);
  const dstPort = buffer.readUInt16BE(offset + 2);
  const dataOffset = (buffer[offset + 12] >> 4) * 4;
  return { srcPort, dstPort, dataOffset, offset };
}

function writeIp(buffer, offset, ip) {
  const bytes = ipToBytes(ip);
  if (bytes.length !== 4) {
    return;
  }
  for (let i = 0; i < 4; i++) {
    buffer[offset + i] = bytes[i];
  }
}

export function rewritePacket(packet, { srcIp, srcPort, dstIp, dstPort } = {}) {
  const buffer = Buffer.from(packet);

  try {
    // 解析 IP 头
    const ipHeader = parseIpHeader(buffer);

    // 只处理 TCP 协议
    if (ipHeader.protocol !== 6) {
      return buffer;
    }

    // 解析 TCP 头（确保偏移正确）
    parseTcpHeader(buffer, ipHeader.ihl);

    if (srcIp) {
      writeIp(buffer, 12, srcIp);
    }
    if (dstIp) {
      writeIp(buffer, 16, dstIp);
    }
    if (Number.isInteger(srcPort)) {
      buffer.writeUInt16BE(srcPort, ipHeader.ihl + 0);
    }
    if (Number.isInteger(dstPort)) {
      buffer.writeUInt16BE(dstPort, ipHeader.ihl + 2);
    }

    // 重新计算 IP 校验和
    buffer.writeUInt16BE(0, 10);
    const ipChecksum = calculateChecksum(buffer, 0, ipHeader.ihl);
    buffer.writeUInt16BE(ipChecksum, 10);

    // 重新计算 TCP 校验和
    buffer.writeUInt16BE(0, ipHeader.ihl + 16);
    const tcpChecksum = calculateTcpChecksum(buffer, ipHeader.ihl);
    buffer.writeUInt16BE(tcpChecksum, ipHeader.ihl + 16);

    return buffer;
  } catch (error) {
    console.error('[packet] Failed to rewrite packet:', error.message);
    return buffer;
  }
}

export function redirectPacket(packet, proxyPort, targetIp = '127.0.0.1') {
  return rewritePacket(packet, { dstIp: targetIp, dstPort: proxyPort });
}

/**
 * 计算 IP 校验和
 */
export function calculateChecksum(buffer, offset, length) {
  let sum = 0;

  for (let i = offset; i < offset + length; i += 2) {
    if (i + 1 < offset + length) {
      sum += buffer.readUInt16BE(i);
    } else {
      sum += buffer[i] << 8;
    }
  }

  // 处理进位
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return ~sum & 0xffff;
}

/**
 * 计算 TCP 校验和
 */
export function calculateTcpChecksum(buffer, ipHeaderLength) {
  // 解析 IP 头获取源/目标 IP
  const srcIp = buffer.slice(12, 16);
  const dstIp = buffer.slice(16, 20);
  const protocol = buffer[9];
  const tcpLength = buffer.readUInt16BE(2) - ipHeaderLength;

  // 构造伪头部
  const pseudoHeader = Buffer.alloc(12);
  srcIp.copy(pseudoHeader, 0);
  dstIp.copy(pseudoHeader, 4);
  pseudoHeader[8] = 0;
  pseudoHeader[9] = protocol;
  pseudoHeader.writeUInt16BE(tcpLength, 10);

  // 计算校验和
  let sum = 0;

  // 伪头部
  for (let i = 0; i < 12; i += 2) {
    sum += pseudoHeader.readUInt16BE(i);
  }

  // TCP 头和数据
  const tcpStart = ipHeaderLength;
  const tcpEnd = buffer.length;

  for (let i = tcpStart; i < tcpEnd; i += 2) {
    if (i + 1 < tcpEnd) {
      sum += buffer.readUInt16BE(i);
    } else {
      sum += buffer[i] << 8;
    }
  }

  // 处理进位
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return ~sum & 0xffff;
}

/**
 * 检查数据包是否需要重定向
 */
export function shouldRedirect(packet, httpSpec, httpsSpec) {
  try {
    const ipHeader = parseIpHeader(packet);

    if (ipHeader.protocol !== 6) {
      return false; // 只处理 TCP
    }

    const tcpHeader = parseTcpHeader(packet, ipHeader.ihl);
    const port = tcpHeader.dstPort;
    if (hasPortSpec(httpSpec) && portMatches(port, httpSpec)) {
      return true;
    }
    if (hasPortSpec(httpsSpec) && portMatches(port, httpsSpec)) {
      return true;
    }
    return false;
  } catch (error) {
    return false;
  }
}
