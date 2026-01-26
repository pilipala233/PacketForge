import { EventEmitter } from 'node:events';
import { parseIpHeader, parseTcpHeader } from './packet-utils.js';
import { bytesToIp } from '../../utils/ip-utils.js';
import { hasPortSpec, portMatches } from '../../utils/ports.js';

const PROTOCOL_TCP = 6;
const PROTOCOL_UDP = 17;
const ADDR_FLAG_LOOPBACK = 0x04;
const ADDR_FLAG_IMPOSTOR = 0x08;

function readAddrFlags(addr) {
  if (!Buffer.isBuffer(addr) || addr.length < 11) {
    return null;
  }
  const flags = addr[10];
  return {
    loopback: (flags & ADDR_FLAG_LOOPBACK) !== 0,
    impostor: (flags & ADDR_FLAG_IMPOSTOR) !== 0
  };
}

function parseUdpHeader(packet, offset) {
  if (!Buffer.isBuffer(packet) || packet.length < offset + 8) {
    throw new Error('UDP packet too short');
  }
  const srcPort = packet.readUInt16BE(offset);
  const dstPort = packet.readUInt16BE(offset + 2);
  const length = packet.readUInt16BE(offset + 4);
  return { srcPort, dstPort, length, offset };
}

function readDnsName(buffer, offset, depth = 0) {
  if (!Buffer.isBuffer(buffer) || offset >= buffer.length) {
    return { name: '', nextOffset: offset };
  }
  if (depth > 6) {
    return { name: '', nextOffset: offset + 1 };
  }

  const labels = [];
  let cursor = offset;
  let nextOffset = offset;
  let jumped = false;

  while (cursor < buffer.length) {
    const length = buffer[cursor];
    if (length === 0) {
      if (!jumped) {
        nextOffset = cursor + 1;
      }
      break;
    }
    if ((length & 0xc0) === 0xc0) {
      if (cursor + 1 >= buffer.length) {
        break;
      }
      const pointer = ((length & 0x3f) << 8) | buffer[cursor + 1];
      if (!jumped) {
        nextOffset = cursor + 2;
      }
      const pointed = readDnsName(buffer, pointer, depth + 1);
      if (pointed.name) {
        labels.push(pointed.name);
      }
      jumped = true;
      break;
    }

    const labelStart = cursor + 1;
    const labelEnd = labelStart + length;
    if (labelEnd > buffer.length) {
      break;
    }
    labels.push(buffer.slice(labelStart, labelEnd).toString('ascii'));
    cursor = labelEnd;
    if (!jumped) {
      nextOffset = cursor;
    }
  }

  return { name: labels.join('.'), nextOffset };
}

function readUint24(buffer, offset) {
  if (!Buffer.isBuffer(buffer) || offset + 3 > buffer.length) {
    return null;
  }
  return (buffer[offset] << 16) | (buffer[offset + 1] << 8) | buffer[offset + 2];
}

function extractTlsSni(payload) {
  if (!Buffer.isBuffer(payload) || payload.length < 5) {
    return '';
  }
  if (payload[0] !== 0x16 || payload[1] !== 0x03) {
    return '';
  }
  const recordLength = payload.readUInt16BE(3);
  if (payload.length < 5 + recordLength) {
    return '';
  }

  let offset = 5;
  if (payload[offset] !== 0x01) {
    return '';
  }
  const handshakeLength = readUint24(payload, offset + 1);
  if (!Number.isFinite(handshakeLength)) {
    return '';
  }
  offset += 4;
  if (payload.length < offset + handshakeLength) {
    return '';
  }

  if (offset + 2 + 32 > payload.length) {
    return '';
  }
  offset += 2 + 32;
  if (offset >= payload.length) {
    return '';
  }

  const sessionIdLength = payload[offset];
  offset += 1 + sessionIdLength;
  if (offset + 2 > payload.length) {
    return '';
  }

  const cipherLength = payload.readUInt16BE(offset);
  offset += 2 + cipherLength;
  if (offset >= payload.length) {
    return '';
  }

  const compressionLength = payload[offset];
  offset += 1 + compressionLength;
  if (offset + 2 > payload.length) {
    return '';
  }

  const extensionLength = payload.readUInt16BE(offset);
  offset += 2;
  const extensionEnd = offset + extensionLength;

  while (offset + 4 <= extensionEnd && offset + 4 <= payload.length) {
    const extensionType = payload.readUInt16BE(offset);
    offset += 2;
    const extensionSize = payload.readUInt16BE(offset);
    offset += 2;
    if (offset + extensionSize > payload.length) {
      return '';
    }

    if (extensionType === 0x0000) {
      if (offset + 2 > payload.length) {
        return '';
      }
      const listLength = payload.readUInt16BE(offset);
      offset += 2;
      const listEnd = offset + listLength;
      while (offset + 3 <= listEnd && offset + 3 <= payload.length) {
        const nameType = payload[offset];
        offset += 1;
        const nameLength = payload.readUInt16BE(offset);
        offset += 2;
        if (offset + nameLength > payload.length) {
          return '';
        }
        if (nameType === 0x00) {
          return payload.slice(offset, offset + nameLength).toString('ascii');
        }
        offset += nameLength;
      }
    }

    offset += extensionSize;
  }

  return '';
}

function parseDnsMessage(payload) {
  if (!Buffer.isBuffer(payload) || payload.length < 12) {
    return null;
  }

  const id = payload.readUInt16BE(0);
  const flags = payload.readUInt16BE(2);
  const qdcount = payload.readUInt16BE(4);
  const ancount = payload.readUInt16BE(6);
  const isResponse = (flags & 0x8000) !== 0;

  let offset = 12;
  const questions = [];
  for (let i = 0; i < qdcount; i += 1) {
    const parsed = readDnsName(payload, offset);
    offset = parsed.nextOffset;
    if (offset + 4 > payload.length) {
      break;
    }
    const qtype = payload.readUInt16BE(offset);
    const qclass = payload.readUInt16BE(offset + 2);
    offset += 4;
    questions.push({ name: parsed.name, type: qtype, class: qclass });
  }

  const answers = [];
  for (let i = 0; i < ancount; i += 1) {
    const parsed = readDnsName(payload, offset);
    offset = parsed.nextOffset;
    if (offset + 10 > payload.length) {
      break;
    }
    const type = payload.readUInt16BE(offset);
    const klass = payload.readUInt16BE(offset + 2);
    const ttl = payload.readUInt32BE(offset + 4);
    const rdlength = payload.readUInt16BE(offset + 8);
    offset += 10;
    if (offset + rdlength > payload.length) {
      break;
    }
    const rdata = payload.slice(offset, offset + rdlength);
    offset += rdlength;
    answers.push({ name: parsed.name, type, class: klass, ttl, rdata });
  }

  return { id, isResponse, questions, answers };
}

function formatHostLabel(hostname, ip) {
  if (!hostname) {
    return ip;
  }
  if (!ip) {
    return hostname;
  }
  return `${hostname} (${ip})`;
}

export class Win32FlowMonitor extends EventEmitter {
  constructor() {
    super();
    this.windivert = null;
    this.handle = null;
    this.running = false;
    this.targetIps = [];
    this.monitorUdp = true;
    this.monitorTcp = false;
    this.ignorePortSpec = null;
    this.localIp = null;
    this.proxyPort = null;
    this.flowIdleMs = 15000;
    this.flowMaxMs = 60000;
    this.cleanupInterval = null;
    this.flowMap = new Map();
    this.dnsCache = new Map();
    this.pendingDns = new Map();
    this.packetCount = 0;
    this.loggedFirstPacket = false;
  }

  async initializeWinDivert() {
    try {
      const WinDivert = await import('windivert');
      this.windivert = WinDivert.default || WinDivert;
      return true;
    } catch (error) {
      console.warn('[monitor] WinDivert not available:', error.message);
      return false;
    }
  }

  buildFilter() {
    const protoParts = [];
    if (this.monitorUdp) {
      protoParts.push('udp');
    }
    if (this.monitorTcp) {
      protoParts.push('tcp');
    }
    if (protoParts.length === 0) {
      throw new Error('No protocols enabled for monitoring');
    }
    const protoClause = protoParts.length === 1 ? protoParts[0] : `(${protoParts.join(' or ')})`;
    const targetClause = this.targetIps
      .map((ip) => `(ip.SrcAddr == ${ip} or ip.DstAddr == ${ip})`)
      .join(' or ');
    if (!targetClause) {
      throw new Error('No targets configured for monitoring');
    }
    return `ip and ${protoClause} and (${targetClause})`;
  }

  startCleanupLoop() {
    if (this.cleanupInterval) {
      return;
    }
    this.cleanupInterval = setInterval(() => {
      this.cleanupFlows();
    }, 5000);
  }

  stopCleanupLoop() {
    if (!this.cleanupInterval) {
      return;
    }
    clearInterval(this.cleanupInterval);
    this.cleanupInterval = null;
  }

  async start({
    targets = [],
    monitorUdp = true,
    monitorTcp = false,
    ignorePortSpec = null,
    localIp = null,
    proxyPort = null,
    flowIdleMs = null,
    flowMaxMs = null
  } = {}) {
    if (this.running) {
      return this.status();
    }
    this.targetIps = Array.isArray(targets)
      ? targets.map((target) => target?.ip).filter((ip) => typeof ip === 'string' && ip.length > 0)
      : [];
    this.monitorUdp = Boolean(monitorUdp);
    this.monitorTcp = Boolean(monitorTcp);
    this.ignorePortSpec = ignorePortSpec;
    this.localIp = typeof localIp === 'string' && localIp.trim() ? localIp.trim() : null;
    const proxyPortValue = Number.isFinite(proxyPort)
      ? Math.trunc(proxyPort)
      : Number.parseInt(proxyPort, 10);
    this.proxyPort =
      Number.isInteger(proxyPortValue) && proxyPortValue > 0 ? proxyPortValue : null;
    if (Number.isFinite(flowIdleMs) && flowIdleMs > 0) {
      this.flowIdleMs = Math.max(1000, Math.trunc(flowIdleMs));
    }
    if (Number.isFinite(flowMaxMs) && flowMaxMs > 0) {
      this.flowMaxMs = Math.max(this.flowIdleMs, Math.trunc(flowMaxMs));
    }

    const ready = await this.initializeWinDivert();
    if (!ready) {
      throw new Error('WinDivert not available for monitoring');
    }
    if (!this.windivert?.createWindivert) {
      throw new Error('WinDivert module missing createWindivert API');
    }

    const filter = this.buildFilter();
    console.log('[monitor] WinDivert filter:', filter);
    const layer =
      this.windivert.LAYERS?.NETWORK_FORWARD ?? this.windivert.LAYERS?.NETWORK ?? 0;
    const flags = this.windivert.FLAGS?.SNIFF ?? 0x0001;
    this.handle = await this.windivert.createWindivert(filter, layer, flags);
    if (typeof this.handle?.open !== 'function') {
      throw new Error('WinDivert handle does not support open()');
    }
    this.handle.open();

    const addReceiveListener = this.windivert?.addReceiveListener;
    if (typeof addReceiveListener === 'function') {
      addReceiveListener(this.handle, (packet, addr) => {
        const flags = readAddrFlags(addr);
        if (flags?.loopback || flags?.impostor) {
          return;
        }
        this.handlePacket(packet);
      });
    } else if (typeof this.handle.recv === 'function') {
      this.handle.recv((packet) => {
        this.handlePacket(packet);
      });
    } else {
      throw new Error('WinDivert handle does not support recv()');
    }

    this.startCleanupLoop();
    this.running = true;
    return this.status();
  }

  async stop({ flush = true } = {}) {
    if (!this.running) {
      return this.status();
    }
    this.stopCleanupLoop();
    if (flush) {
      this.flushAllFlows();
    }
    if (this.handle && typeof this.handle.close === 'function') {
      try {
        this.handle.close();
      } catch (error) {
        console.warn('[monitor] Failed to close WinDivert handle:', error.message);
      }
    }
    this.handle = null;
    this.running = false;
    this.flowMap.clear();
    this.pendingDns.clear();
    this.dnsCache.clear();
    return this.status();
  }

  status() {
    return {
      running: this.running,
      targets: this.targetIps,
      monitorUdp: this.monitorUdp,
      monitorTcp: this.monitorTcp,
      ignorePortSpec: this.ignorePortSpec,
      localIp: this.localIp,
      proxyPort: this.proxyPort,
      activeFlows: this.flowMap.size
    };
  }

  handlePacket(packet) {
    if (!Buffer.isBuffer(packet)) {
      return;
    }
    this.packetCount += 1;
    if (!this.loggedFirstPacket) {
      this.loggedFirstPacket = true;
      console.log('[monitor] First packet captured');
    }

    let ipHeader;
    try {
      ipHeader = parseIpHeader(packet);
    } catch (_error) {
      return;
    }

    const protocol = ipHeader.protocol;
    if (protocol === PROTOCOL_UDP && !this.monitorUdp) {
      return;
    }
    if (protocol === PROTOCOL_TCP && !this.monitorTcp) {
      return;
    }
    if (protocol !== PROTOCOL_UDP && protocol !== PROTOCOL_TCP) {
      return;
    }

    const srcIp = ipHeader.srcIp;
    const dstIp = ipHeader.dstIp;
    const isOutbound = this.targetIps.includes(srcIp);
    const isInbound = this.targetIps.includes(dstIp);
    if (!isOutbound && !isInbound) {
      return;
    }

    let srcPort;
    let dstPort;
    let tcpHeader;
    let tcpPayload;
    try {
      if (protocol === PROTOCOL_UDP) {
        const udpHeader = parseUdpHeader(packet, ipHeader.ihl);
        srcPort = udpHeader.srcPort;
        dstPort = udpHeader.dstPort;
        this.inspectDns(packet, ipHeader, udpHeader);
      } else {
        tcpHeader = parseTcpHeader(packet, ipHeader.ihl);
        srcPort = tcpHeader.srcPort;
        dstPort = tcpHeader.dstPort;
        const payloadOffset = tcpHeader.offset + tcpHeader.dataOffset;
        if (payloadOffset < packet.length) {
          tcpPayload = packet.slice(payloadOffset);
        }
      }
    } catch (_error) {
      return;
    }

    const clientIp = isOutbound ? srcIp : dstIp;
    const clientPort = isOutbound ? srcPort : dstPort;
    const serverIp = isOutbound ? dstIp : srcIp;
    const serverPort = isOutbound ? dstPort : srcPort;
    if (
      this.localIp &&
      this.proxyPort &&
      serverIp === this.localIp &&
      serverPort === this.proxyPort
    ) {
      return;
    }
    if (hasPortSpec(this.ignorePortSpec) && portMatches(serverPort, this.ignorePortSpec)) {
      return;
    }
    const protoName = protocol === PROTOCOL_UDP ? 'udp' : 'tcp';
    const key = `${protoName}:${clientIp}:${clientPort}-${serverIp}:${serverPort}`;

    const now = Date.now();
    const bytes = packet.length;
    let flow = this.flowMap.get(key);
    const isNewFlow = !flow;
    if (!flow) {
      flow = {
        protocol: protoName,
        clientIp,
        clientPort,
        serverIp,
        serverPort,
        bytes: 0,
        packets: 0,
        firstSeen: now,
        lastSeen: now,
        tlsServerName: ''
      };
      this.flowMap.set(key, flow);
    }
    flow.bytes += bytes;
    flow.packets += 1;
    flow.lastSeen = now;

    if (protocol === PROTOCOL_TCP && isOutbound && isNewFlow && tcpPayload?.length) {
      const sni = extractTlsSni(tcpPayload);
      if (sni) {
        flow.tlsServerName = sni;
        this.dnsCache.set(serverIp, { name: sni, lastSeen: now });
      }
    }
  }

  inspectDns(packet, ipHeader, udpHeader) {
    const udpPayloadOffset = ipHeader.ihl + 8;
    if (udpPayloadOffset >= packet.length) {
      return;
    }
    const payload = packet.slice(udpPayloadOffset);
    const message = parseDnsMessage(payload);
    if (!message) {
      return;
    }

    const now = Date.now();
    const srcIp = ipHeader.srcIp;
    const dstIp = ipHeader.dstIp;
    const srcPort = udpHeader.srcPort;
    const dstPort = udpHeader.dstPort;

    const queryKey = `${srcIp}|${dstIp}|${message.id}`;
    const responseKey = `${dstIp}|${srcIp}|${message.id}`;

    if (!message.isResponse && dstPort === 53) {
      const name = message.questions[0]?.name;
      if (name) {
        this.pendingDns.set(queryKey, { name, timestamp: now });
      }
      return;
    }

    if (message.isResponse && srcPort === 53) {
      const pending = this.pendingDns.get(responseKey);
      if (pending) {
        this.pendingDns.delete(responseKey);
      }
      const fallbackName = pending?.name || message.questions[0]?.name || '';
      for (const answer of message.answers) {
        if (answer.type === 1 && answer.rdata.length === 4) {
          const ip = bytesToIp([...answer.rdata]);
          const name = fallbackName || answer.name;
          if (ip && name) {
            this.dnsCache.set(ip, { name, lastSeen: now });
          }
        }
      }
    }
  }

  cleanupFlows() {
    const now = Date.now();
    for (const [key, flow] of this.flowMap.entries()) {
      const idle = now - flow.lastSeen;
      const age = now - flow.firstSeen;
      if (idle >= this.flowIdleMs) {
        this.flushFlow(key, flow, 'idle');
        this.flowMap.delete(key);
        continue;
      }
      if (age >= this.flowMaxMs) {
        this.flushFlow(key, flow, 'rollover');
        flow.firstSeen = now;
        flow.bytes = 0;
        flow.packets = 0;
      }
    }

    for (const [key, entry] of this.pendingDns.entries()) {
      if (now - entry.timestamp > 10000) {
        this.pendingDns.delete(key);
      }
    }

    for (const [ip, entry] of this.dnsCache.entries()) {
      if (now - entry.lastSeen > 10 * 60 * 1000) {
        this.dnsCache.delete(ip);
      }
    }
  }

  flushAllFlows() {
    for (const [key, flow] of this.flowMap.entries()) {
      this.flushFlow(key, flow, 'stop');
    }
    this.flowMap.clear();
  }

  flushFlow(_key, flow, _reason) {
    if (!flow || flow.bytes <= 0) {
      return;
    }
    const durationMs = Math.max(1, flow.lastSeen - flow.firstSeen);
    const dnsEntry = this.dnsCache.get(flow.serverIp);
    const tlsName = flow.tlsServerName || dnsEntry?.name || '';
    const hostLabel = formatHostLabel(tlsName, flow.serverIp);
    const url = `${flow.protocol}://${hostLabel}:${flow.serverPort}`;
    this.emit('flow', {
      protocol: flow.protocol,
      url,
      sizeBytes: flow.bytes,
      durationMs,
      serverIp: flow.serverIp,
      serverPort: flow.serverPort,
      tlsServerName: tlsName || undefined
    });
  }
}
