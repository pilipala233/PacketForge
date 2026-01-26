import { EventEmitter } from 'node:events';
import { parseIpHeader } from './packet-utils.js';

const ADDR_FLAG_OUTBOUND = 0x02;
const ADDR_FLAG_LOOPBACK = 0x04;
const ADDR_FLAG_IMPOSTOR = 0x08;

const MAX_QUEUE_PACKETS = 2000;
const FLUSH_INTERVAL_MS = 20;

function readAddrFlags(addr) {
  if (!Buffer.isBuffer(addr) || addr.length < 11) {
    return null;
  }
  const flags = addr[10];
  return {
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

class TokenBucket {
  constructor(rateBytesPerSec) {
    this.rate = Number.isFinite(rateBytesPerSec) ? Math.max(0, rateBytesPerSec) : 0;
    this.capacity = this.rate;
    this.tokens = this.capacity;
    this.lastRefill = Date.now();
  }

  refill(now = Date.now()) {
    if (this.rate <= 0) {
      this.tokens = Infinity;
      this.lastRefill = now;
      return;
    }
    const deltaMs = Math.max(0, now - this.lastRefill);
    if (deltaMs === 0) {
      return;
    }
    const add = (this.rate * deltaMs) / 1000;
    this.tokens = Math.min(this.capacity, this.tokens + add);
    this.lastRefill = now;
  }

  consume(bytes, now = Date.now()) {
    this.refill(now);
    if (this.tokens >= bytes) {
      this.tokens -= bytes;
      return true;
    }
    return false;
  }
}

export class Win32TrafficShaper extends EventEmitter {
  constructor() {
    super();
    this.windivert = null;
    this.handle = null;
    this.running = false;
    this.targetIps = [];
    this.uploadRate = 0;
    this.downloadRate = 0;
    this.buckets = new Map();
    this.queues = new Map();
    this.flushTimer = null;
    this.stats = {
      queued: 0,
      sent: 0,
      dropped: 0
    };
  }

  async initializeWinDivert() {
    try {
      const WinDivert = await import('windivert');
      this.windivert = WinDivert.default || WinDivert;
      return true;
    } catch (error) {
      console.warn('[shaper] WinDivert not available:', error.message);
      return false;
    }
  }

  buildFilter() {
    const targetClause = this.targetIps
      .map((ip) => `(ip.SrcAddr == ${ip} or ip.DstAddr == ${ip})`)
      .join(' or ');
    if (!targetClause) {
      throw new Error('No targets configured for shaping');
    }
    return `ip and !impostor and (${targetClause})`;
  }

  getKey(targetIp, direction) {
    return `${targetIp}|${direction}`;
  }

  getBucket(targetIp, direction) {
    const key = this.getKey(targetIp, direction);
    let bucket = this.buckets.get(key);
    if (!bucket) {
      const rate = direction === 'upload' ? this.uploadRate : this.downloadRate;
      bucket = new TokenBucket(rate);
      this.buckets.set(key, bucket);
    }
    return bucket;
  }

  getQueue(targetIp, direction) {
    const key = this.getKey(targetIp, direction);
    let queue = this.queues.get(key);
    if (!queue) {
      queue = [];
      this.queues.set(key, queue);
    }
    return queue;
  }

  shouldShape(direction) {
    if (direction === 'upload') {
      return this.uploadRate > 0;
    }
    return this.downloadRate > 0;
  }

  sendPacket(packet, addr) {
    if (!this.handle || typeof this.handle.send !== 'function') {
      return false;
    }
    if (!Buffer.isBuffer(packet) || !Buffer.isBuffer(addr)) {
      return false;
    }
    const sendAddr = Buffer.from(addr);
    writeAddrFlags(sendAddr, { impostor: true });
    try {
      if (typeof this.handle.HelperCalcChecksums === 'function') {
        this.handle.HelperCalcChecksums({ packet }, 0);
      }
      this.handle.send({ packet, addr: sendAddr });
      this.stats.sent += 1;
      return true;
    } catch (error) {
      this.stats.dropped += 1;
      console.warn('[shaper] Packet send failed:', error.message);
      return false;
    }
  }

  flushQueues() {
    const now = Date.now();
    for (const [key, queue] of this.queues.entries()) {
      if (queue.length === 0) {
        continue;
      }
      const [targetIp, direction] = key.split('|');
      const bucket = this.getBucket(targetIp, direction);
      let sentCount = 0;
      while (queue.length > 0) {
        const item = queue[0];
        if (!bucket.consume(item.size, now)) {
          break;
        }
        queue.shift();
        this.sendPacket(item.packet, item.addr);
        sentCount += 1;
        if (sentCount > 200) {
          break;
        }
      }
    }
    let queued = 0;
    for (const queue of this.queues.values()) {
      queued += queue.length;
    }
    this.stats.queued = queued;
  }

  startFlushLoop() {
    if (this.flushTimer) {
      return;
    }
    this.flushTimer = setInterval(() => this.flushQueues(), FLUSH_INTERVAL_MS);
  }

  stopFlushLoop() {
    if (!this.flushTimer) {
      return;
    }
    clearInterval(this.flushTimer);
    this.flushTimer = null;
  }

  async start({ targets = [], uploadKbps = 0, downloadKbps = 0 } = {}) {
    if (this.running) {
      return this.status();
    }
    this.targetIps = Array.isArray(targets)
      ? targets.map((target) => target?.ip).filter((ip) => typeof ip === 'string' && ip.length > 0)
      : [];
    this.uploadRate = Math.max(0, Number.parseInt(uploadKbps, 10) || 0) * 1024;
    this.downloadRate = Math.max(0, Number.parseInt(downloadKbps, 10) || 0) * 1024;

    if (this.uploadRate <= 0 && this.downloadRate <= 0) {
      return this.status();
    }

    const ready = await this.initializeWinDivert();
    if (!ready) {
      throw new Error('WinDivert not available for shaping');
    }
    if (!this.windivert?.createWindivert) {
      throw new Error('WinDivert module missing createWindivert API');
    }

    const filter = this.buildFilter();
    console.log('[shaper] WinDivert filter:', filter);
    const layer =
      this.windivert.LAYERS?.NETWORK_FORWARD ?? this.windivert.LAYERS?.NETWORK ?? 0;
    this.handle = await this.windivert.createWindivert(
      filter,
      layer,
      this.windivert.FLAGS?.DEFAULT ?? 0
    );
    if (typeof this.handle?.open !== 'function') {
      throw new Error('WinDivert handle does not support open()');
    }
    this.handle.open();

    const addReceiveListener = this.windivert?.addReceiveListener;
    if (typeof addReceiveListener !== 'function') {
      throw new Error('WinDivert addReceiveListener not available');
    }

    addReceiveListener(this.handle, (packet, addr) => {
      const flags = readAddrFlags(addr);
      if (flags?.loopback || flags?.impostor) {
        return;
      }
      if (!Buffer.isBuffer(packet)) {
        return;
      }
      let ipHeader;
      try {
        ipHeader = parseIpHeader(packet);
      } catch (_error) {
        return;
      }
      const srcIp = ipHeader.srcIp;
      const dstIp = ipHeader.dstIp;
      const isOutbound = this.targetIps.includes(srcIp);
      const isInbound = this.targetIps.includes(dstIp);
      if (!isOutbound && !isInbound) {
        return;
      }
      const direction = isOutbound ? 'upload' : 'download';
      const targetIp = isOutbound ? srcIp : dstIp;
      if (!this.shouldShape(direction)) {
        this.sendPacket(packet, addr);
        return false;
      }
      const queue = this.getQueue(targetIp, direction);
      if (queue.length >= MAX_QUEUE_PACKETS) {
        this.stats.dropped += 1;
        return false;
      }
      const size = packet.length;
      const bucket = this.getBucket(targetIp, direction);
      if (bucket.consume(size)) {
        this.sendPacket(packet, addr);
        return false;
      }
      queue.push({ packet: Buffer.from(packet), addr: Buffer.from(addr), size });
      return false;
    });

    this.startFlushLoop();
    this.running = true;
    return this.status();
  }

  async stop() {
    if (!this.running) {
      return this.status();
    }
    this.stopFlushLoop();
    if (this.handle && typeof this.handle.close === 'function') {
      try {
        this.handle.close();
      } catch (error) {
        console.warn('[shaper] Failed to close WinDivert handle:', error.message);
      }
    }
    this.handle = null;
    this.running = false;
    this.buckets.clear();
    this.queues.clear();
    this.stats = { queued: 0, sent: 0, dropped: 0 };
    return this.status();
  }

  status() {
    return {
      running: this.running,
      targets: this.targetIps,
      uploadKbps: Math.round(this.uploadRate / 1024),
      downloadKbps: Math.round(this.downloadRate / 1024),
      stats: { ...this.stats }
    };
  }
}
