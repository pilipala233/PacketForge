import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

const DEFAULT_MAX_BYTES = 100 * 1024 * 1024;
const MAX_ANALYZE_BYTES = 512 * 1024;

const TYPE_EXTENSION_MAP = new Map([
  ['text/plain', 'txt'],
  ['text/html', 'html'],
  ['text/xml', 'xml'],
  ['text/css', 'css'],
  ['text/javascript', 'js'],
  ['application/javascript', 'js'],
  ['application/json', 'json'],
  ['application/xml', 'xml'],
  ['application/pdf', 'pdf'],
  ['application/zip', 'zip'],
  ['application/gzip', 'gz'],
  ['application/x-tar', 'tar'],
  ['application/wasm', 'wasm'],
  ['application/vnd.apple.mpegurl', 'm3u8'],
  ['audio/mpeg', 'mp3'],
  ['audio/mp4', 'm4a'],
  ['audio/ogg', 'ogg'],
  ['audio/wav', 'wav'],
  ['video/mp4', 'mp4'],
  ['video/webm', 'webm'],
  ['video/quicktime', 'mov'],
  ['video/x-msvideo', 'avi'],
  ['video/x-flv', 'flv'],
  ['image/jpeg', 'jpg'],
  ['image/png', 'png'],
  ['image/gif', 'gif'],
  ['image/webp', 'webp'],
  ['image/bmp', 'bmp'],
  ['image/svg+xml', 'svg']
]);

const SOURCE_PRIORITY = {
  fallback: 0,
  sniff: 1,
  url: 2,
  disposition: 3,
  header: 4,
  override: 5
};

function toByteValue(value, fallback) {
  if (Number.isFinite(value)) {
    return Math.trunc(value);
  }
  if (typeof value === 'string') {
    const parsed = Number.parseInt(value.trim(), 10);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return fallback;
}

function sanitizeExtension(value) {
  if (!value || typeof value !== 'string') {
    return '';
  }
  const cleaned = value.trim().replace(/^\.+/, '').toLowerCase();
  if (!/^[a-z0-9]{1,10}$/.test(cleaned)) {
    return '';
  }
  return cleaned;
}

function extensionFromUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return '';
  }
  try {
    const url = new URL(rawUrl);
    const parts = url.pathname.split('/');
    const last = parts[parts.length - 1] || '';
    const dotIndex = last.lastIndexOf('.');
    if (dotIndex <= 0 || dotIndex === last.length - 1) {
      return '';
    }
    return sanitizeExtension(last.slice(dotIndex + 1));
  } catch (_error) {
    return '';
  }
}

function extensionFromFilename(value) {
  if (!value || typeof value !== 'string') {
    return '';
  }
  const base = path.basename(value.trim());
  const dotIndex = base.lastIndexOf('.');
  if (dotIndex <= 0 || dotIndex === base.length - 1) {
    return '';
  }
  return sanitizeExtension(base.slice(dotIndex + 1));
}

function stripQuotes(value) {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function decodeDispositionValue(value) {
  const trimmed = value.trim();
  const parts = trimmed.split("'");
  if (parts.length >= 3) {
    const encoded = parts.slice(2).join("'");
    try {
      return decodeURIComponent(encoded);
    } catch (_error) {
      return encoded;
    }
  }
  return trimmed;
}

function extensionFromDisposition(header) {
  if (!header || typeof header !== 'string') {
    return '';
  }
  const starMatch = /filename\*\s*=\s*([^;]+)/i.exec(header);
  if (starMatch) {
    const raw = stripQuotes(starMatch[1]);
    const decoded = decodeDispositionValue(raw);
    const ext = extensionFromFilename(decoded);
    if (ext) {
      return ext;
    }
  }
  const match = /filename\s*=\s*([^;]+)/i.exec(header);
  if (match) {
    const raw = stripQuotes(match[1]);
    const ext = extensionFromFilename(raw);
    if (ext) {
      return ext;
    }
  }
  return '';
}

function isOctetStream(type) {
  return type === 'application/octet-stream' || type === 'binary/octet-stream';
}

export function resolveExtensionInfo({ contentType, contentDisposition, url, fallback = 'bin' } = {}) {
  const rawType = typeof contentType === 'string' ? contentType : '';
  const baseType = rawType.split(';')[0]?.trim().toLowerCase();
  if (baseType && !isOctetStream(baseType)) {
    const mapped = TYPE_EXTENSION_MAP.get(baseType);
    if (mapped) {
      return { ext: mapped, source: 'header' };
    }
    if (baseType.endsWith('+json')) {
      return { ext: 'json', source: 'header' };
    }
    if (baseType.endsWith('+xml')) {
      return { ext: 'xml', source: 'header' };
    }
    if (baseType.startsWith('text/')) {
      return { ext: 'txt', source: 'header' };
    }
  }

  const dispositionExt = extensionFromDisposition(contentDisposition);
  if (dispositionExt) {
    return { ext: dispositionExt, source: 'disposition' };
  }

  const urlExt = extensionFromUrl(url);
  if (urlExt && urlExt !== 'bin') {
    return { ext: urlExt, source: 'url' };
  }

  const fallbackExt = sanitizeExtension(fallback) || 'bin';
  return { ext: fallbackExt, source: 'fallback' };
}

export function resolveExtension(options = {}) {
  return resolveExtensionInfo(options).ext;
}

function sniffExtension(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 4) {
    return '';
  }

  if (buffer.length >= 3 && buffer.slice(0, 3).toString('ascii') === 'FLV') {
    return 'flv';
  }
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return 'jpg';
  }
  if (
    buffer.length >= 8 &&
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0d &&
    buffer[5] === 0x0a &&
    buffer[6] === 0x1a &&
    buffer[7] === 0x0a
  ) {
    return 'png';
  }
  if (buffer.length >= 6) {
    const gif = buffer.slice(0, 6).toString('ascii');
    if (gif === 'GIF87a' || gif === 'GIF89a') {
      return 'gif';
    }
  }
  if (
    buffer.length >= 12 &&
    buffer.slice(0, 4).toString('ascii') === 'RIFF' &&
    buffer.slice(8, 12).toString('ascii') === 'WEBP'
  ) {
    return 'webp';
  }
  if (buffer.length >= 2 && buffer[0] === 0x42 && buffer[1] === 0x4d) {
    return 'bmp';
  }
  if (buffer.length >= 4 && buffer.slice(0, 4).toString('ascii') === '%PDF') {
    return 'pdf';
  }
  if (
    buffer.length >= 4 &&
    buffer[0] === 0x50 &&
    buffer[1] === 0x4b &&
    (buffer[2] === 0x03 || buffer[2] === 0x05 || buffer[2] === 0x07) &&
    (buffer[3] === 0x04 || buffer[3] === 0x06 || buffer[3] === 0x08)
  ) {
    return 'zip';
  }
  if (buffer.length >= 2 && buffer[0] === 0x1f && buffer[1] === 0x8b) {
    return 'gz';
  }
  if (
    buffer.length >= 12 &&
    buffer.slice(0, 4).toString('ascii') === 'RIFF' &&
    buffer.slice(8, 12).toString('ascii') === 'WAVE'
  ) {
    return 'wav';
  }
  if (buffer.length >= 4 && buffer.slice(0, 4).toString('ascii') === 'fLaC') {
    return 'flac';
  }
  if (buffer.length >= 4 && buffer.slice(0, 4).toString('ascii') === 'OggS') {
    return 'ogg';
  }
  if (buffer.length >= 3 && buffer.slice(0, 3).toString('ascii') === 'ID3') {
    return 'mp3';
  }
  if (buffer.length >= 2 && buffer[0] === 0xff && (buffer[1] & 0xe0) === 0xe0) {
    return 'mp3';
  }
  if (buffer.length >= 12 && buffer.slice(4, 8).toString('ascii') === 'ftyp') {
    const brand = buffer.slice(8, 12).toString('ascii');
    if (brand === 'qt  ') {
      return 'mov';
    }
    return 'mp4';
  }
  if (
    buffer.length >= 4 &&
    buffer[0] === 0x1a &&
    buffer[1] === 0x45 &&
    buffer[2] === 0xdf &&
    buffer[3] === 0xa3
  ) {
    return 'webm';
  }

  return '';
}

function analyzeFlv(buffer) {
  const info = {
    container: 'flv',
    headerSeen: false,
    sequenceHeader: null,
    keyframe: null
  };
  if (!Buffer.isBuffer(buffer) || buffer.length < 9) {
    return info;
  }
  if (buffer.slice(0, 3).toString('ascii') !== 'FLV') {
    return info;
  }
  info.headerSeen = true;
  info.sequenceHeader = false;
  info.keyframe = false;

  const headerSize = buffer.readUInt32BE(5);
  let offset = headerSize + 4;
  if (buffer.length < offset) {
    return info;
  }

  while (offset + 11 <= buffer.length) {
    const tagType = buffer[offset];
    const dataSize = buffer.readUIntBE(offset + 1, 3);
    const tagTotal = 11 + dataSize + 4;
    if (offset + tagTotal > buffer.length) {
      break;
    }

    if (tagType === 9 && dataSize >= 1) {
      const videoHeader = buffer[offset + 11];
      const frameType = (videoHeader >> 4) & 0x0f;
      const codecId = videoHeader & 0x0f;
      if (frameType === 1) {
        info.keyframe = true;
      }
      if ((codecId === 7 || codecId === 12) && dataSize >= 2) {
        const packetType = buffer[offset + 12];
        if (packetType === 0) {
          info.sequenceHeader = true;
        }
      }
    }

    if (info.sequenceHeader && info.keyframe) {
      break;
    }
    offset += tagTotal;
  }

  return info;
}

export function normalizeCaptureConfig(input, defaults = {}) {
  if (!input && !defaults) {
    return null;
  }
  const enabled = input?.enabled !== false;
  if (!enabled) {
    return null;
  }
  const dir = typeof input?.dir === 'string' && input.dir.trim() ? input.dir.trim() : defaults.dir;
  const maxBytes = toByteValue(input?.maxBytes, toByteValue(defaults.maxBytes, DEFAULT_MAX_BYTES));
  if (!dir || !Number.isFinite(maxBytes) || maxBytes <= 0) {
    return null;
  }
  return { dir, maxBytes };
}

class BodyCapture {
  constructor(dir, maxBytes, baseName, defaultExt = 'bin') {
    this.dir = dir;
    this.maxBytes = maxBytes;
    this.baseName = baseName;
    this.extension = sanitizeExtension(defaultExt) || 'bin';
    this.extensionSource = 'fallback';
    this.filePath = null;
    this.stream = null;
    this.totalBytes = 0;
    this.savedBytes = 0;
    this.truncated = false;
    this.finalized = false;
    this.mediaKind = null;
    this.analysisBuffer = null;
    this.mediaInfo = null;
  }

  setExtension(extension, source = 'fallback', force = false) {
    if (this.stream || this.finalized) {
      return;
    }
    const next = sanitizeExtension(extension);
    if (!next) {
      return;
    }
    const sourceKey = source && SOURCE_PRIORITY[source] !== undefined ? source : 'fallback';
    if (!force) {
      const currentPriority = SOURCE_PRIORITY[this.extensionSource] ?? 0;
      const nextPriority = SOURCE_PRIORITY[sourceKey] ?? 0;
      if (nextPriority < currentPriority) {
        return;
      }
    }
    this.extension = next;
    this.extensionSource = sourceKey;
    if (next === 'flv') {
      this.enableMediaAnalysis('flv');
    }
  }

  enableMediaAnalysis(kind) {
    if (this.mediaKind || this.finalized) {
      return;
    }
    if (kind !== 'flv') {
      return;
    }
    this.mediaKind = kind;
    this.analysisBuffer = Buffer.alloc(0);
  }

  appendAnalysis(chunk) {
    if (this.mediaKind !== 'flv' || !Buffer.isBuffer(chunk) || chunk.length === 0) {
      return;
    }
    if (!this.analysisBuffer) {
      this.analysisBuffer = Buffer.alloc(0);
    }
    if (this.analysisBuffer.length >= MAX_ANALYZE_BYTES) {
      return;
    }
    const remaining = MAX_ANALYZE_BYTES - this.analysisBuffer.length;
    const slice = chunk.length <= remaining ? chunk : chunk.slice(0, remaining);
    this.analysisBuffer = Buffer.concat([this.analysisBuffer, slice]);
  }

  resolveFilename() {
    return `${this.baseName}.${this.extension}`;
  }

  ensureStream() {
    if (this.stream || this.finalized) {
      return;
    }
    this.filePath = path.join(this.dir, this.resolveFilename());
    this.stream = fs.createWriteStream(this.filePath);
    this.stream.on('error', () => {
      this.truncated = true;
      this.stream = null;
    });
  }

  handleChunk(chunk) {
    if (this.finalized || !Buffer.isBuffer(chunk) || chunk.length === 0) {
      return;
    }
    if (this.extension === 'flv') {
      this.appendAnalysis(chunk);
    }
    this.totalBytes += chunk.length;
    if (this.savedBytes >= this.maxBytes) {
      this.truncated = true;
      return;
    }
    const remaining = this.maxBytes - this.savedBytes;
    const slice = chunk.length <= remaining ? chunk : chunk.slice(0, remaining);
    if (slice.length === 0) {
      return;
    }
    if (!this.stream && this.extensionSource === 'fallback') {
      const sniffed = sniffExtension(chunk);
      if (sniffed) {
        this.setExtension(sniffed, 'sniff');
        if (sniffed === 'flv') {
          this.appendAnalysis(chunk);
        }
      }
    }
    this.ensureStream();
    if (!this.stream) {
      return;
    }
    this.stream.write(slice);
    this.savedBytes += slice.length;
    if (chunk.length > remaining) {
      this.truncated = true;
      this.finalize();
    }
  }

  captureBuffer(buffer) {
    if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
      return;
    }
    this.handleChunk(buffer);
  }

  finalize() {
    if (this.finalized) {
      return this.summary();
    }
    this.finalized = true;
    if (this.stream) {
      this.stream.end();
      this.stream = null;
    }
    return this.summary();
  }

  summary() {
    if (this.mediaKind === 'flv' && !this.mediaInfo && this.analysisBuffer?.length) {
      this.mediaInfo = analyzeFlv(this.analysisBuffer);
    }
    return {
      path: this.savedBytes > 0 ? this.filePath : null,
      totalBytes: this.totalBytes,
      savedBytes: this.savedBytes,
      truncated: this.truncated || (this.savedBytes >= this.maxBytes && this.totalBytes > this.savedBytes),
      media: this.mediaInfo || undefined
    };
  }
}

export function createCaptureSession(config) {
  if (!config?.dir || !Number.isFinite(config?.maxBytes) || config.maxBytes <= 0) {
    return null;
  }
  try {
    fs.mkdirSync(config.dir, { recursive: true });
  } catch (error) {
    console.warn('[capture] Failed to create capture directory:', error.message);
    return null;
  }
  const id = randomUUID();
  return {
    id,
    request: new BodyCapture(config.dir, config.maxBytes, `${id}-request`, 'bin'),
    response: new BodyCapture(config.dir, config.maxBytes, `${id}-response`, 'bin')
  };
}
