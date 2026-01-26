import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { EventEmitter } from 'node:events';
import { collectRuleCandidates, normalizeContentType, selectBestRule, selectRule } from './rules.js';
import { resolveAction } from './actions.js';
import { createCaptureSession, normalizeCaptureConfig, resolveExtensionInfo } from './capture.js';

const DEFAULT_MAX_BODY_SIZE = 2 * 1024 * 1024;
const REQUEST_PREVIEW_BYTES = 64 * 1024;

function sanitizeHeaders(headers) {
  const next = { ...headers };
  delete next['proxy-connection'];
  delete next['proxy-authorization'];
  return next;
}

function isProbablyText(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return true;
  }
  const sampleSize = Math.min(buffer.length, 4096);
  let nonPrintable = 0;
  for (let i = 0; i < sampleSize; i += 1) {
    const byte = buffer[i];
    if (byte === 0x00) {
      nonPrintable += 2;
      continue;
    }
    if (byte === 0x09 || byte === 0x0a || byte === 0x0d) {
      continue;
    }
    if (byte >= 0x20) {
      continue;
    }
    nonPrintable += 1;
  }
  return nonPrintable / sampleSize <= 0.2;
}

function shouldTreatAsText(contentType, buffer) {
  const lower = typeof contentType === 'string' ? contentType.toLowerCase() : '';
  if (
    lower.startsWith('text/') ||
    lower.includes('json') ||
    lower.includes('xml') ||
    lower.includes('javascript') ||
    lower.includes('x-www-form-urlencoded')
  ) {
    return true;
  }
  return isProbablyText(buffer);
}

function createBodyPreview(limitBytes = REQUEST_PREVIEW_BYTES) {
  const limit = Number.isFinite(limitBytes) && limitBytes > 0 ? Math.trunc(limitBytes) : 0;
  let totalBytes = 0;
  let savedBytes = 0;
  let truncated = false;
  let chunks = [];
  let summary = null;
  return {
    handleChunk(chunk) {
      if (!Buffer.isBuffer(chunk) || chunk.length === 0) {
        return;
      }
      totalBytes += chunk.length;
      if (savedBytes >= limit) {
        truncated = true;
        return;
      }
      const remaining = limit - savedBytes;
      const slice = chunk.length <= remaining ? chunk : chunk.slice(0, remaining);
      if (slice.length > 0) {
        chunks.push(slice);
        savedBytes += slice.length;
      }
      if (chunk.length > remaining) {
        truncated = true;
      }
    },
    finalize(contentType) {
      if (summary) {
        return summary;
      }
      const buffer = chunks.length > 0 ? Buffer.concat(chunks) : Buffer.alloc(0);
      const isText = shouldTreatAsText(contentType, buffer);
      summary = {
        ok: true,
        isText,
        truncated: truncated || totalBytes > savedBytes,
        bytesRead: savedBytes,
        totalBytes,
        text: isText ? buffer.toString('utf8') : null,
        base64: isText ? null : buffer.toString('base64')
      };
      chunks = [];
      return summary;
    },
    stats() {
      return { totalBytes, savedBytes, truncated: truncated || totalBytes > savedBytes };
    }
  };
}

function resolveTargetUrl(req) {
  if (!req.url) {
    return null;
  }

  try {
    if (req.url.startsWith('http://') || req.url.startsWith('https://')) {
      return new URL(req.url);
    }
  } catch (error) {
    return null;
  }

  const host = req.headers.host;
  if (!host) {
    return null;
  }

  try {
    const scheme = req.socket?.encrypted ? 'https' : 'http';
    return new URL(`${scheme}://${host}${req.url}`);
  } catch (error) {
    return null;
  }
}

function shouldInspectResponse(rule, proxyRes, maxBodySize, needsBody) {
  if (!rule && !needsBody) {
    return false;
  }

  const encoding = proxyRes.headers['content-encoding'];
  if (encoding) {
    return false;
  }

  const lengthHeader = proxyRes.headers['content-length'];
  if (!lengthHeader) {
    return false;
  }

  const length = Number.parseInt(lengthHeader, 10);
  if (!Number.isFinite(length)) {
    return false;
  }

  return length <= maxBodySize;
}

function updateHeadersForBody(headers, body, contentType) {
  const next = { ...headers };
  if (contentType) {
    next['content-type'] = contentType;
  }
  next['content-length'] = String(body.length);
  delete next['content-encoding'];
  delete next['transfer-encoding'];
  return next;
}

function parseConnectTarget(value) {
  if (!value) {
    return null;
  }
  try {
    const url = new URL(`http://${value}`);
    const port = Number.parseInt(url.port, 10) || 443;
    return { host: url.hostname, port };
  } catch (error) {
    return null;
  }
}

export class ProxyServer extends EventEmitter {
  constructor({
    port = 8080,
    host = '127.0.0.1',
    rulesStore,
    resourcesStore,
    sessionsStore,
    maxBodySize = DEFAULT_MAX_BODY_SIZE,
    httpsMode = 'tunnel',
    certificateManager = null,
    capture = null
  } = {}) {
    super();
    this.port = port;
    this.host = host;
    this.rulesStore = rulesStore;
    this.resourcesStore = resourcesStore;
    this.sessionsStore = sessionsStore;
    this.maxBodySize = maxBodySize;
    this.httpsMode = httpsMode;
    this.certificateManager = certificateManager;
    this.captureConfig = normalizeCaptureConfig(capture);
    this.server = null;
    this.mitmServer = http.createServer(this.handleHttp.bind(this));
    this.mitmServer.on('clientError', (error, socket) => {
      socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    });
    this.running = false;
    this.pendingWrites = new Set();
    this.activeSockets = new Set();
    this.paused = false;
  }

  status() {
    return {
      running: this.running,
      port: this.port,
      host: this.host,
      httpsMode: this.httpsMode
    };
  }

  setHttpsMode(mode) {
    this.httpsMode = mode === 'mitm' ? 'mitm' : 'tunnel';
    this.emit('status', this.status());
  }

  async start(port = this.port, host = this.host) {
    if (this.running) {
      return this.status();
    }

    this.port = port ?? this.port;
    this.host = host ?? this.host;
    this.server = http.createServer(this.handleHttp.bind(this));
    this.server.on('connect', this.handleConnect.bind(this));
    this.server.on('clientError', (error, socket) => {
      socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    });
    this.trackServerSockets(this.server);

    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.port, this.host, () => {
        this.running = true;
        const address = this.server.address();
        if (address && typeof address === 'object') {
          this.port = address.port;
        }
        this.emit('status', this.status());
        resolve();
      });
    });

    return this.status();
  }

  async stop({ flush = true } = {}) {
    if (!this.server) {
      return this.status();
    }

    if (flush) {
      await this.flush();
    }
    const closePromise = new Promise((resolve) => {
      this.server.close(() => resolve('closed'));
    });
    if (!flush) {
      const timeoutPromise = new Promise((resolve) => {
        setTimeout(() => resolve('timeout'), 1500);
      });
      const result = await Promise.race([closePromise, timeoutPromise]);
      if (result === 'timeout') {
        this.destroyActiveSockets();
        await Promise.race([
          closePromise,
          new Promise((resolve) => setTimeout(resolve, 500))
        ]);
      }
    } else {
      await closePromise;
    }
    this.server = null;
    this.running = false;
    this.emit('status', this.status());
    return this.status();
  }

  handleHttp(req, res) {
    const startAt = Date.now();
    const paused = this.paused === true;
    const targetUrl = resolveTargetUrl(req);
    if (!targetUrl) {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('Invalid target URL');
      return;
    }

    const captureSession =
      !paused && this.captureConfig ? createCaptureSession(this.captureConfig) : null;
    const requestCapture = null;
    const responseCapture = captureSession?.response ?? null;
    const requestPreview = paused ? null : createBodyPreview(REQUEST_PREVIEW_BYTES);

    const buildCaptureFields = () => {
      const fields = {};
      const requestSummary = requestCapture?.finalize();
      const responseSummary = responseCapture?.finalize();
      if (requestSummary && (requestSummary.totalBytes > 0 || requestSummary.path)) {
        fields.requestBodyPath = requestSummary.path ?? undefined;
        fields.requestBodyBytes = requestSummary.totalBytes ?? 0;
        fields.requestBodySavedBytes = requestSummary.savedBytes ?? 0;
        fields.requestBodyTruncated = requestSummary.truncated ?? false;
      }
      if (!fields.requestBodyPath && requestPreview) {
        const previewSummary = requestPreview.finalize(req.headers['content-type']);
        if (previewSummary && (previewSummary.totalBytes > 0 || previewSummary.bytesRead > 0)) {
          fields.requestBodyPreview = previewSummary;
          fields.requestBodyBytes = previewSummary.totalBytes ?? 0;
          fields.requestBodySavedBytes = previewSummary.bytesRead ?? 0;
          fields.requestBodyTruncated = previewSummary.truncated ?? false;
        }
      }
      if (responseSummary && (responseSummary.totalBytes > 0 || responseSummary.path)) {
        fields.responseBodyPath = responseSummary.path ?? undefined;
        fields.responseBodyBytes = responseSummary.totalBytes ?? 0;
        fields.responseBodySavedBytes = responseSummary.savedBytes ?? 0;
        fields.responseBodyTruncated = responseSummary.truncated ?? false;
        if (responseSummary.media) {
          fields.responseMedia = responseSummary.media;
        }
      }
      return fields;
    };

    let sessionRecorded = false;
    const recordOnce = (entry) => {
      if (paused) {
        return;
      }
      if (sessionRecorded) {
        return;
      }
      sessionRecorded = true;
      const captureFields = buildCaptureFields();
      this.recordSession({ requestHeaders, ...entry, ...captureFields });
    };

    const protocol = targetUrl.protocol === 'https:' ? https : http;
    const requestHeaders = sanitizeHeaders(req.headers);
    const headers = {
      ...requestHeaders,
      host: targetUrl.host,
      'accept-encoding': 'identity'
    };
    if (requestCapture) {
      const requestExt = resolveExtensionInfo({
        contentType: req.headers['content-type'],
        contentDisposition: req.headers['content-disposition'],
        url: targetUrl.toString(),
        fallback: 'bin'
      });
      requestCapture.setExtension(requestExt.ext, requestExt.source);
    }

    const requestOptions = {
      method: req.method,
      hostname: targetUrl.hostname,
      port: targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80),
      path: `${targetUrl.pathname}${targetUrl.search}`,
      headers
    };

    let proxyReq;
    const failResponse = (status = 502, message = 'Bad gateway') => {
      if (res.writableEnded || res.destroyed) {
        return;
      }
      if (!res.headersSent) {
        res.writeHead(status, { 'content-type': 'text/plain' });
      }
      res.end(message);
    };
    const handleProxyError = (error) => {
      console.error('[proxy] Upstream error:', error?.message ?? error);
      if (proxyReq && !proxyReq.destroyed) {
        proxyReq.destroy();
      }
      failResponse(502, 'Bad gateway');
      const durationMs = Date.now() - startAt;
      recordOnce({
        url: targetUrl.toString(),
        method: req.method,
        status: 502,
        contentType: '',
        sizeBytes: 0,
        durationMs,
        responseHeaders: null,
        matchedRuleId: null,
        applied: false
      });
    };

    if (requestCapture || requestPreview) {
      const finalizeRequest = () => {
        requestCapture?.finalize();
        requestPreview?.finalize(req.headers['content-type']);
      };
      req.on('data', (chunk) => {
        requestCapture?.handleChunk(chunk);
        requestPreview?.handleChunk(chunk);
      });
      req.on('end', finalizeRequest);
      req.on('aborted', finalizeRequest);
      req.on('error', finalizeRequest);
    }

    proxyReq = protocol.request(requestOptions, (proxyRes) => {
      const contentType = normalizeContentType(proxyRes.headers['content-type']);
      const context = {
        method: req.method,
        url: targetUrl.toString(),
        contentType,
        headers: req.headers
      };
      if (responseCapture) {
        const responseExt = resolveExtensionInfo({
          contentType: proxyRes.headers['content-type'],
          contentDisposition: proxyRes.headers['content-disposition'],
          url: targetUrl.toString(),
          fallback: 'bin'
        });
        responseCapture.setExtension(responseExt.ext, responseExt.source);
      }
      proxyRes.on('error', handleProxyError);
      proxyRes.on('aborted', () => handleProxyError(new Error('Upstream aborted')));
      const rules = paused ? [] : this.rulesStore?.list?.() ?? [];
      const candidates = collectRuleCandidates(rules, context);
      const rule = selectBestRule(candidates.matches);
      const inspect = shouldInspectResponse(
        rule,
        proxyRes,
        this.maxBodySize,
        candidates.needsBody.length > 0
      );

      if (!inspect) {
        let bytes = 0;
        proxyRes.on('data', (chunk) => {
          bytes += chunk.length;
          responseCapture?.handleChunk(chunk);
        });
        proxyRes.on('aborted', () => {
          responseCapture?.finalize();
        });
        proxyRes.on('end', () => {
          const durationMs = Date.now() - startAt;
        recordOnce({
          url: targetUrl.toString(),
          method: req.method,
          status: proxyRes.statusCode ?? 0,
          contentType: contentType || '',
          sizeBytes: bytes,
          durationMs,
          responseHeaders: proxyRes.headers,
          matchedRuleId: rule?.id ?? null,
          applied: false
        });
        });

        res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
        proxyRes.pipe(res);
        return;
      }

      const chunks = [];
      proxyRes.on('data', (chunk) => {
        chunks.push(chunk);
      });
      proxyRes.on('end', () => {
        const body = Buffer.concat(chunks);
        const baseResponse = {
          status: proxyRes.statusCode ?? 502,
          headers: proxyRes.headers,
          body,
          contentType
        };

        const bodyText = candidates.needsBody.length > 0 ? body.toString('utf8') : undefined;
        const finalRule = selectRule(rules, { ...context, bodyText });
        const resolved = resolveAction(finalRule?.action, baseResponse, this.resourcesStore);
        const outBody = resolved.body ?? Buffer.alloc(0);
        const baseHeaders = resolved.headers ?? proxyRes.headers;
        const outHeaders = resolved.modified
          ? updateHeadersForBody(baseHeaders, outBody, resolved.contentType)
          : baseHeaders;
        const outStatus = resolved.status ?? proxyRes.statusCode ?? 502;

        res.writeHead(outStatus, outHeaders);
        res.end(outBody);

        if (responseCapture) {
          const resolvedExt = resolveExtensionInfo({
            contentType: resolved.contentType || contentType || proxyRes.headers['content-type'],
            contentDisposition:
              resolved.headers?.['content-disposition'] ?? proxyRes.headers['content-disposition'],
            url: targetUrl.toString(),
            fallback: 'bin'
          });
          responseCapture.setExtension(resolvedExt.ext, resolvedExt.source, resolved.modified);
        }
        responseCapture?.captureBuffer(outBody);

        const durationMs = Date.now() - startAt;
        recordOnce({
          url: targetUrl.toString(),
          method: req.method,
          status: outStatus,
          contentType: resolved.contentType || contentType || '',
          sizeBytes: outBody.length,
          durationMs,
          responseHeaders: outHeaders,
          matchedRuleId: finalRule?.id ?? null,
          applied: resolved.modified
        });
      });
    });

    proxyReq.on('error', handleProxyError);
    proxyReq.on('timeout', () => handleProxyError(new Error('Upstream timeout')));
    req.on('aborted', () => {
      if (proxyReq && !proxyReq.destroyed) {
        proxyReq.destroy();
      }
    });
    req.on('error', handleProxyError);
    res.on('error', handleProxyError);
    res.on('close', () => {
      if (proxyReq && !proxyReq.destroyed) {
        proxyReq.destroy();
      }
    });

    req.pipe(proxyReq);
  }

  handleConnect(req, clientSocket, head) {
    if (this.httpsMode === 'mitm' && this.certificateManager) {
      void this.handleMitmConnect(req, clientSocket, head);
      return;
    }

    this.handleTunnelConnect(req, clientSocket, head);
  }

  async handleMitmConnect(req, clientSocket, head) {
    const target = parseConnectTarget(req.url);
    if (!target?.host) {
      clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
      return;
    }
    const { host } = target;

    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head && head.length > 0) {
      clientSocket.unshift(head);
    }

    let cert;
    try {
      cert = await this.certificateManager.getCertificate(host);
    } catch (error) {
      clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
      return;
    }

    const tlsSocket = new tls.TLSSocket(clientSocket, {
      isServer: true,
      secureContext: tls.createSecureContext({
        key: cert.keyPem,
        cert: cert.chainPem || cert.certPem
      })
    });
    this.trackSocket(tlsSocket);

    tlsSocket.on('error', () => {
      clientSocket.destroy();
    });

    tlsSocket.on('secure', () => {
      this.mitmServer.emit('connection', tlsSocket);
    });
  }

  handleTunnelConnect(req, clientSocket, head) {
    const startAt = Date.now();
    const target = parseConnectTarget(req.url);
    if (!target?.host) {
      clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
      return;
    }
    const { host, port } = target;

    const serverSocket = net.connect(port, host, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length > 0) {
        serverSocket.write(head);
      }
      serverSocket.pipe(clientSocket);
      clientSocket.pipe(serverSocket);
    });

    serverSocket.on('error', () => {
      clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    });

    serverSocket.on('close', () => {
      const durationMs = Date.now() - startAt;
      const requestHeaders = sanitizeHeaders(req.headers);
      this.recordSession({
        url: `https://${host}:${port}`,
        method: 'CONNECT',
        status: 200,
        contentType: '',
        sizeBytes: 0,
        durationMs,
        requestHeaders,
        responseHeaders: null,
        matchedRuleId: null,
        applied: false
      });
    });
  }

  recordSession(entry) {
    if (this.paused) {
      return;
    }
    if (this.sessionsStore?.add) {
      const pending = this.sessionsStore.add(entry);
      this.pendingWrites.add(pending);
      void pending
        .then((session) => {
          this.emit('session', session);
        })
        .finally(() => {
          this.pendingWrites.delete(pending);
        });
      return;
    }

    this.emit('session', entry);
  }

  async flush() {
    if (this.pendingWrites.size === 0) {
      return;
    }
    await Promise.allSettled([...this.pendingWrites]);
  }

  setPaused(paused) {
    this.paused = Boolean(paused);
  }

  trackSocket(socket) {
    if (!socket) {
      return;
    }
    this.activeSockets.add(socket);
    socket.on('close', () => {
      this.activeSockets.delete(socket);
    });
  }

  trackServerSockets(server) {
    if (!server || typeof server.on !== 'function') {
      return;
    }
    server.on('connection', (socket) => this.trackSocket(socket));
  }

  destroyActiveSockets() {
    for (const socket of this.activeSockets) {
      try {
        socket.destroy();
      } catch (_error) {}
    }
    this.activeSockets.clear();
  }
}
