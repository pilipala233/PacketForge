import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { EventEmitter } from 'node:events';
import { collectRuleCandidates, normalizeContentType, selectBestRule, selectRule } from './rules.js';
import { resolveAction } from './actions.js';

const DEFAULT_MAX_BODY_SIZE = 2 * 1024 * 1024;

function sanitizeHeaders(headers) {
  const next = { ...headers };
  delete next['proxy-connection'];
  delete next['proxy-authorization'];
  return next;
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
    certificateManager = null
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
    this.server = null;
    this.mitmServer = http.createServer(this.handleHttp.bind(this));
    this.mitmServer.on('clientError', (error, socket) => {
      socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    });
    this.running = false;
    this.pendingWrites = new Set();
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

  async stop() {
    if (!this.server) {
      return this.status();
    }

    await this.flush();
    await new Promise((resolve) => {
      this.server.close(() => resolve());
    });
    this.server = null;
    this.running = false;
    this.emit('status', this.status());
    return this.status();
  }

  handleHttp(req, res) {
    const startAt = Date.now();
    const targetUrl = resolveTargetUrl(req);
    if (!targetUrl) {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('Invalid target URL');
      return;
    }

    const protocol = targetUrl.protocol === 'https:' ? https : http;
    const headers = sanitizeHeaders(req.headers);
    headers.host = targetUrl.host;
    headers['accept-encoding'] = 'identity';

    const requestOptions = {
      method: req.method,
      hostname: targetUrl.hostname,
      port: targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80),
      path: `${targetUrl.pathname}${targetUrl.search}`,
      headers
    };

    const proxyReq = protocol.request(requestOptions, (proxyRes) => {
      const contentType = normalizeContentType(proxyRes.headers['content-type']);
      const context = {
        method: req.method,
        url: targetUrl.toString(),
        contentType,
        headers: req.headers
      };
      const rules = this.rulesStore?.list?.() ?? [];
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
        });
        proxyRes.on('end', () => {
          const durationMs = Date.now() - startAt;
          this.recordSession({
            url: targetUrl.toString(),
            method: req.method,
            status: proxyRes.statusCode ?? 0,
            contentType: contentType || '',
            sizeBytes: bytes,
            durationMs,
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

        const durationMs = Date.now() - startAt;
        this.recordSession({
          url: targetUrl.toString(),
          method: req.method,
          status: outStatus,
          contentType: resolved.contentType || contentType || '',
          sizeBytes: outBody.length,
          durationMs,
          matchedRuleId: finalRule?.id ?? null,
          applied: resolved.modified
        });
      });
    });

    proxyReq.on('error', () => {
      res.writeHead(502, { 'content-type': 'text/plain' });
      res.end('Bad gateway');
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
        cert: cert.certPem
      })
    });

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
      this.recordSession({
        url: `https://${host}:${port}`,
        method: 'CONNECT',
        status: 200,
        contentType: '',
        sizeBytes: 0,
        durationMs,
        matchedRuleId: null,
        applied: false
      });
    });
  }

  recordSession(entry) {
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
}
