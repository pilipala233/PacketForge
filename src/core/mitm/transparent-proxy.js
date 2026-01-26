/**
 * 透明代理服务器（改进版）
 * 继承 ProxyServer，支持透明代理模式
 * 智能 URL 重构 + 连接映射表
 */

import net from 'node:net';
import tls from 'node:tls';
import { ProxyServer } from '../proxy.js';

export class TransparentProxy extends ProxyServer {
  constructor(options = {}) {
    super({
      ...options,
      host: options.host || '0.0.0.0', // 透明代理监听所有接口
      httpsMode: options.httpsMode ?? 'mitm' // 透明代理默认启用 HTTPS 拦截
    });

    // 连接映射表：记录客户端连接的原始目标
    this.connectionMap = new Map();
    this.tlsServer = null;
    this.mitmServer.on('connect', this.handleConnect.bind(this));
    this.mitmServer.on('clientError', (_error, socket) => {
      socket?.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    });

    // 定期清理过期连接（5分钟）
    this.cleanupInterval = setInterval(() => {
      this.cleanupConnections();
    }, 5 * 60 * 1000);
  }

  looksLikeTlsClientHello(buffer) {
    if (!buffer || buffer.length < 3) {
      return false;
    }
    return buffer[0] === 0x16 && buffer[1] === 0x03;
  }

  createTlsServer() {
    if (!this.certificateManager) {
      throw new Error('Certificate manager is required for HTTPS intercept');
    }

    const server = tls.createServer(
      {
        ALPNProtocols: ['http/1.1'],
        SNICallback: (servername, callback) => {
          const host = servername && servername.trim() ? servername : 'localhost';
          this.certificateManager
            .getCertificate(host)
            .then((cert) => {
              const context = tls.createSecureContext({
                key: cert.keyPem,
                cert: cert.chainPem || cert.certPem
              });
              callback(null, context);
            })
            .catch((error) => callback(error));
        }
      },
      (tlsSocket) => {
        this.mitmServer.emit('connection', tlsSocket);
      }
    );

    server.on('tlsClientError', (_error, socket) => {
      socket?.destroy();
    });

    return server;
  }

  handleTransparentSocket(socket) {
    socket.once('data', (chunk) => {
      socket.pause();
      socket.unshift(chunk);

      const isTls = this.looksLikeTlsClientHello(chunk);
      if (isTls) {
        if (!this.tlsServer) {
          socket.destroy();
          return;
        }
        this.tlsServer.emit('connection', socket);
      } else {
        this.mitmServer.emit('connection', socket);
      }

      socket.resume();
    });

    socket.on('error', () => {});
  }

  async start(port = this.port, host = this.host) {
    if (this.running) {
      return this.status();
    }

    this.port = port ?? this.port;
    this.host = host ?? this.host;

    if (this.httpsMode === 'mitm' && this.certificateManager) {
      await this.certificateManager.ensureCa();
    }

    this.tlsServer =
      this.httpsMode === 'mitm' && this.certificateManager ? this.createTlsServer() : null;
    this.server = net.createServer((socket) => this.handleTransparentSocket(socket));
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

  /**
   * 重写 handleHttp 以支持透明代理模式
   * 透明代理中 req.url 是相对路径，需要从 Host 头重构完整 URL
   */
  handleHttp(req, res) {
    // 如果 URL 不是完整的 http:// 或 https:// 格式
    if (!req.url.startsWith('http://') && !req.url.startsWith('https://')) {
      const host = req.headers.host;
      if (!host) {
        console.error('[transparent-proxy] Missing Host header');
        res.writeHead(400, { 'content-type': 'text/plain' });
        res.end('Missing Host header');
        return;
      }

      // 智能判断协议
      const scheme = this.detectScheme(req);

      // 重构完整 URL
      req.url = `${scheme}://${host}${req.url}`;

      // 调试日志
      console.log('[transparent-proxy] Request:', {
        method: req.method,
        url: req.url,
        host: req.headers.host,
        localPort: req.socket.localPort,
        remoteAddr: `${req.socket.remoteAddress}:${req.socket.remotePort}`,
        scheme
      });
    }

    // 调用父类方法，复用规则引擎、证书管理等
    try {
      super.handleHttp(req, res);
    } catch (error) {
      console.error('[transparent-proxy] Error handling request:', error);
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'text/plain' });
        res.end('Proxy Error');
      }
    }
  }

  /**
   * 智能检测协议（HTTP/HTTPS）
   */
  detectScheme(req) {
    // 方法 1：通过本地端口判断
    const localPort = req.socket.localPort;
    if (localPort === 443 || localPort === 8443) {
      return 'https';
    }

    // 方法 2：通过 TLS 加密判断
    if (req.socket.encrypted) {
      return 'https';
    }

    // 方法 3：通过请求方法判断
    if (req.method === 'CONNECT') {
      return 'https';
    }

    // 方法 4：从连接映射表查询
    const connectionKey = `${req.socket.remoteAddress}:${req.socket.remotePort}`;
    const mapping = this.connectionMap.get(connectionKey);
    if (mapping && mapping.scheme) {
      return mapping.scheme;
    }

    // 默认 HTTP
    return 'http';
  }

  /**
   * 记录连接映射
   * @param {string} clientKey - 客户端标识 (ip:port)
   * @param {Object} target - 原始目标 {host, port, scheme}
   */
  recordConnection(clientKey, target) {
    this.connectionMap.set(clientKey, {
      ...target,
      timestamp: Date.now()
    });

    console.log('[transparent-proxy] Connection mapped:', {
      client: clientKey,
      target: `${target.scheme}://${target.host}:${target.port}`
    });
  }

  /**
   * 查询连接映射
   */
  getConnectionMapping(clientKey) {
    return this.connectionMap.get(clientKey);
  }

  /**
   * 清理过期连接（超过 5 分钟）
   */
  cleanupConnections() {
    const now = Date.now();
    const timeout = 5 * 60 * 1000; // 5 分钟

    let cleaned = 0;
    for (const [key, value] of this.connectionMap.entries()) {
      if (now - value.timestamp > timeout) {
        this.connectionMap.delete(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      console.log(`[transparent-proxy] Cleaned ${cleaned} expired connections`);
    }
  }

  /**
   * 停止代理
   */
  async stop(options = {}) {
    // 清理定时器
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }

    // 清空连接映射
    this.connectionMap.clear();

    if (this.tlsServer) {
      this.tlsServer.close();
      this.tlsServer = null;
    }

    // 调用父类停止方法
    return super.stop(options);
  }

  /**
   * 获取状态
   */
  status() {
    return {
      ...super.status(),
      mode: 'transparent',
      connections: this.connectionMap.size
    };
  }
}
