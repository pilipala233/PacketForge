/**
 * MITM 控制器
 * 协调 ARP 欺骗、流量重定向、透明代理等组件
 */

import { EventEmitter } from 'node:events';
import { NetworkScanner } from './scanner.js';
import { ArpSpoofer } from './arp-spoofer.js';
import { TrafficRedirect } from './traffic-redirect.js';
import { TrafficShaper } from './traffic-shaper.js';
import { TransparentProxy } from './transparent-proxy.js';
import { checkPrivileges, requestElevation } from './utils/privileges.js';
import { hasPortSpec, isAllPorts, parsePortSpec } from './utils/ports.js';
import { FlowMonitor } from './flow-monitor.js';
import { normalizeCaptureConfig } from '../capture.js';

const STOP_TIMEOUT_MS = 5000;

async function runWithTimeout(label, task, timeoutMs = STOP_TIMEOUT_MS) {
  if (typeof task !== 'function') {
    return null;
  }
  let timerId;
  const work = Promise.resolve().then(task);
  const timeout =
    Number.isFinite(timeoutMs) && timeoutMs > 0
      ? new Promise((_, reject) => {
          timerId = setTimeout(() => reject(new Error(`${label} timeout`)), timeoutMs);
        })
      : null;
  try {
    if (timeout) {
      return await Promise.race([work, timeout]);
    }
    return await work;
  } catch (error) {
    console.warn('[mitm]', label, 'failed:', error?.message ?? error);
    return null;
  } finally {
    if (timerId) {
      clearTimeout(timerId);
    }
  }
}

function parseThrottleValue(value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return 0;
  }
  return parsed;
}

function normalizeThrottleConfig(input) {
  if (!input || typeof input !== 'object') {
    return { uploadKbps: 0, downloadKbps: 0 };
  }
  return {
    uploadKbps: parseThrottleValue(input.uploadKbps),
    downloadKbps: parseThrottleValue(input.downloadKbps)
  };
}

function shouldThrottle(config) {
  return Boolean(config && (config.uploadKbps > 0 || config.downloadKbps > 0));
}

export class MitmController extends EventEmitter {
  constructor({ certificateManager, rulesStore, resourcesStore, sessionsStore }) {
    super();

    // 复用现有组件
    this.certificateManager = certificateManager;
    this.rulesStore = rulesStore;
    this.resourcesStore = resourcesStore;
    this.sessionsStore = sessionsStore;

    // MITM 组件
    this.scanner = new NetworkScanner();
    this.arpSpoofer = new ArpSpoofer();
    this.trafficRedirect = new TrafficRedirect();
    this.trafficShaper = new TrafficShaper();
    this.transparentProxy = null;
    this.flowMonitor = new FlowMonitor();

    // 状态
    this.running = false;
    this.interfaceName = null;
    this.gateway = null;
    this.targets = [];
    this.captureConfig = null;
    this.httpPortSpec = null;
    this.httpsPortSpec = null;
    this.proxyPort = 8888;
    this.httpsIntercept = false;
    this.httpsObserve = false;
    this.paused = false;
    this.pausedHard = false;
    this.redirectHttpSpec = null;
    this.redirectHttpsSpec = null;
    this.hasRedirectPorts = false;
    this.throttleConfig = { uploadKbps: 0, downloadKbps: 0 };
    this.throttleConfig = { uploadKbps: 0, downloadKbps: 0 };

    // 监听事件
    this.arpSpoofer.on('started', () => {
      this.emit('status', this.status());
    });
    this.arpSpoofer.on('stopped', () => {
      this.emit('status', this.status());
    });

    this.flowMonitor.on('flow', (flow) => {
      if (this.paused) {
        return;
      }
      const tlsServerName = flow.tlsServerName || flow.serverName || flow.hostname;
      const isHttpsFlow =
        flow.protocol === 'tcp' &&
        (flow.serverPort === 443 || (typeof tlsServerName === 'string' && tlsServerName));
      const url =
        isHttpsFlow && typeof flow.url === 'string'
          ? flow.url.replace(/^tcp:/, 'https:')
          : flow.url;
      const entry = {
        url,
        method: isHttpsFlow ? 'HTTPS' : flow.protocol?.toUpperCase?.() || 'UDP',
        status: undefined,
        contentType: isHttpsFlow ? 'https' : flow.protocol || 'udp',
        sizeBytes: flow.sizeBytes ?? 0,
        durationMs: flow.durationMs ?? 0,
        matchedRuleId: null,
        applied: false
      };
      if (this.sessionsStore?.add) {
        const pending = this.sessionsStore.add(entry);
        pending
          .then((session) => {
            this.emit('session', session);
          })
          .catch(() => {});
      } else {
        this.emit('session', entry);
      }
    });
  }

  /**
   * 获取当前状态
   */
  status() {
    const shaperStatus = this.trafficShaper?.status?.();
    return {
      running: this.running,
      paused: this.paused,
      interface: this.interfaceName,
      gateway: this.gateway,
      targets: this.targets,
      proxyPort: this.proxyPort,
      httpsIntercept: this.httpsIntercept,
      httpsObserve: this.httpsObserve,
      httpPorts: this.httpPortSpec,
      httpsPorts: this.httpsPortSpec,
      capture: this.captureConfig,
      throttle: {
        ...this.throttleConfig,
        running: Boolean(shaperStatus?.running)
      }
    };
  }

  async startTrafficShaper() {
    if (!shouldThrottle(this.throttleConfig)) {
      await this.stopTrafficShaper();
      return null;
    }
    const status = await runWithTimeout('traffic shaper start', () =>
      this.trafficShaper.start({
        targets: this.targets,
        uploadKbps: this.throttleConfig.uploadKbps,
        downloadKbps: this.throttleConfig.downloadKbps
      })
    );
    if (status?.running) {
      console.log('[mitm] Traffic shaper enabled:', {
        uploadKbps: this.throttleConfig.uploadKbps,
        downloadKbps: this.throttleConfig.downloadKbps
      });
    } else {
      console.warn('[mitm] Traffic shaper failed to start');
    }
    return status;
  }

  async stopTrafficShaper() {
    return runWithTimeout('traffic shaper stop', () => this.trafficShaper.stop());
  }

  /**
   * 列出网络接口
   */
  async listInterfaces() {
    return this.scanner.listInterfaces();
  }

  /**
   * 扫描网络
   */
  async scanNetwork(interfaceName) {
    const devices = await this.scanner.scanSubnet(interfaceName, null);

    // 发送设备发现事件
    for (const device of devices) {
      this.emit('device-discovered', device);
    }

    return devices;
  }

  /**
   * 获取网关
   */
  async getGateway(interfaceName) {
    return this.scanner.getGateway(interfaceName);
  }

  /**
   * 启动 MITM
   * @param {Object} options
   * @param {string} options.interface - 网络接口名称
   * @param {Object} options.gateway - 网关信息 {ip, mac}
   * @param {Array} options.targets - 目标设备列表 [{ip, mac}]
   * @param {number} options.proxyPort - 透明代理端口
   * @param {boolean} options.httpsIntercept - 是否拦截 HTTPS
   */
  async start({
    interface: interfaceName,
    gateway,
    targets,
    proxyPort = 8888,
    httpsIntercept = false,
    httpsObserve = false,
    httpPorts,
    httpsPorts,
    capture,
    throttle
  }) {
    if (this.running) {
      throw new Error('MITM already running');
    }

    // 检查权限
    const privileges = await checkPrivileges();
    if (!privileges.elevated) {
      throw new Error(`Administrator privileges required: ${privileges.reason}`);
    }

    try {
      this.interfaceName = interfaceName;
      this.gateway = gateway;
      this.targets = targets;
      this.proxyPort = proxyPort;
      this.throttleConfig = normalizeThrottleConfig(throttle);
      const observeHttps = Boolean(httpsObserve);
      const httpsRequested = Boolean(httpsIntercept) && !observeHttps;
      const httpsSpecEnabled = httpsRequested || observeHttps;
      const parsedHttpSpec = parsePortSpec(httpPorts, 80);
      const parsedHttpsSpec = httpsSpecEnabled
        ? parsePortSpec(httpsPorts, 443)
        : parsePortSpec([]);
      const httpListenOnly = isAllPorts(parsedHttpSpec);
      const httpsListenOnly = httpsSpecEnabled && isAllPorts(parsedHttpsSpec);
      const redirectHttpSpec = httpListenOnly ? parsePortSpec([]) : parsedHttpSpec;
      const redirectHttpsSpec =
        httpsRequested && !httpsListenOnly ? parsedHttpsSpec : parsePortSpec([]);
      const hasRedirectPorts =
        hasPortSpec(redirectHttpSpec) || hasPortSpec(redirectHttpsSpec);
      const httpsMitmEnabled = httpsRequested && hasPortSpec(redirectHttpsSpec);

      if (httpListenOnly) {
        console.warn('[mitm] HTTP ports set to all (*); running in listen-only mode for HTTP.');
      }
      if (httpsListenOnly) {
        console.warn('[mitm] HTTPS ports set to all (*); running in listen-only mode for HTTPS.');
      }
      const httpsMode = httpsMitmEnabled ? 'mitm' : observeHttps ? 'observe' : 'off';
      console.log('[mitm] HTTPS mode:', httpsMode);

      this.httpsIntercept = httpsMitmEnabled;
      this.httpsObserve = observeHttps;
      this.httpPortSpec = parsedHttpSpec;
      this.httpsPortSpec = parsedHttpsSpec;
      this.redirectHttpSpec = redirectHttpSpec;
      this.redirectHttpsSpec = redirectHttpsSpec;
      this.hasRedirectPorts = hasRedirectPorts;
      this.paused = false;
      this.pausedHard = false;

      // 1. 启动透明代理（仅在有拦截端口时）
      this.captureConfig = normalizeCaptureConfig(capture);

      if (hasRedirectPorts) {
        if (httpsMitmEnabled) {
          await this.certificateManager.ensureCa();
        }
        this.transparentProxy = new TransparentProxy({
          port: proxyPort,
          host: '0.0.0.0',
          rulesStore: this.rulesStore,
          resourcesStore: this.resourcesStore,
          sessionsStore: this.sessionsStore,
          certificateManager: this.certificateManager,
          httpsMode: httpsMitmEnabled ? 'mitm' : 'tunnel',
          capture: this.captureConfig
        });

        // 转发 session 事件
        this.transparentProxy.on('session', (session) => {
          if (this.paused) {
            return;
          }
          this.emit('session', session);
        });

        await this.transparentProxy.start(proxyPort, '0.0.0.0');
      } else {
        console.warn('[mitm] Redirect disabled; running in listen-only mode.');
      }

      // 2. 启用 IP 转发
      await this.trafficRedirect.enableIpForwarding({ interfaceName });

      // 3. 设置流量重定向
      const interfaces = await this.scanner.listInterfaces();
      const matchedInterface = interfaces.find((item) => item.name === interfaceName);
      const localIp = matchedInterface?.ip || null;
      if (!localIp) {
        console.warn('[mitm] Unable to resolve local IP for interface:', interfaceName);
      }
      if (hasRedirectPorts) {
        await this.trafficRedirect.setupRedirect({
          httpPorts: redirectHttpSpec,
          httpsPorts: redirectHttpsSpec,
          proxyPort,
          localIp,
          targets
        });
      }

      // 4. Start traffic shaping (per target, if configured)
      await this.startTrafficShaper();

      // 5. 启动流量监控（UDP/TCP）
      try {
        const ignorePortSpec = parsePortSpec([redirectHttpSpec, redirectHttpsSpec]);
        const monitorTcp =
          observeHttps || !hasPortSpec(redirectHttpSpec) || !hasPortSpec(redirectHttpsSpec);
        const flowIdleMs = observeHttps ? 5000 : null;
        const flowMaxMs = observeHttps ? 20000 : null;
        await this.flowMonitor.start({
          targets,
          monitorUdp: true,
          monitorTcp,
          ignorePortSpec,
          localIp: hasRedirectPorts ? localIp ?? '127.0.0.1' : null,
          proxyPort: hasRedirectPorts ? proxyPort : null,
          flowIdleMs,
          flowMaxMs
        });
        console.log('[mitm] Flow monitor enabled:', {
          tcp: monitorTcp,
          udp: true,
          flowIdleMs: flowIdleMs ?? 'default',
          flowMaxMs: flowMaxMs ?? 'default'
        });
      } catch (error) {
        console.warn('[mitm] Flow monitor disabled:', error.message);
      }

      // 6. 启动 ARP 欺骗
      await this.arpSpoofer.startSpoofing({
        interface: interfaceName,
        gateway,
        targets
      });

      this.running = true;
      this.emit('status', this.status());

      return this.status();
    } catch (error) {
      // 启动失败，清理资源
      await this.cleanup();
      throw error;
    }
  }

  /**
   * 停止 MITM
   */
  async stop() {
    if (!this.running) {
      return this.status();
    }

    await this.cleanup();

    this.running = false;
    this.paused = false;
    this.pausedHard = false;
    this.httpsObserve = false;
    this.interfaceName = null;
    this.gateway = null;
    this.targets = [];
    this.redirectHttpSpec = null;
    this.redirectHttpsSpec = null;
    this.hasRedirectPorts = false;

    this.emit('status', this.status());
    return this.status();
  }

  async pause(options = {}) {
    if (!this.running) {
      throw new Error('MITM not running');
    }
    if (this.paused) {
      return this.status();
    }

    const hard = options?.hard === true;
    this.paused = true;
    this.pausedHard = hard;
    this.emit('status', this.status());
    this.transparentProxy?.setPaused?.(true);
    await this.stopTrafficShaper();

    if (hard) {
      const proxy = this.transparentProxy;
      const stopTasks = [
        runWithTimeout('flow monitor stop', () => this.flowMonitor.stop({ flush: false })),
        runWithTimeout('transparent proxy stop', () => proxy?.stop({ flush: false })),
        runWithTimeout('redirect clear', () => this.trafficRedirect.clearRedirect()),
        runWithTimeout('arp spoofing stop', () => this.arpSpoofer.stopSpoofing())
      ];
      await Promise.allSettled(stopTasks);
      if (this.transparentProxy === proxy) {
        this.transparentProxy = null;
      }
    }
    this.emit('status', this.status());
    return this.status();
  }

  async resume() {
    if (!this.running) {
      throw new Error('MITM not running');
    }
    if (!this.paused) {
      return this.status();
    }

    this.paused = false;
    this.emit('status', this.status());
    try {
      this.transparentProxy?.setPaused?.(false);

      if (!this.pausedHard) {
        await this.startTrafficShaper();
        this.emit('status', this.status());
        return this.status();
      }

      if (this.transparentProxy) {
        await runWithTimeout('transparent proxy stop', () =>
          this.transparentProxy.stop({ flush: false })
        );
        this.transparentProxy = null;
      }

      const interfaces = await this.scanner.listInterfaces();
      const matchedInterface = interfaces.find((item) => item.name === this.interfaceName);
      const localIp = matchedInterface?.ip || null;

      if (this.hasRedirectPorts) {
        if (this.httpsIntercept) {
          await this.certificateManager.ensureCa();
        }
        this.transparentProxy = new TransparentProxy({
          port: this.proxyPort,
          host: '0.0.0.0',
          rulesStore: this.rulesStore,
          resourcesStore: this.resourcesStore,
          sessionsStore: this.sessionsStore,
          certificateManager: this.certificateManager,
          httpsMode: this.httpsIntercept ? 'mitm' : 'tunnel',
          capture: this.captureConfig
        });

        this.transparentProxy.on('session', (session) => {
          this.emit('session', session);
        });

        await this.transparentProxy.start(this.proxyPort, '0.0.0.0');

        await this.trafficRedirect.setupRedirect({
          httpPorts: this.redirectHttpSpec,
          httpsPorts: this.redirectHttpsSpec,
          proxyPort: this.proxyPort,
          localIp,
          targets: this.targets
        });
      }

      await this.startTrafficShaper();

      try {
        const ignorePortSpec = parsePortSpec([this.redirectHttpSpec, this.redirectHttpsSpec]);
        const monitorTcp =
          !hasPortSpec(this.redirectHttpSpec) || !hasPortSpec(this.redirectHttpsSpec);
        await this.flowMonitor.start({
          targets: this.targets,
          monitorUdp: true,
          monitorTcp,
          ignorePortSpec,
          localIp: this.hasRedirectPorts ? localIp ?? '127.0.0.1' : null,
          proxyPort: this.hasRedirectPorts ? this.proxyPort : null
        });
      } catch (error) {
        console.warn('[mitm] Flow monitor disabled:', error.message);
      }

      await runWithTimeout('arp spoofing start', () =>
        this.arpSpoofer.startSpoofing({
          interface: this.interfaceName,
          gateway: this.gateway,
          targets: this.targets
        })
      );
      this.pausedHard = false;
      this.emit('status', this.status());
      return this.status();
    } catch (error) {
      this.paused = true;
      this.emit('status', this.status());
      throw error;
    }
  }

  /**
   * 清理资源
   */
  async cleanup() {
    try {
      // 1. 停止 ARP 欺骗
      await this.arpSpoofer.stopSpoofing();

      // 2. 停止流量监控
      await this.flowMonitor.stop();

      // 3. 停止流量限速
      await this.stopTrafficShaper();

      // 4. 清除流量重定向
      await this.trafficRedirect.clearRedirect();

      // 5. 禁用 IP 转发
      await this.trafficRedirect.disableIpForwarding({ interfaceName: this.interfaceName });

      // 6. 停止透明代理
      if (this.transparentProxy) {
        await this.transparentProxy.stop();
        this.transparentProxy = null;
      }
    } catch (error) {
      console.error('[mitm] Cleanup error:', error);
      this.emit('error', { message: error.message });
    }
  }

  /**
   * 添加目标
   */
  async addTarget(target) {
    if (!this.running) {
      throw new Error('MITM not running');
    }

    this.targets.push(target);
    await this.arpSpoofer.addTarget(target);

    this.emit('status', this.status());
    return this.status();
  }

  /**
   * 移除目标
   */
  async removeTarget(targetIp) {
    if (!this.running) {
      throw new Error('MITM not running');
    }

    const index = this.targets.findIndex((t) => t.ip === targetIp);
    if (index !== -1) {
      this.targets.splice(index, 1);
      await this.arpSpoofer.removeTarget(targetIp);
    }

    this.emit('status', this.status());
    return this.status();
  }

  /**
   * 检查权限
   */
  async checkPrivileges() {
    return checkPrivileges();
  }

  /**
   * 请求权限提升
   */
  async requestPrivileges() {
    return requestElevation();
  }
}
