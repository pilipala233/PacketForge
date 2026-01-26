/**
 * 国际化（i18n）系统
 * 支持中文和英文双语切换
 */

// 语言包
const translations = {
  'zh-CN': {
    // 应用标题
    'app.title': 'PacketForge',
    'app.subtitle': '授权代理工具 - 本地测试专用',

    // 代理控制
    'proxy.title': '代理控制',
    'proxy.status': '状态',
    'proxy.status.running': '运行中',
    'proxy.status.stopped': '已停止',
    'proxy.port': '端口',
    'proxy.https': 'HTTPS 拦截',
    'proxy.https.enabled': '已启用',
    'proxy.https.disabled': '已禁用',
    'proxy.start': '启动代理',
    'proxy.stop': '停止代理',
    'proxy.enable-https': '启用 HTTPS',
    'proxy.disable-https': '禁用 HTTPS',

    // 证书管理
    'cert.title': '证书管理',
    'cert.path': '证书路径',
    'cert.copy-path': '复制路径',
    'cert.install-guide': '安装指南',
    'cert.guide.title': 'CA 证书安装指南',
    'cert.guide.windows': 'Windows: 双击证书 → 安装证书 → 本地计算机 → 受信任的根证书颁发机构',
    'cert.guide.macos': 'macOS: 双击证书 → 钥匙串访问 → 系统 → 始终信任',
    'cert.guide.warning': '⚠️ 仅在测试环境安装此证书',

    // 规则管理
    'rules.title': '规则管理',
    'rules.add': '添加规则',
    'rules.edit': '编辑',
    'rules.delete': '删除',
    'rules.enable': '启用',
    'rules.disable': '禁用',
    'rules.name': '规则名称',
    'rules.condition': '条件',
    'rules.action': '动作',
    'rules.method': '方法',
    'rules.url': 'URL 模式',
    'rules.header': '请求头',
    'rules.content-type': 'Content-Type',
    'rules.response-body': '响应体包含',
    'rules.action.replace': '替换响应体',
    'rules.action.block': '阻断请求',
    'rules.action.redirect': '重定向',
    'rules.action.modify-headers': '修改头部',
    'rules.replacement': '替换内容',
    'rules.resource': '资源文件',
    'rules.status-code': '状态码',
    'rules.redirect-url': '重定向 URL',
    'rules.save': '保存',
    'rules.cancel': '取消',

    // 资源管理
    'resources.title': '资源管理',
    'resources.add': '添加资源',
    'resources.name': '资源名称',
    'resources.path': '文件路径',
    'resources.browse': '浏览',
    'resources.delete': '删除',

    // 会话日志
    'sessions.title': '会话日志',
    'sessions.clear': '清空',
    'sessions.pause': '暂停',
    'sessions.resume': '继续',
    'sessions.method': '方法',
    'sessions.url': 'URL',
    'sessions.status': '状态',
    'sessions.time': '时间',
    'sessions.matched-rule': '匹配规则',
    'sessions.no-rule': '无',
    'sessions.hideUdp': '\u9690\u85cf UDP',
    'sessions.maxEntries': '\u4f1a\u8bdd\u4e0a\u9650',
    'sessions.detail': '会话详情',
    'sessions.detail.empty': '请选择一条会话查看详情。',

    // MITM 控制
    'mitm.title': '局域网 MITM',
    'mitm.warning': '⚠️ 仅用于授权测试环境',
    'mitm.help': '帮助',
    'mitm.status': '状态',
    'mitm.status.active': '运行中',
    'mitm.status.inactive': '未激活',
    'mitm.status.paused': '已暂停',
    'mitm.privileges': '权限',
    'mitm.privileges.elevated': '已提权',
    'mitm.privileges.not-elevated': '未提权',
    'mitm.privileges.checking': '检查中...',
    'mitm.interface': '网络接口',
    'mitm.targets': '目标设备',
    'mitm.targets.count': '已选择',
    'mitm.interface.select': '选择网络接口',
    'mitm.interface.refresh': '刷新',
    'mitm.gateway': '网关',
    'mitm.gateway.detect': '检测网关',
    'mitm.scan': '扫描网络',
    'mitm.scan.button': '扫描设备',
    'mitm.proxy-port': '透明代理端口',
    'mitm.http-ports': 'HTTP 端口范围',
    'mitm.https-ports': 'HTTPS 端口范围',
    'mitm.https.observe': 'HTTPS 仅记录域名 (SNI)',
    'mitm.https.observe.hint': '不解密 HTTPS，不需要安装证书',
    'mitm.throttle.upload': '\u4e0a\u4f20\u9650\u901f (KB/s)',
    'mitm.throttle.download': '\u4e0b\u8f7d\u9650\u901f (KB/s)',
    'mitm.throttle.hint': '0 \u8868\u793a\u4e0d\u9650\u901f\uff0c\u6309\u76ee\u6807\u8bbe\u5907\u751f\u6548',
    'mitm.request-admin': '以管理员身份重启',
    'mitm.start': '启动 MITM',
    'mitm.stop': '停止',
    'mitm.device.select-all': '全选',
    'mitm.device.deselect-all': '取消全选',

    // 会话存档
    'capture.title': '会话存档',
    'capture.dir': '保存目录',
    'capture.browse': '选择',
    'capture.max-size': '单次上限 (MB)',
    'capture.hint': '超过上限仅保存前 N MB',
    'capture.ffmpeg-path': 'FFmpeg Path',
    'capture.ffmpeg-browse': 'Browse',
    'capture.auto-convert': 'Auto Convert',
    'capture.auto-convert.off': 'Off',
    'capture.auto-convert.remux': 'FLV -> MP4 (remux)',
    'capture.auto-convert.h264': 'FLV -> MP4 (H.264)',
    'capture.ffmpeg-hint': 'Requires ffmpeg executable',

    // 设置
    'settings.title': '设置',
    'settings.language': '语言',
    'settings.language.zh-CN': '简体中文',
    'settings.language.en-US': 'English',
    'settings.theme': '主题',
    'settings.theme.light': '浅色',
    'settings.theme.dark': '深色',
    'settings.theme.auto': '跟随系统',

    // Scope Panel
    'scope.title': '适用范围',
    'scope.description': 'PacketForge 仅适用于经授权的本地测试。您必须拥有拦截或修改流量的明确许可。',
    'scope.mode': '模式',
    'scope.mode.explicit': '隐性监听',

    // 通用
    'common.save': '保存',
    'common.cancel': '取消',
    'common.delete': '删除',
    'common.edit': '编辑',
    'common.add': '添加',
    'common.close': '关闭',
    'common.confirm': '确认',
    'common.copy': '复制',
    'common.open': '打开',
    'common.yes': '是',
    'common.no': '否',
    'common.ok': '确定',
    'common.loading': '加载中...',
    'common.error': '错误',
    'common.success': '成功',
    'common.warning': '警告',

    // 错误消息
    'error.proxy-start': '启动代理失败',
    'error.proxy-stop': '停止代理失败',
    'error.rule-save': '保存规则失败',
    'error.rule-delete': '删除规则失败',
    'error.resource-add': '添加资源失败',
    'error.mitm-start': '启动 MITM 失败',
    'error.mitm-stop': '停止 MITM 失败',
    'error.privileges': '权限不足',

    // 成功消息
    'success.proxy-started': '代理已启动',
    'success.proxy-stopped': '代理已停止',
    'success.rule-saved': '规则已保存',
    'success.rule-deleted': '规则已删除',
    'success.resource-added': '资源已添加',
    'success.mitm-started': 'MITM 已启动',
    'success.mitm-stopped': 'MITM 已停止'
  },

  'en-US': {
    // App title
    'app.title': 'PacketForge',
    'app.subtitle': 'Authorized Proxy Tool - For Local Testing Only',

    // Proxy control
    'proxy.title': 'Proxy Control',
    'proxy.status': 'Status',
    'proxy.status.running': 'Running',
    'proxy.status.stopped': 'Stopped',
    'proxy.port': 'Port',
    'proxy.https': 'HTTPS Intercept',
    'proxy.https.enabled': 'Enabled',
    'proxy.https.disabled': 'Disabled',
    'proxy.start': 'Start Proxy',
    'proxy.stop': 'Stop Proxy',
    'proxy.enable-https': 'Enable HTTPS',
    'proxy.disable-https': 'Disable HTTPS',

    // Certificate management
    'cert.title': 'Certificate Management',
    'cert.path': 'Certificate Path',
    'cert.copy-path': 'Copy Path',
    'cert.install-guide': 'Installation Guide',
    'cert.guide.title': 'CA Certificate Installation Guide',
    'cert.guide.windows': 'Windows: Double-click cert → Install Certificate → Local Machine → Trusted Root Certification Authorities',
    'cert.guide.macos': 'macOS: Double-click cert → Keychain Access → System → Always Trust',
    'cert.guide.warning': '⚠️ Only install this certificate in testing environments',

    // Rules management
    'rules.title': 'Rules Management',
    'rules.add': 'Add Rule',
    'rules.edit': 'Edit',
    'rules.delete': 'Delete',
    'rules.enable': 'Enable',
    'rules.disable': 'Disable',
    'rules.name': 'Rule Name',
    'rules.condition': 'Condition',
    'rules.action': 'Action',
    'rules.method': 'Method',
    'rules.url': 'URL Pattern',
    'rules.header': 'Request Header',
    'rules.content-type': 'Content-Type',
    'rules.response-body': 'Response Body Contains',
    'rules.action.replace': 'Replace Response',
    'rules.action.block': 'Block Request',
    'rules.action.redirect': 'Redirect',
    'rules.action.modify-headers': 'Modify Headers',
    'rules.replacement': 'Replacement',
    'rules.resource': 'Resource File',
    'rules.status-code': 'Status Code',
    'rules.redirect-url': 'Redirect URL',
    'rules.save': 'Save',
    'rules.cancel': 'Cancel',

    // Resources management
    'resources.title': 'Resources Management',
    'resources.add': 'Add Resource',
    'resources.name': 'Resource Name',
    'resources.path': 'File Path',
    'resources.browse': 'Browse',
    'resources.delete': 'Delete',

    // Session logs
    'sessions.title': 'Session Logs',
    'sessions.clear': 'Clear',
    'sessions.pause': 'Pause',
    'sessions.resume': 'Resume',
    'sessions.method': 'Method',
    'sessions.url': 'URL',
    'sessions.status': 'Status',
    'sessions.time': 'Time',
    'sessions.matched-rule': 'Matched Rule',
    'sessions.no-rule': 'None',
    'sessions.hideUdp': 'Hide UDP',
    'sessions.maxEntries': 'Session Limit',
    'sessions.detail': 'Session Detail',
    'sessions.detail.empty': 'Select a session to inspect.',

    // MITM control
    'mitm.title': 'LAN MITM',
    'mitm.warning': '⚠️ For authorized testing environments only',
    'mitm.help': 'Help',
    'mitm.status': 'Status',
    'mitm.status.active': 'Active',
    'mitm.status.inactive': 'Inactive',
    'mitm.status.paused': 'Paused',
    'mitm.privileges': 'Privileges',
    'mitm.privileges.elevated': 'Elevated',
    'mitm.privileges.not-elevated': 'Not Elevated',
    'mitm.privileges.checking': 'Checking...',
    'mitm.interface': 'Network Interface',
    'mitm.targets': 'Target Devices',
    'mitm.targets.count': 'Selected',
    'mitm.interface.select': 'Select Network Interface',
    'mitm.interface.refresh': 'Refresh',
    'mitm.gateway': 'Gateway',
    'mitm.gateway.detect': 'Detect Gateway',
    'mitm.scan': 'Scan Network',
    'mitm.scan.button': 'Scan Devices',
    'mitm.proxy-port': 'Transparent Proxy Port',
    'mitm.http-ports': 'HTTP Port Range',
    'mitm.https-ports': 'HTTPS Port Range',
    'mitm.https.observe': 'HTTPS SNI only',
    'mitm.https.observe.hint': 'No decryption; no CA install required',
    'mitm.throttle.upload': 'Upload limit (KB/s)',
    'mitm.throttle.download': 'Download limit (KB/s)',
    'mitm.throttle.hint': '0 = no limit (per target)',
    'mitm.request-admin': 'Restart as Admin',
    'mitm.start': 'Start MITM',
    'mitm.stop': 'Stop',
    'mitm.device.select-all': 'Select All',
    'mitm.device.deselect-all': 'Deselect All',

    // Session capture
    'capture.title': 'Session Capture',
    'capture.dir': 'Storage folder',
    'capture.browse': 'Browse',
    'capture.max-size': 'Max per body (MB)',
    'capture.hint': 'Only the first N MB are saved when exceeding the limit',
    'capture.ffmpeg-path': 'FFmpeg Path',
    'capture.ffmpeg-browse': 'Browse',
    'capture.auto-convert': 'Auto Convert',
    'capture.auto-convert.off': 'Off',
    'capture.auto-convert.remux': 'FLV -> MP4 (remux)',
    'capture.auto-convert.h264': 'FLV -> MP4 (H.264)',
    'capture.ffmpeg-hint': 'Requires ffmpeg executable',

    // Settings
    'settings.title': 'Settings',
    'settings.language': 'Language',
    'settings.language.zh-CN': '简体中文',
    'settings.language.en-US': 'English',
    'settings.theme': 'Theme',
    'settings.theme.light': 'Light',
    'settings.theme.dark': 'Dark',
    'settings.theme.auto': 'Auto',

    // Scope Panel
    'scope.title': 'Scope',
    'scope.description': 'PacketForge is intended for authorized, local testing only. You must have explicit permission to intercept or modify traffic.',
    'scope.mode': 'Mode',
    'scope.mode.explicit': 'Transparent MITM',

    // Common
    'common.save': 'Save',
    'common.cancel': 'Cancel',
    'common.delete': 'Delete',
    'common.edit': 'Edit',
    'common.add': 'Add',
    'common.close': 'Close',
    'common.confirm': 'Confirm',
    'common.copy': 'Copy',
    'common.open': 'Open',
    'common.yes': 'Yes',
    'common.no': 'No',
    'common.ok': 'OK',
    'common.loading': 'Loading...',
    'common.error': 'Error',
    'common.success': 'Success',
    'common.warning': 'Warning',

    // Error messages
    'error.proxy-start': 'Failed to start proxy',
    'error.proxy-stop': 'Failed to stop proxy',
    'error.rule-save': 'Failed to save rule',
    'error.rule-delete': 'Failed to delete rule',
    'error.resource-add': 'Failed to add resource',
    'error.mitm-start': 'Failed to start MITM',
    'error.mitm-stop': 'Failed to stop MITM',
    'error.privileges': 'Insufficient privileges',

    // Success messages
    'success.proxy-started': 'Proxy started',
    'success.proxy-stopped': 'Proxy stopped',
    'success.rule-saved': 'Rule saved',
    'success.rule-deleted': 'Rule deleted',
    'success.resource-added': 'Resource added',
    'success.mitm-started': 'MITM started',
    'success.mitm-stopped': 'MITM stopped'
  }
};

// 当前语言
let currentLanguage = 'zh-CN';

/**
 * 初始化 i18n 系统
 */
export function initI18n() {
  // 从 localStorage 读取用户偏好
  const savedLanguage = localStorage.getItem('language');
  if (savedLanguage && translations[savedLanguage]) {
    currentLanguage = savedLanguage;
  } else {
    // 检测系统语言
    const systemLanguage = navigator.language || navigator.userLanguage;
    if (systemLanguage.startsWith('zh')) {
      currentLanguage = 'zh-CN';
    } else {
      currentLanguage = 'en-US';
    }
  }

  // 应用翻译
  applyTranslations();
}

/**
 * 获取翻译文本
 * @param {string} key - 翻译键
 * @param {object} params - 参数（用于插值）
 * @returns {string}
 */
export function t(key, params = {}) {
  let text = translations[currentLanguage]?.[key] || key;

  // 参数插值
  Object.keys(params).forEach((param) => {
    text = text.replace(`{${param}}`, params[param]);
  });

  return text;
}

/**
 * 切换语言
 * @param {string} language - 语言代码 (zh-CN 或 en-US)
 */
export function setLanguage(language) {
  if (!translations[language]) {
    console.error(`Language ${language} not supported`);
    return;
  }

  currentLanguage = language;
  localStorage.setItem('language', language);
  applyTranslations();
}

/**
 * 获取当前语言
 * @returns {string}
 */
export function getCurrentLanguage() {
  return currentLanguage;
}

/**
 * 应用翻译到页面
 */
function applyTranslations() {
  // 翻译所有带 data-i18n 属性的元素
  document.querySelectorAll('[data-i18n]').forEach((element) => {
    const key = element.getAttribute('data-i18n');
    element.textContent = t(key);
  });

  // 翻译所有带 data-i18n-placeholder 属性的元素
  document.querySelectorAll('[data-i18n-placeholder]').forEach((element) => {
    const key = element.getAttribute('data-i18n-placeholder');
    element.placeholder = t(key);
  });

  // 翻译所有带 data-i18n-title 属性的元素
  document.querySelectorAll('[data-i18n-title]').forEach((element) => {
    const key = element.getAttribute('data-i18n-title');
    element.title = t(key);
  });

  // 触发语言变更事件
  document.dispatchEvent(new CustomEvent('languageChanged', { detail: { language: currentLanguage } }));
}

/**
 * 获取所有支持的语言
 * @returns {Array}
 */
export function getSupportedLanguages() {
  return [
    { code: 'zh-CN', name: '简体中文' },
    { code: 'en-US', name: 'English' }
  ];
}
