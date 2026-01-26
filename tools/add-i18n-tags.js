/**
 * 批量添加 i18n 标记到 HTML 文件
 * 运行: node tools/add-i18n-tags.js
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const htmlFile = path.join(__dirname, '../src/renderer/index.html');
let html = fs.readFileSync(htmlFile, 'utf-8');

console.log('Adding i18n tags to HTML...');

// 定义替换规则（按出现顺序）
const replacements = [
  // HTTPS 卡片
  { from: '<h2>HTTPS Intercept</h2>', to: '<h2 data-i18n="proxy.https">HTTPS 拦截</h2>' },
  { from: '<span class="label">Mode</span>', to: '<span class="label" data-i18n="proxy.https">HTTPS 拦截</span>', context: 'https' },
  { from: '<label for="https-intercept">Enable HTTPS interception</label>', to: '<label for="https-intercept" data-i18n="proxy.enable-https">启用 HTTPS 拦截</label>' },
  { from: '<label for="ca-path">CA Certificate Path</label>', to: '<label for="ca-path" data-i18n="cert.path">证书路径</label>' },
  { from: '<button id="ca-generate" type="button" class="button button--ghost">Generate CA</button>', to: '<button id="ca-generate" type="button" class="button button--ghost" data-i18n="cert.title">证书管理</button>' },
  { from: '<button id="ca-copy" type="button" class="button button--ghost">Copy Path</button>', to: '<button id="ca-copy" type="button" class="button button--ghost" data-i18n="cert.copy-path">复制路径</button>' },

  // MITM 卡片（已部分完成，补充剩余）
  { from: '<span class="label">Status</span>', to: '<span class="label" data-i18n="mitm.status">状态</span>', context: 'mitm' },
  { from: '<span class="label">Privileges</span>', to: '<span class="label" data-i18n="mitm.privileges">权限</span>' },
  { from: '<span class="label">Interface</span>', to: '<span class="label" data-i18n="mitm.interface">网络接口</span>' },
  { from: '<span class="label">Targets</span>', to: '<span class="label" data-i18n="mitm.targets">目标设备</span>' },
  { from: '<label for="mitm-interface-select">Network Interface</label>', to: '<label for="mitm-interface-select" data-i18n="mitm.interface">网络接口</label>' },
  { from: '<option value="">Select interface...</option>', to: '<option value="" data-i18n="mitm.interface.select">选择网络接口...</option>' },
  { from: '<button id="mitm-refresh-interfaces" type="button" class="button button--ghost button--small">Refresh</button>', to: '<button id="mitm-refresh-interfaces" type="button" class="button button--ghost button--small" data-i18n="mitm.interface.refresh">刷新</button>' },
  { from: '<label>Gateway</label>', to: '<label data-i18n="mitm.gateway">网关</label>' },
  { from: '<button id="mitm-detect-gateway" type="button" class="button button--ghost button--small">Detect Gateway</button>', to: '<button id="mitm-detect-gateway" type="button" class="button button--ghost button--small" data-i18n="mitm.gateway.detect">检测网关</button>' },
  { from: '<label>Devices</label>', to: '<label data-i18n="mitm.scan">扫描网络</label>' },
  { from: '<button id="mitm-scan-network" type="button" class="button button--ghost button--small">Scan Network</button>', to: '<button id="mitm-scan-network" type="button" class="button button--ghost button--small" data-i18n="mitm.scan.button">扫描设备</button>' },
  { from: '<label for="mitm-proxy-port">Transparent Proxy Port</label>', to: '<label for="mitm-proxy-port" data-i18n="mitm.proxy-port">透明代理端口</label>' },
  { from: '<button id="mitm-request-privileges" type="button" class="button button--ghost hidden">Request Admin Access</button>', to: '<button id="mitm-request-privileges" type="button" class="button button--ghost hidden" data-i18n="mitm.request-admin">请求管理员权限</button>' },
  { from: '<button id="mitm-start" type="button" class="button button--primary">Start MITM</button>', to: '<button id="mitm-start" type="button" class="button button--primary" data-i18n="mitm.start">启动 MITM</button>' },
  { from: '<button id="mitm-stop" type="button" class="button button--ghost">Stop</button>', to: '<button id="mitm-stop" type="button" class="button button--ghost" data-i18n="mitm.stop">停止</button>' },

  // 规则卡片
  { from: '<h2>Rules</h2>', to: '<h2 data-i18n="rules.title">规则管理</h2>' },
  { from: '<label for="rule-name">Name</label>', to: '<label for="rule-name" data-i18n="rules.name">规则名称</label>' },
  { from: 'placeholder="Replace hero image"', to: 'data-i18n-placeholder="rules.name" placeholder="替换图片"' },
  { from: '<label for="rule-priority">Priority</label>', to: '<label for="rule-priority">Priority</label>' },
  { from: '<label for="rule-url">URL Contains</label>', to: '<label for="rule-url" data-i18n="rules.url">URL 模式</label>' },
  { from: '<label for="rule-method">Method</label>', to: '<label for="rule-method" data-i18n="rules.method">方法</label>' },
  { from: '<label for="rule-content-type">Content-Type</label>', to: '<label for="rule-content-type" data-i18n="rules.content-type">Content-Type</label>' },
  { from: '<label for="rule-headers">Headers Contains</label>', to: '<label for="rule-headers" data-i18n="rules.header">请求头</label>' },
  { from: '<label for="rule-body-contains">Response Body Contains</label>', to: '<label for="rule-body-contains" data-i18n="rules.response-body">响应体包含</label>' },
  { from: '<label for="rule-action-type">Action</label>', to: '<label for="rule-action-type" data-i18n="rules.action">动作</label>' },
  { from: '<option value="replaceBody">Replace Body</option>', to: '<option value="replaceBody" data-i18n="rules.action.replace">替换响应体</option>' },
  { from: '<option value="replaceResource">Replace With Resource</option>', to: '<option value="replaceResource">Replace With Resource</option>' },
  { from: '<option value="block">Block</option>', to: '<option value="block" data-i18n="rules.action.block">阻断请求</option>' },
  { from: '<option value="redirect">Redirect</option>', to: '<option value="redirect" data-i18n="rules.action.redirect">重定向</option>' },
  { from: '<button id="rule-submit" type="submit" class="button button--primary">Add Rule</button>', to: '<button id="rule-submit" type="submit" class="button button--primary" data-i18n="rules.add">添加规则</button>' },
  { from: '<button id="rule-cancel" type="button" class="button button--ghost hidden">Cancel</button>', to: '<button id="rule-cancel" type="button" class="button button--ghost hidden" data-i18n="common.cancel">取消</button>' },

  // 资源卡片
  { from: '<h2>Resources</h2>', to: '<h2 data-i18n="resources.title">资源管理</h2>' },
  { from: '<label for="resource-name">Name</label>', to: '<label for="resource-name" data-i18n="resources.name">资源名称</label>' },
  { from: '<label for="resource-type">Content-Type</label>', to: '<label for="resource-type" data-i18n="rules.content-type">Content-Type</label>' },
  { from: '<label for="resource-file">File</label>', to: '<label for="resource-file">File</label>' },
  { from: '<button type="submit" class="button button--primary">Add Resource</button>', to: '<button type="submit" class="button button--primary" data-i18n="resources.add">添加资源</button>' },

  // 会话卡片
  { from: '<h2>Sessions</h2>', to: '<h2 data-i18n="sessions.title">会话日志</h2>' },
  { from: '<button id="sessions-clear" class="button button--ghost">Clear</button>', to: '<button id="sessions-clear" class="button button--ghost" data-i18n="sessions.clear">清空</button>' },
  { from: 'placeholder="Filter by URL or method"', to: 'data-i18n-placeholder="sessions.filter" placeholder="按 URL 或方法过滤"' }
];

// 执行替换
let replacedCount = 0;
replacements.forEach(({ from, to, context }) => {
  if (html.includes(from)) {
    html = html.replace(from, to);
    replacedCount++;
    console.log(`✓ Replaced: ${from.substring(0, 50)}...`);
  } else {
    console.log(`⚠ Not found: ${from.substring(0, 50)}...`);
  }
});

// 写回文件
fs.writeFileSync(htmlFile, html, 'utf-8');

console.log(`\n✓ Done! ${replacedCount}/${replacements.length} replacements made.`);
console.log(`Updated file: ${htmlFile}`);
