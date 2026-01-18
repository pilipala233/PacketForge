# PacketForge

PacketForge 是面向授权、本地测试的桌面代理工具。MVP 聚焦显式代理模式（手动代理配置），
支持请求/响应替换与规则驱动管线。

PacketForge is a desktop proxy tool for authorized, local testing. The MVP focuses
on explicit proxy mode (manual proxy configuration) with request/response
replacement and a rule-based pipeline.

## MVP 目标 / Goals (MVP)
中文：
- 显式 HTTP/HTTPS 代理（仅限授权环境）
- 规则条件：方法/URL/头/内容类型/响应体片段
- 动作：替换/阻断/重定向/资源替换
- 会话日志与轻量 UI

English:
- Explicit HTTP/HTTPS proxy (authorized environments only)
- Rule conditions: method/url/header/content-type/response body snippet
- Actions: replace/block/redirect/resource swap
- Session logging and lightweight UI

## 开发 / Development
```bash
npm install
npm run dev
```

## 测试 / Tests
```bash
npm test
```

## 打包 / Packaging
```bash
npm run dist
```

## HTTPS 拦截（授权）/ HTTPS Intercept (Authorized)
中文：在 UI 中显式启用后可进行 HTTPS 拦截。应用会在数据目录生成本地 CA 证书，
需将其安装到系统/浏览器信任库以启用替换功能。可使用界面中的 Copy Path
快速定位证书路径。

English: PacketForge can intercept HTTPS when explicitly enabled in the UI. The app
will generate a local CA certificate under the app data directory; install it in
your OS/browser trust store for HTTPS replacement to work. Use the in-app Copy Path
button to locate the certificate.

## 注意 / Notes
中文：
- 本项目仅用于授权测试环境。
- 使用本工具即表示你已获得明确授权。

English:
- This project is intended for authorized testing environments only.
- By using this tool, you confirm you have explicit authorization.
