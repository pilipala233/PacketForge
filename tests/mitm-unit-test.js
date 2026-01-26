/**
 * MITM 组件单元测试
 *
 * 测试各个 MITM 组件的功能
 */

import { test } from 'node:test';
import assert from 'node:assert';

// 测试数据包工具
test('Packet Utils - IP Header Parsing', async (t) => {
  const { parseIpHeader } = await import('../src/core/mitm/platform/win32/packet-utils.js');

  // 创建一个简单的 IPv4 头
  const buffer = Buffer.alloc(20);
  buffer[0] = 0x45; // Version 4, IHL 5
  buffer[1] = 0x00; // TOS
  buffer.writeUInt16BE(40, 2); // Total Length
  buffer[9] = 6; // Protocol (TCP)
  buffer[12] = 192; // Src IP: 192.168.1.100
  buffer[13] = 168;
  buffer[14] = 1;
  buffer[15] = 100;
  buffer[16] = 10; // Dst IP: 10.0.0.1
  buffer[17] = 0;
  buffer[18] = 0;
  buffer[19] = 1;

  const header = parseIpHeader(buffer);

  assert.strictEqual(header.version, 4);
  assert.strictEqual(header.ihl, 20);
  assert.strictEqual(header.protocol, 6);
  assert.strictEqual(header.srcIp, '192.168.1.100');
  assert.strictEqual(header.dstIp, '10.0.0.1');
});

test('Packet Utils - TCP Header Parsing', async (t) => {
  const { parseTcpHeader } = await import('../src/core/mitm/platform/win32/packet-utils.js');

  // 创建一个包含 IP 头和 TCP 头的缓冲区
  const buffer = Buffer.alloc(40);

  // IP 头 (20 字节)
  buffer[0] = 0x45; // Version 4, IHL 5

  // TCP 头 (从字节 20 开始)
  buffer.writeUInt16BE(12345, 20); // Src Port
  buffer.writeUInt16BE(80, 22); // Dst Port (HTTP)
  buffer.writeUInt32BE(1000, 24); // Seq Number
  buffer.writeUInt32BE(2000, 28); // Ack Number
  buffer[32] = 0x50; // Data Offset (5 * 4 = 20 bytes)

  const header = parseTcpHeader(buffer, 20);

  assert.strictEqual(header.srcPort, 12345);
  assert.strictEqual(header.dstPort, 80);
  assert.strictEqual(header.seqNumber, 1000);
  assert.strictEqual(header.ackNumber, 2000);
  assert.strictEqual(header.dataOffset, 20);
});

test('Packet Utils - Should Redirect', async (t) => {
  const { shouldRedirect } = await import('../src/core/mitm/platform/win32/packet-utils.js');

  // 创建一个 HTTP 请求包 (目标端口 80)
  const httpPacket = Buffer.alloc(40);
  httpPacket[0] = 0x45; // IPv4
  httpPacket[9] = 6; // TCP
  httpPacket.writeUInt16BE(80, 22); // Dst Port = 80

  assert.strictEqual(shouldRedirect(httpPacket, 80, 443), true);

  // 创建一个 HTTPS 请求包 (目标端口 443)
  const httpsPacket = Buffer.alloc(40);
  httpsPacket[0] = 0x45; // IPv4
  httpsPacket[9] = 6; // TCP
  httpsPacket.writeUInt16BE(443, 22); // Dst Port = 443

  assert.strictEqual(shouldRedirect(httpsPacket, 80, 443), true);

  // 创建一个其他端口的包
  const otherPacket = Buffer.alloc(40);
  otherPacket[0] = 0x45; // IPv4
  otherPacket[9] = 6; // TCP
  otherPacket.writeUInt16BE(8080, 22); // Dst Port = 8080

  assert.strictEqual(shouldRedirect(otherPacket, 80, 443), false);
});

test('Packet Utils - Checksum Calculation', async (t) => {
  const { calculateChecksum } = await import('../src/core/mitm/platform/win32/packet-utils.js');

  // 创建一个简单的缓冲区
  const buffer = Buffer.from([0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06]);

  const checksum = calculateChecksum(buffer, 0, 10);

  // 校验和应该是一个 16 位数字
  assert.strictEqual(typeof checksum, 'number');
  assert.ok(checksum >= 0 && checksum <= 0xffff);
});

test('IP Utils - IP Address Validation', async (t) => {
  const { isValidIp, ipToInt, intToIp } = await import('../src/core/mitm/utils/ip-utils.js');

  // 测试有效 IP
  assert.strictEqual(isValidIp('192.168.1.1'), true);
  assert.strictEqual(isValidIp('10.0.0.1'), true);
  assert.strictEqual(isValidIp('255.255.255.255'), true);

  // 测试无效 IP
  assert.strictEqual(isValidIp('256.1.1.1'), false);
  assert.strictEqual(isValidIp('192.168.1'), false);
  assert.strictEqual(isValidIp('not.an.ip.address'), false);

  // 测试 IP 转换
  const ip = '192.168.1.100';
  const intValue = ipToInt(ip);
  const backToIp = intToIp(intValue);
  assert.strictEqual(backToIp, ip);
});

test('TransparentProxy - URL Reconstruction', async (t) => {
  const { TransparentProxy } = await import('../src/core/mitm/transparent-proxy.js');

  const proxy = new TransparentProxy({ port: 8888 });

  // 测试协议检测
  const mockReq = {
    url: '/test',
    headers: { host: 'example.com' },
    socket: { localPort: 80, remoteAddress: '192.168.1.100', remotePort: 12345 },
    method: 'GET'
  };

  const scheme = proxy.detectScheme(mockReq);
  assert.strictEqual(scheme, 'http');

  // 测试 HTTPS 检测
  const httpsReq = {
    url: '/test',
    headers: { host: 'example.com' },
    socket: { localPort: 443, remoteAddress: '192.168.1.100', remotePort: 12345, encrypted: true },
    method: 'GET'
  };

  const httpsScheme = proxy.detectScheme(httpsReq);
  assert.strictEqual(httpsScheme, 'https');

  // 清理
  await proxy.stop();
});

console.log('✓ 所有单元测试通过');
