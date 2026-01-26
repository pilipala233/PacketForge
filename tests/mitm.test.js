/**
 * MITM 模块基础测试
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { NetworkScanner } from '../src/core/mitm/scanner.js';
import { checkPrivileges } from '../src/core/mitm/utils/privileges.js';
import { isValidIp, isValidMac, normalizeMac } from '../src/core/mitm/utils/ip-utils.js';

describe('MITM Utils', () => {
  it('should validate IP addresses', () => {
    assert.strictEqual(isValidIp('192.168.1.1'), true);
    assert.strictEqual(isValidIp('255.255.255.255'), true);
    assert.strictEqual(isValidIp('256.1.1.1'), false);
    assert.strictEqual(isValidIp('192.168.1'), false);
    assert.strictEqual(isValidIp('invalid'), false);
  });

  it('should validate MAC addresses', () => {
    assert.strictEqual(isValidMac('aa:bb:cc:dd:ee:ff'), true);
    assert.strictEqual(isValidMac('AA:BB:CC:DD:EE:FF'), true);
    assert.strictEqual(isValidMac('aa-bb-cc-dd-ee-ff'), true);
    assert.strictEqual(isValidMac('invalid'), false);
    assert.strictEqual(isValidMac('aa:bb:cc:dd:ee'), false);
  });

  it('should normalize MAC addresses', () => {
    assert.strictEqual(normalizeMac('AA-BB-CC-DD-EE-FF'), 'aa:bb:cc:dd:ee:ff');
    assert.strictEqual(normalizeMac('aa:bb:cc:dd:ee:ff'), 'aa:bb:cc:dd:ee:ff');
  });
});

describe('NetworkScanner', () => {
  it('should list network interfaces', async () => {
    const scanner = new NetworkScanner();
    const interfaces = await scanner.listInterfaces();

    assert.ok(Array.isArray(interfaces));
    console.log('Network interfaces:', interfaces);
  });

  it('should get gateway', async () => {
    const scanner = new NetworkScanner();
    const interfaces = await scanner.listInterfaces();

    if (interfaces.length > 0) {
      const gateway = await scanner.getGateway(interfaces[0].name);
      console.log('Gateway:', gateway);
    }
  });
});

describe('Privileges', () => {
  it('should check privileges', async () => {
    const result = await checkPrivileges();
    assert.ok(typeof result.elevated === 'boolean');
    console.log('Privileges:', result);
  });
});
