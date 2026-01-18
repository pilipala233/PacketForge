import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createCertificateManager } from '../src/core/certs.js';

async function withTempDir(fn) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'packetforge-'));
  try {
    return await fn(base);
  } finally {
    await fs.rm(base, { recursive: true, force: true });
  }
}

test('certificate manager creates CA and host certificates', async () => {
  await withTempDir(async (dir) => {
    const manager = createCertificateManager(dir, {
      caKeyBits: 1024,
      certKeyBits: 1024,
      caValidDays: 2,
      certValidDays: 2
    });

    const statusBefore = await manager.status();
    assert.equal(statusBefore.ready, false);

    const caCert = await manager.getCaCertificate();
    assert.ok(caCert.includes('BEGIN CERTIFICATE'));

    const statusAfter = await manager.status();
    assert.equal(statusAfter.ready, true);

    const hostCert = await manager.getCertificate('example.com');
    assert.ok(hostCert.certPem.includes('BEGIN CERTIFICATE'));
    assert.ok(
      hostCert.keyPem.includes('BEGIN PRIVATE KEY') ||
        hostCert.keyPem.includes('BEGIN RSA PRIVATE KEY')
    );
  });
});
