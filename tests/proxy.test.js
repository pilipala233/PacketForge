import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import forge from 'node-forge';
import { ProxyServer } from '../src/core/proxy.js';
import { createCertificateManager } from '../src/core/certs.js';
import { createResourcesStore, createRulesStore, createSessionsStore } from '../src/core/stores.js';

async function listen(server, host) {
  return new Promise((resolve) => {
    server.listen(0, host, () => resolve(server.address().port));
  });
}

async function withTempDir(fn) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'packetforge-'));
  try {
    return await fn(base);
  } finally {
    await fs.rm(base, { recursive: true, force: true });
  }
}

function createSelfSignedCert(host) {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 1024, workers: -1 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  const notBefore = new Date();
  const notAfter = new Date(notBefore);
  notAfter.setDate(notAfter.getDate() + 2);
  cert.validity.notBefore = notBefore;
  cert.validity.notAfter = notAfter;
  const attrs = [{ name: 'commonName', value: host }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'subjectAltName', altNames: [{ type: 7, ip: host }] }
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    key: forge.pki.privateKeyToPem(keys.privateKey),
    cert: forge.pki.certificateToPem(cert)
  };
}

function readUntil(socket, delimiter) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    function onData(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      const index = buffer.indexOf(delimiter);
      if (index !== -1) {
        socket.off('data', onData);
        const head = buffer.slice(0, index + delimiter.length);
        const rest = buffer.slice(index + delimiter.length);
        resolve({ head, rest });
      }
    }
    socket.on('data', onData);
    socket.once('error', reject);
  });
}

test('proxy replaces response body when rule matches', async () => {
  await withTempDir(async (dir) => {
    const target = http.createServer((req, res) => {
      const body = 'hello';
      res.writeHead(200, {
        'content-type': 'text/plain',
        'content-length': String(Buffer.byteLength(body))
      });
      res.end(body);
    });

    const targetPort = await listen(target, '127.0.0.1');

    const rulesStore = createRulesStore(path.join(dir, 'rules.json'));
    const resourcesStore = createResourcesStore(path.join(dir, 'resources.json'));
    const sessionsStore = createSessionsStore(path.join(dir, 'sessions.json'));

    await rulesStore.load();
    await resourcesStore.load();
    await sessionsStore.load();

    await rulesStore.add({
      name: 'Replace hello',
      when: { urlIncludes: '/test', contentType: 'text/plain' },
      action: { type: 'replaceBody', body: 'patched', bodyType: 'text' }
    });

    const proxy = new ProxyServer({
      port: 0,
      host: '127.0.0.1',
      rulesStore,
      resourcesStore,
      sessionsStore
    });
    await proxy.start(0);

    const proxyPort = proxy.status().port;

    const body = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port: proxyPort,
          method: 'GET',
          path: `http://127.0.0.1:${targetPort}/test`
        },
        (res) => {
          const chunks = [];
          res.on('data', (chunk) => chunks.push(chunk));
          res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        }
      );
      req.on('error', reject);
      req.end();
    });

    assert.equal(body, 'patched');
    assert.equal(sessionsStore.list().length, 1);
    assert.equal(sessionsStore.list()[0].applied, true);

    await proxy.flush();
    await proxy.stop();
    await new Promise((resolve) => target.close(() => resolve()));
  });
});

test('proxy intercepts HTTPS with MITM enabled', async () => {
  await withTempDir(async (dir) => {
    const cert = createSelfSignedCert('127.0.0.1');
    const target = https.createServer({ key: cert.key, cert: cert.cert }, (req, res) => {
      const body = 'secure';
      res.writeHead(200, {
        'content-type': 'text/plain',
        'content-length': String(Buffer.byteLength(body))
      });
      res.end(body);
    });

    const targetPort = await listen(target, '127.0.0.1');

    const rulesStore = createRulesStore(path.join(dir, 'rules.json'));
    const resourcesStore = createResourcesStore(path.join(dir, 'resources.json'));
    const sessionsStore = createSessionsStore(path.join(dir, 'sessions.json'));
    const certificateManager = createCertificateManager(path.join(dir, 'certs'), {
      caKeyBits: 1024,
      certKeyBits: 1024,
      caValidDays: 2,
      certValidDays: 2
    });

    await rulesStore.load();
    await resourcesStore.load();
    await sessionsStore.load();

    await rulesStore.add({
      name: 'Replace secure',
      when: { urlIncludes: '/secure', contentType: 'text/plain' },
      action: { type: 'replaceBody', body: 'patched', bodyType: 'text' }
    });

    const proxy = new ProxyServer({
      port: 0,
      host: '127.0.0.1',
      rulesStore,
      resourcesStore,
      sessionsStore,
      httpsMode: 'mitm',
      certificateManager
    });
    await proxy.start(0);

    const proxyPort = proxy.status().port;
    const previousReject = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

    try {
      const socket = net.connect(proxyPort, '127.0.0.1');
      socket.write(`CONNECT 127.0.0.1:${targetPort} HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\n\r\n`);
      const { head, rest } = await readUntil(socket, '\r\n\r\n');
      assert.ok(head.toString('utf8').includes('200'));
      if (rest.length > 0) {
        socket.unshift(rest);
      }

      const caCert = await certificateManager.getCaCertificate();
      const tlsSocket = tls.connect({
        socket,
        servername: '127.0.0.1',
        ca: caCert
      });

      await new Promise((resolve, reject) => {
        tlsSocket.once('secureConnect', resolve);
        tlsSocket.once('error', reject);
      });

      const request = [
        'GET /secure HTTP/1.1',
        `Host: 127.0.0.1:${targetPort}`,
        'Connection: close',
        '',
        ''
      ].join('\r\n');
      tlsSocket.write(request);

      const response = await new Promise((resolve, reject) => {
        const chunks = [];
        tlsSocket.on('data', (chunk) => chunks.push(chunk));
        tlsSocket.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        tlsSocket.on('error', reject);
      });

      const body = response.split('\r\n\r\n')[1] || '';
      assert.equal(body, 'patched');
      assert.equal(sessionsStore.list().length, 1);
      assert.equal(sessionsStore.list()[0].applied, true);
    } finally {
      if (previousReject === undefined) {
        delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
      } else {
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = previousReject;
      }
    }

    await proxy.flush();
    await proxy.stop();
    await new Promise((resolve) => target.close(() => resolve()));
  });
});
