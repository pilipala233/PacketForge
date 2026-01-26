import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import forge from 'node-forge';

const DEFAULT_CA_SUBJECT = [
  { name: 'commonName', value: 'PacketForge Local CA' },
  { name: 'organizationName', value: 'PacketForge' }
];

function normalizeHost(host) {
  if (!host) {
    return '';
  }
  return host.replace(/^\[/, '').replace(/\]$/, '');
}

function sanitizeHost(host) {
  const normalized = normalizeHost(host);
  if (!normalized) {
    return 'unknown';
  }
  return normalized.replace(/[^a-zA-Z0-9.-]/g, '_');
}

function createSerialNumber() {
  return randomBytes(16).toString('hex');
}

function createValidity(days) {
  const notBefore = new Date();
  const notAfter = new Date(notBefore);
  notAfter.setDate(notAfter.getDate() + days);
  return { notBefore, notAfter };
}

function buildAltNames(host) {
  const altNames = [];
  const normalized = normalizeHost(host);
  const ipType = net.isIP(normalized);
  if (ipType) {
    altNames.push({ type: 7, ip: normalized });
  } else if (normalized) {
    altNames.push({ type: 2, value: normalized });
  }
  return altNames;
}

function generateCaCertificate({ keyBits, validDays, subject }) {
  const keys = forge.pki.rsa.generateKeyPair({ bits: keyBits, workers: -1 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = createSerialNumber();
  const validity = createValidity(validDays);
  cert.validity.notBefore = validity.notBefore;
  cert.validity.notAfter = validity.notAfter;
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', keyCertSign: true, digitalSignature: true, cRLSign: true },
    { name: 'subjectKeyIdentifier' }
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
    certPem: forge.pki.certificateToPem(cert)
  };
}

function generateHostCertificate(host, ca, { keyBits, validDays }) {
  const keys = forge.pki.rsa.generateKeyPair({ bits: keyBits, workers: -1 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = createSerialNumber();
  const validity = createValidity(validDays);
  cert.validity.notBefore = validity.notBefore;
  cert.validity.notAfter = validity.notAfter;
  const normalized = normalizeHost(host);
  cert.setSubject([
    { name: 'commonName', value: normalized || 'localhost' },
    { name: 'organizationName', value: 'PacketForge' }
  ]);
  cert.setIssuer(ca.cert.subject.attributes);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectAltName', altNames: buildAltNames(normalized) },
    { name: 'subjectKeyIdentifier' },
    { name: 'authorityKeyIdentifier', keyIdentifier: true }
  ]);
  cert.sign(ca.key, forge.md.sha256.create());

  return {
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
    certPem: forge.pki.certificateToPem(cert)
  };
}

async function readIfExists(filePath) {
  try {
    return await fs.readFile(filePath, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

async function writePem(filePath, data, mode) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, data, { encoding: 'utf8', mode });
}

export function createCertificateManager(baseDir, options = {}) {
  const {
    caSubject = DEFAULT_CA_SUBJECT,
    caKeyBits = 2048,
    caValidDays = 3650,
    certKeyBits = 2048,
    certValidDays = 825
  } = options;

  const caDir = path.join(baseDir, 'ca');
  const hostsDir = path.join(baseDir, 'hosts');
  const caKeyPath = path.join(caDir, 'ca.key');
  const caCertPath = path.join(caDir, 'ca.crt');

  let cachedCa = null;
  let pendingCa = null;
  const hostCache = new Map();
  const pendingHosts = new Map();

  async function loadCaFromDisk() {
    const [keyPem, certPem] = await Promise.all([
      readIfExists(caKeyPath),
      readIfExists(caCertPath)
    ]);
    if (!keyPem || !certPem) {
      return null;
    }
    return {
      keyPem,
      certPem,
      key: forge.pki.privateKeyFromPem(keyPem),
      cert: forge.pki.certificateFromPem(certPem)
    };
  }

  async function ensureCa() {
    if (cachedCa) {
      return cachedCa;
    }
    if (pendingCa) {
      return pendingCa;
    }
    pendingCa = (async () => {
      const existing = await loadCaFromDisk();
      if (existing) {
        cachedCa = existing;
        return cachedCa;
      }
      const generated = generateCaCertificate({
        keyBits: caKeyBits,
        validDays: caValidDays,
        subject: caSubject
      });
      await writePem(caKeyPath, generated.keyPem, 0o600);
      await writePem(caCertPath, generated.certPem, 0o644);
      cachedCa = {
        keyPem: generated.keyPem,
        certPem: generated.certPem,
        key: forge.pki.privateKeyFromPem(generated.keyPem),
        cert: forge.pki.certificateFromPem(generated.certPem)
      };
      return cachedCa;
    })();

    try {
      return await pendingCa;
    } finally {
      pendingCa = null;
    }
  }

  async function status() {
    const certPem = await readIfExists(caCertPath);
    return {
      ready: Boolean(certPem),
      caCertPath
    };
  }

  async function getCaCertificate() {
    const ca = await ensureCa();
    return ca.certPem;
  }

  async function getCertificate(host) {
    const normalized = normalizeHost(host);
    if (!normalized) {
      throw new Error('Invalid host for certificate');
    }
    if (hostCache.has(normalized)) {
      return hostCache.get(normalized);
    }
    if (pendingHosts.has(normalized)) {
      return pendingHosts.get(normalized);
    }

    const task = (async () => {
      const fileKey = path.join(hostsDir, `${sanitizeHost(normalized)}.key`);
      const fileCert = path.join(hostsDir, `${sanitizeHost(normalized)}.crt`);
      const ca = await ensureCa();
      const [keyPem, certPem] = await Promise.all([
        readIfExists(fileKey),
        readIfExists(fileCert)
      ]);
      if (keyPem && certPem) {
        try {
          const parsed = forge.pki.certificateFromPem(certPem);
          const valid = parsed.verify(ca.cert);
          if (valid) {
            const existing = {
              keyPem,
              certPem,
              chainPem: `${certPem}\n${ca.certPem}`
            };
            hostCache.set(normalized, existing);
            return existing;
          }
        } catch (_error) {
          // fall through to regenerate
        }
      }

      const generated = generateHostCertificate(normalized, ca, {
        keyBits: certKeyBits,
        validDays: certValidDays
      });
      await writePem(fileKey, generated.keyPem, 0o600);
      await writePem(fileCert, generated.certPem, 0o644);
      const result = {
        ...generated,
        chainPem: `${generated.certPem}\n${ca.certPem}`
      };
      hostCache.set(normalized, result);
      return result;
    })();

    pendingHosts.set(normalized, task);
    try {
      return await task;
    } finally {
      pendingHosts.delete(normalized);
    }
  }

  return {
    ensureCa,
    status,
    getCaCertificate,
    getCertificate
  };
}
