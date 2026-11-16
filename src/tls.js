import { webcrypto } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import * as x509 from '@peculiar/x509'

x509.cryptoProvider.set(webcrypto)

const ALGORITHM = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 }
const SIGNING = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
const CA_DAYS = 3650
const LEAF_DAYS = 825

const FILE = { ca: 'ca.pem', caKey: 'ca.key', leaf: 'leaf.pem', leafKey: 'leaf.key', meta: 'meta.json' }

function pem(der, label) {
  const body = Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n')
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`
}

async function exportKey(key) {
  return pem(await webcrypto.subtle.exportKey('pkcs8', key), 'PRIVATE KEY')
}

function formatFingerprint(buffer) {
  return [...new Uint8Array(buffer)].map((byte) => byte.toString(16).toUpperCase().padStart(2, '0')).join(':')
}

async function thumbprint(cert) {
  return formatFingerprint(await cert.getThumbprint('SHA-256', webcrypto))
}

function splitHost(host) {
  const colon = host.indexOf(':')
  const type = host.slice(0, colon).toLowerCase()
  const value = host.slice(colon + 1)
  return { type, value }
}

function sanEntries(cert) {
  const extension = cert.getExtension(x509.SubjectAlternativeNameExtension)
  return extension ? extension.names.toJSON() : []
}

/**
 * @param {string} certPem
 * @param {string[]} hosts entries like `IP:192.168.1.237` or `DNS:localhost`
 * @returns {boolean}
 */
export function certificateCovers(certPem, hosts) {
  const cert = new x509.X509Certificate(certPem)
  const entries = sanEntries(cert)
  return hosts.every((host) => {
    const { type, value } = splitHost(host)
    return entries.some((entry) => entry.type === type && String(entry.value) === value)
  })
}

async function generate({ dir, hosts }) {
  const caKeys = await webcrypto.subtle.generateKey(ALGORITHM, true, ['sign', 'verify'])
  const notBefore = new Date(Date.now() - 60_000)
  const caCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=DSH Phone Access CA',
    notBefore,
    notAfter: new Date(Date.now() + CA_DAYS * 86_400_000),
    signingAlgorithm: SIGNING,
    keys: caKeys,
    extensions: [new x509.BasicConstraintsExtension(true, undefined, true)],
  })
  const leafKeys = await webcrypto.subtle.generateKey(ALGORITHM, true, ['sign', 'verify'])
  const leafCert = await x509.X509CertificateGenerator.create({
    serialNumber: '02',
    subject: `CN=${hosts[0] ?? 'dsh-phone'}`,
    issuer: caCert.subject,
    notBefore,
    notAfter: new Date(Date.now() + LEAF_DAYS * 86_400_000),
    signingAlgorithm: SIGNING,
    publicKey: leafKeys.publicKey,
    signingKey: caKeys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment,
        true,
      ),
      new x509.SubjectAlternativeNameExtension(
        hosts.map((host) => {
          const { type, value } = splitHost(host)
          return { type: type === 'ip' ? 'ip' : type, value }
        }),
      ),
    ],
  })
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, FILE.ca), caCert.toString('pem'))
  writeFileSync(join(dir, FILE.caKey), await exportKey(caKeys.privateKey))
  writeFileSync(join(dir, FILE.leaf), leafCert.toString('pem'))
  writeFileSync(join(dir, FILE.leafKey), await exportKey(leafKeys.privateKey))
  writeFileSync(join(dir, FILE.meta), JSON.stringify({ hosts }, null, 2))
  return {
    kind: 'auto',
    cert: leafCert.toString('pem'),
    key: await exportKey(leafKeys.privateKey),
    ca: caCert.toString('pem'),
    caFingerprint: await thumbprint(caCert),
    hosts,
  }
}

/**
 * @param {{ mode: string, dir: string, hosts: string[], certFile?: string, keyFile?: string }} options
 * @returns {Promise<{ kind: 'off' } | { kind: 'auto' | 'files', cert: string, key: string, ca: string, caFingerprint: string, hosts: string[] }>}
 */
export async function ensureTls({ mode, dir, hosts, certFile, keyFile }) {
  if (mode === 'off') return { kind: 'off' }
  if (mode === 'files') {
    if (!certFile || !keyFile) throw new Error('phone-access: tls.mode files needs certFile and keyFile')
    const cert = readFileSync(certFile, 'utf8')
    const key = readFileSync(keyFile, 'utf8')
    const parsed = new x509.X509Certificate(cert)
    return { kind: 'files', cert, key, ca: cert, caFingerprint: await thumbprint(parsed), hosts: [] }
  }
  const metaPath = join(dir, FILE.meta)
  const leafPath = join(dir, FILE.leaf)
  if (existsSync(metaPath) && existsSync(leafPath)) {
    const meta = JSON.parse(readFileSync(metaPath, 'utf8'))
    const same = Array.isArray(meta.hosts)
      && meta.hosts.length === hosts.length
      && meta.hosts.every((host, index) => host === hosts[index])
    if (same) {
      const cert = readFileSync(leafPath, 'utf8')
      const ca = readFileSync(join(dir, FILE.ca), 'utf8')
      const caCert = new x509.X509Certificate(ca)
      return {
        kind: 'auto',
        cert,
        key: readFileSync(join(dir, FILE.leafKey), 'utf8'),
        ca,
        caFingerprint: await thumbprint(caCert),
        hosts,
      }
    }
  }
  return generate({ dir, hosts })
}
