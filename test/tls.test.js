import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { certificateCovers, ensureTls } from '../src/tls.js'

test('auto mode generates a CA and a leaf covering the hosts', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'phone-tls-'))
  const material = await ensureTls({ mode: 'auto', dir, hosts: ['IP:192.168.1.237', 'DNS:localhost'] })
  assert.equal(material.kind, 'auto')
  assert.match(material.cert, /BEGIN CERTIFICATE/)
  assert.match(material.ca, /BEGIN CERTIFICATE/)
  assert.equal(certificateCovers(material.cert, ['IP:192.168.1.237']), true)
  assert.equal(certificateCovers(material.cert, ['IP:10.20.22.131']), false)
  assert.match(material.caFingerprint, /^[0-9A-F:]{95}$/)
})

test('second call reuses the material and a new host regenerates it', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'phone-tls-'))
  const first = await ensureTls({ mode: 'auto', dir, hosts: ['IP:192.168.1.237'] })
  const again = await ensureTls({ mode: 'auto', dir, hosts: ['IP:192.168.1.237'] })
  assert.equal(again.caFingerprint, first.caFingerprint)
  const moved = await ensureTls({ mode: 'auto', dir, hosts: ['IP:192.168.1.237', 'IP:10.20.22.131'] })
  assert.notEqual(moved.caFingerprint, first.caFingerprint)
  assert.equal(certificateCovers(moved.cert, ['IP:10.20.22.131']), true)
})

test('files mode reads given files and off mode returns off', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'phone-tls-'))
  const generated = await ensureTls({ mode: 'auto', dir, hosts: ['IP:127.0.0.1'] })
  const certFile = join(dir, 'user-cert.pem')
  const keyFile = join(dir, 'user-key.pem')
  await writeFile(certFile, generated.cert)
  await writeFile(keyFile, generated.key)
  const material = await ensureTls({ mode: 'files', dir, hosts: [], certFile, keyFile })
  assert.equal(material.kind, 'files')
  assert.equal(material.cert.trim(), generated.cert.trim())
  const off = await ensureTls({ mode: 'off', dir, hosts: [] })
  assert.deepEqual(off, { kind: 'off' })
})
