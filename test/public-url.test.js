import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { normalizePublicUrl, readPublicUrl, writePublicUrl } from '../src/public-url.js'

test('normalizePublicUrl accepts a bare host and keeps an explicit port', () => {
  assert.equal(normalizePublicUrl('dsh.shmell-tech.ru'), 'https://dsh.shmell-tech.ru')
  assert.equal(normalizePublicUrl('dsh.shmell-tech.ru:3099'), 'https://dsh.shmell-tech.ru:3099')
  assert.equal(normalizePublicUrl('https://dsh.shmell-tech.ru:3099/'), 'https://dsh.shmell-tech.ru:3099')
  assert.equal(normalizePublicUrl(' http://192.168.1.237:3099 '), 'http://192.168.1.237:3099')
})

test('normalizePublicUrl rejects non-http schemes and empty input', () => {
  assert.throws(() => normalizePublicUrl('ftp://dsh.shmell-tech.ru'), /public url/)
  assert.throws(() => normalizePublicUrl(''), /public url/)
  assert.throws(() => normalizePublicUrl('https://dsh.shmell-tech.ru/prefix'), /public url/)
})

test('the public url file round-trips, creating its directory, and a missing file reads as undefined', async () => {
  const dir = join(await mkdtemp(join(tmpdir(), 'phone-url-')), 'nested', 'phone-access')
  assert.equal(await readPublicUrl(dir), undefined)
  await writePublicUrl(dir, 'https://dsh.shmell-tech.ru:3099')
  assert.equal(await readPublicUrl(dir), 'https://dsh.shmell-tech.ru:3099')
})

