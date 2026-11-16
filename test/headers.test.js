import test from 'node:test'
import assert from 'node:assert/strict'
import { forwardRequestHeaders, isAllowedOrigin, responseHeaderEntries } from '../src/headers.js'

const inner = { innerOrigin: 'http://127.0.0.1:61110', innerCookie: 'dsh-auth-x=1' }

test('forwards ordinary headers and rewrites host, cookie and origin', () => {
  const out = forwardRequestHeaders(
    {
      'user-agent': 'phone',
      connection: 'keep-alive',
      host: '192.168.1.237:3099',
      cookie: 'dsh-phone=abc',
      origin: 'https://192.168.1.237:3099',
      referer: 'https://192.168.1.237:3099/chat',
    },
    inner,
  )
  assert.equal(out['user-agent'], 'phone')
  assert.equal(out.connection, undefined)
  assert.equal(out.host, '127.0.0.1:61110')
  assert.equal(out.cookie, 'dsh-auth-x=1')
  assert.equal(out.origin, 'http://127.0.0.1:61110')
  assert.equal(out.referer, 'http://127.0.0.1:61110/chat')
})

test('does not invent origin when the client sent none', () => {
  assert.equal(forwardRequestHeaders({ 'user-agent': 'phone' }, inner).origin, undefined)
})

test('origin allowlist accepts own origin only', () => {
  assert.equal(isAllowedOrigin(undefined, 'https://192.168.1.237:3099'), true)
  assert.equal(isAllowedOrigin('https://192.168.1.237:3099', 'https://192.168.1.237:3099'), true)
  assert.equal(isAllowedOrigin('https://evil.example', 'https://192.168.1.237:3099'), false)
})

test('response headers drop set-cookie and hop-by-hop', () => {
  const out = responseHeaderEntries([
    'content-type', 'text/html',
    'set-cookie', 'dsh-auth-x=1',
    'connection', 'close',
    'content-length', '42',
  ])
  assert.deepEqual(out, [['content-type', 'text/html']])
})
