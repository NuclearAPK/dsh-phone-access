import test from 'node:test'
import assert from 'node:assert/strict'
import { createTokenStore, randomSecret, serializeCookie, signCookie, verifyCookie } from '../src/cookie.js'

test('token is single use and expires', () => {
  let now = 1000
  const store = createTokenStore({ ttlMs: 60_000, now: () => now })
  const { token, expiresAt } = store.issue()
  assert.equal(expiresAt, 61_000)
  assert.equal(store.redeem(token), true)
  assert.equal(store.redeem(token), false)
  const second = store.issue().token
  now = 62_000
  assert.equal(store.redeem(second), false)
})

test('cookie round-trips and rejects tampering, expiry and foreign secret', () => {
  const secret = randomSecret()
  const value = signCookie(secret, { sub: 'phone', exp: 2_000_000 })
  assert.deepEqual(verifyCookie(secret, value, { now: () => 1_000 }), { sub: 'phone', exp: 2_000_000 })
  const [payload, mac] = value.split('.')
  assert.equal(verifyCookie(secret, `${payload}x.${mac}`, { now: () => 1_000 }), null)
  assert.equal(verifyCookie(randomSecret(), value, { now: () => 1_000 }), null)
  assert.equal(verifyCookie(secret, value, { now: () => 2_000_001 }), null)
})

test('cookie attributes follow the tls mode', () => {
  assert.match(serializeCookie('v', { secure: true, maxAgeSeconds: 60 }), /HttpOnly; Secure; SameSite=Lax/)
  assert.doesNotMatch(serializeCookie('v', { secure: false, maxAgeSeconds: 60 }), /Secure/)
})
