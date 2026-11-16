import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

const COOKIE_NAME = 'dsh-phone'

/** @returns {string} 32 random bytes as base64url */
export function randomSecret() {
  return randomBytes(32).toString('base64url')
}

/**
 * One-time sign-in tokens held in process memory.
 * @param {{ ttlMs: number, now?: () => number }} options
 */
export function createTokenStore({ ttlMs, now = () => Date.now() }) {
  /** @type {Map<string, number>} */
  const live = new Map()
  return {
    issue() {
      const token = randomBytes(32).toString('base64url')
      const expiresAt = now() + ttlMs
      live.set(token, expiresAt)
      return { token, expiresAt }
    },
    redeem(token) {
      const expiresAt = live.get(token)
      if (expiresAt === undefined) return false
      live.delete(token)
      return expiresAt > now()
    },
    clear() {
      live.clear()
    },
  }
}

/**
 * @param {string} secret
 * @param {{ sub: string, exp: number }} payload exp is milliseconds since epoch
 * @returns {string}
 */
export function signCookie(secret, payload) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url')
  const mac = createHmac('sha256', secret).update(body).digest('base64url')
  return `${body}.${mac}`
}

/**
 * @param {string} secret
 * @param {string} value
 * @param {{ now?: () => number }} [options]
 * @returns {{ sub: string, exp: number } | null}
 */
export function verifyCookie(secret, value, { now = () => Date.now() } = {}) {
  const dot = value.indexOf('.')
  if (dot <= 0) return null
  const body = value.slice(0, dot)
  const mac = value.slice(dot + 1)
  const expected = createHmac('sha256', secret).update(body).digest('base64url')
  const given = Buffer.from(mac)
  const want = Buffer.from(expected)
  if (given.length !== want.length || !timingSafeEqual(given, want)) return null
  let payload
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'))
  } catch {
    return null
  }
  if (typeof payload?.sub !== 'string' || typeof payload?.exp !== 'number') return null
  if (payload.exp <= now()) return null
  return { sub: payload.sub, exp: payload.exp }
}

/**
 * @param {string} value
 * @param {{ secure: boolean, maxAgeSeconds: number }} options
 * @returns {string} Set-Cookie value
 */
export function serializeCookie(value, { secure, maxAgeSeconds }) {
  const parts = [
    `${COOKIE_NAME}=${value}`,
    'Path=/',
    'HttpOnly',
  ]
  if (secure) parts.push('Secure')
  parts.push('SameSite=Lax', `Max-Age=${String(maxAgeSeconds)}`)
  return parts.join('; ')
}

export { COOKIE_NAME }
