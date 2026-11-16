/** Headers describing one connection rather than the message; never forwarded. */
export const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'content-length',
])

/** Headers the proxy replaces itself. */
const REWRITTEN = new Set(['host', 'cookie', 'origin', 'referer'])

/** Response headers the phone must never receive. */
const WITHHELD_RESPONSE = new Set([...HOP_BY_HOP, 'set-cookie'])

/**
 * @param {string | undefined} origin
 * @param {string} publicOrigin
 * @returns {boolean}
 */
export function isAllowedOrigin(origin, publicOrigin) {
  if (origin === undefined || origin === '') return true
  return origin === publicOrigin
}

/**
 * Headers for the request the proxy sends to the inner host.
 * @param {Record<string, string | string[] | undefined>} headers
 * @param {{ innerOrigin: string, innerCookie: string }} target
 * @returns {Record<string, string>}
 */
export function forwardRequestHeaders(headers, { innerOrigin, innerCookie }) {
  /** @type {Record<string, string>} */
  const out = {}
  for (const [rawName, value] of Object.entries(headers)) {
    if (value === undefined) continue
    const name = rawName.toLowerCase()
    if (HOP_BY_HOP.has(name) || REWRITTEN.has(name)) continue
    out[name] = Array.isArray(value) ? value.join(', ') : String(value)
  }
  const inner = new URL(innerOrigin)
  out.host = inner.host
  out.cookie = innerCookie
  const origin = headers.origin ?? headers.Origin
  if (origin !== undefined) out.origin = innerOrigin
  const referer = headers.referer ?? headers.Referer
  if (referer !== undefined) {
    try {
      const parsed = new URL(Array.isArray(referer) ? referer[0] : referer)
      out.referer = `${innerOrigin}${parsed.pathname}${parsed.search}`
    } catch {
      out.referer = `${innerOrigin}/`
    }
  }
  return out
}

/**
 * @param {string[]} rawHeaders flat name/value pairs as Node reports them
 * @returns {string[][]}
 */
export function responseHeaderEntries(rawHeaders) {
  /** @type {string[][]} */
  const out = []
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
    const name = rawHeaders[index]
    if (WITHHELD_RESPONSE.has(name.toLowerCase())) continue
    out.push([name, rawHeaders[index + 1]])
  }
  return out
}
