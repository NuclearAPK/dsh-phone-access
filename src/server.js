import http from 'node:http'
import https from 'node:https'
import { COOKIE_NAME, createTokenStore, serializeCookie, signCookie, verifyCookie } from './cookie.js'
import { isAllowedOrigin } from './headers.js'
import { forwardHttp, forwardUpgrade } from './proxy.js'
import { createTunnelRegistry } from './tunnels.js'

const DENIED_PAGE = '<!doctype html><meta charset="utf-8"><title>DSH phone access</title>'
  + '<p>Откройте ссылку из карточки «Телефон» на компьютере.</p>'

/** @param {string | undefined} header */
function cookieValue(header) {
  if (!header) return undefined
  for (const part of header.split(';')) {
    const [name, ...rest] = part.trim().split('=')
    if (name === COOKIE_NAME) return rest.join('=')
  }
  return undefined
}

/**
 * @param {{
 *   config: { host: string, port: number, cookieDays: number, linkTtlMinutes: number },
 *   tls: { kind: string, cert?: string, key?: string, ca?: string },
 *   getSecret: () => string,
 *   inner: { origin: string, auth: { ensure(): Promise<string> } },
 *   now?: () => number,
 * }} options
 */
export async function createPhoneServer({ config, tls, getSecret, inner, now = () => Date.now() }) {
  const tokens = createTokenStore({ ttlMs: config.linkTtlMinutes * 60_000, now })
  const tunnels = createTunnelRegistry()
  const secure = tls.kind !== 'off'
  const scheme = secure ? 'https' : 'http'
  let port = config.port
  let origin = `${scheme}://${config.host}:${String(port)}`
  const maxAgeSeconds = config.cookieDays * 86_400

  /** @param {http.IncomingMessage} req */
  const admitted = (req) => {
    const cookie = cookieValue(req.headers.cookie)
    if (cookie === undefined) return false
    return verifyCookie(getSecret(), cookie, { now }) !== null
  }

  /** @param {http.IncomingMessage} req */
  const trustedOrigin = (req) => isAllowedOrigin(req.headers.origin, origin)
    && req.headers['sec-fetch-site'] !== 'cross-site'

  /** @param {http.IncomingMessage} req @param {http.ServerResponse} res */
  const handle = async (req, res) => {
    const requestUrl = new URL(req.url ?? '/', origin)
    if (requestUrl.pathname === '/ca.crt' && tls.ca) {
      res.writeHead(200, { 'content-type': 'application/x-pem-file' })
      res.end(tls.ca)
      return
    }
    const token = requestUrl.searchParams.get('t')
    if (req.method === 'GET' && requestUrl.pathname === '/' && token !== null) {
      if (!tokens.redeem(token)) {
        res.writeHead(401, { 'content-type': 'text/html; charset=utf-8' })
        res.end(DENIED_PAGE)
        return
      }
      const value = serializeCookie(
        // Signed afresh on every entry so a rotated secret invalidates old phones.
        signCookie(getSecret(), { sub: 'phone', exp: now() + maxAgeSeconds * 1000 }),
        { secure, maxAgeSeconds },
      )
      res.writeHead(302, { location: '/', 'set-cookie': value })
      res.end()
      return
    }
    if (!trustedOrigin(req)) {
      res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' })
      res.end('phone-access: origin not allowed')
      return
    }
    if (!admitted(req)) {
      res.writeHead(401, { 'content-type': 'text/html; charset=utf-8' })
      res.end(DENIED_PAGE)
      return
    }
    let innerCookie
    try {
      innerCookie = await inner.auth.ensure()
    } catch (error) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
      res.end(`phone-access: ${error instanceof Error ? error.message : String(error)}`)
      return
    }
    await forwardHttp(req, res, { innerOrigin: inner.origin, innerCookie })
  }

  const server = secure
    ? https.createServer({ cert: tls.cert, key: tls.key }, handle)
    : http.createServer(handle)

  server.on('upgrade', (req, socket, head) => {
    if (!trustedOrigin(req) || !admitted(req)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
      socket.destroy()
      return
    }
    inner.auth.ensure().then(
      (innerCookie) => {
        forwardUpgrade(req, socket, head, { innerOrigin: inner.origin, innerCookie, tunnels })
      },
      (error) => {
        socket.write(`HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n${error instanceof Error ? error.message : String(error)}`)
        socket.destroy()
      },
    )
  })

  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(config.port, config.host, () => {
      server.off('error', reject)
      resolve(undefined)
    })
  })
  port = server.address().port
  origin = `${scheme}://${config.host}:${String(port)}`

  return {
    server,
    tunnels,
    port,
    urlFor(token) {
      return `${origin}/?t=${token}`
    },
    link() {
      const { token, expiresAt } = tokens.issue()
      return { token, expiresAt, url: this.urlFor(token) }
    },
    revoke() {
      tokens.clear()
      tunnels.closeAll()
    },
    async close() {
      tunnels.closeAll()
      const done = new Promise((resolve) => server.close(resolve))
      server.closeAllConnections?.()
      await done
    },
  }
}
