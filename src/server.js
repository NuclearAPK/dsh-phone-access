import http from 'node:http'
import https from 'node:https'
import { COOKIE_NAME, createTokenStore, serializeCookie, signCookie, verifyCookie } from './cookie.js'
import { isAllowedOrigin } from './headers.js'
import { forwardHttp, forwardUpgrade } from './proxy.js'
import { createTunnelRegistry } from './tunnels.js'

const DENIED_AUTH = '<!doctype html><meta charset="utf-8"><title>DSH phone access</title>'
  + '<p>В этом браузере нет входа: нужна ссылка из карточки «Телефон» на компьютере.</p>'
  + '<p>Нажмите «Показать ссылку» и откройте выданную ссылку целиком, вместе с <code>?t=…</code>.</p>'

const DENIED_TOKEN = '<!doctype html><meta charset="utf-8"><title>DSH phone access</title>'
  + '<p>Ссылка недействительна: она одноразовая и живёт 10 минут.</p>'
  + '<p>Нажмите «Показать ссылку» в карточке «Телефон» ещё раз и откройте новую ссылку.</p>'

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
  /** The root links and QR codes advertise: an external address when configured. */
  let advertised = config.publicUrl ?? origin
  const maxAgeSeconds = config.cookieDays * 86_400

  /** @param {http.IncomingMessage} req */
  const admitted = (req) => {
    const cookie = cookieValue(req.headers.cookie)
    if (cookie === undefined) return false
    return verifyCookie(getSecret(), cookie, { now }) !== null
  }

  /**
   * A top-level navigation is how the phone arrives from a QR scanner or
   * another app; it carries no Origin and is not a cross-site subresource
   * request, so the CSWSH-style refusal must not cover it.
   * @param {http.IncomingMessage} req
   */
  const isNavigation = (req) => req.headers['sec-fetch-mode'] === 'navigate'
    && req.headers['sec-fetch-dest'] === 'document'

  /** @param {http.IncomingMessage} req */
  const trustedOrigin = (req) => isAllowedOrigin(req.headers.origin, origin, advertised)
    && (isNavigation(req) || req.headers['sec-fetch-site'] !== 'cross-site')

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
        res.end(DENIED_TOKEN)
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
      res.end(DENIED_AUTH)
      return
    }
    let innerCookie
    try {
      innerCookie = await inner.auth.ensure()
    } catch (error) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
      res.end(error instanceof Error ? error.message : String(error))
      return
    }
    // A stale inner cookie is refreshed once for a body-less request: a request
    // with a body cannot be replayed, so its 401 passes through.
    const replayable = req.method === 'GET' || req.method === 'HEAD'
    let retried = false
    for (;;) {
      let aborted = false
      await forwardHttp(req, res, {
        innerOrigin: inner.origin,
        innerCookie,
        beforeWrite: (statusCode) => {
          if (statusCode !== 401 || !replayable || retried) return false
          retried = true
          aborted = true
          return true
        },
      })
      if (!aborted) return
      inner.auth.invalidate()
      innerCookie = await inner.auth.ensure()
    }
  }

  const server = secure
    ? https.createServer({ cert: tls.cert, key: tls.key }, handle)
    : http.createServer(handle)

  /** Every open TCP connection, so revocation also ends plain HTTP exchanges. */
  const sockets = new Set()
  server.on('connection', (socket) => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
  })

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
  advertised = config.publicUrl ?? origin

  return {
    server,
    tunnels,
    port,
    urlFor(token) {
      return `${advertised}/?t=${token}`
    },
    caUrl() {
      return `${advertised}/ca.crt`
    },
    setPublicUrl(url) {
      advertised = url ?? origin
    },
    link() {
      const { token, expiresAt } = tokens.issue()
      return { token, expiresAt, url: this.urlFor(token) }
    },
    revoke() {
      tokens.clear()
      tunnels.closeAll()
      for (const socket of sockets) socket.destroy()
      sockets.clear()
    },
    async close() {
      tunnels.closeAll()
      const done = new Promise((resolve) => server.close(resolve))
      server.closeAllConnections?.()
      await done
    },
  }
}

