import http from 'node:http'
import net from 'node:net'
import { forwardRequestHeaders, responseHeaderEntries } from './headers.js'

/**
 * Cookie the proxy presents to the inner host: exchanged once from the
 * authenticated launch URL, then cached in memory.
 * @param {{ origin: string, fetchImpl?: typeof fetch }} options
 */
export function createInnerAuth({ origin, fetchImpl = fetch }) {
  /** @type {string | undefined} */
  let cookie
  return {
    async ensure() {
      if (cookie !== undefined) return cookie
      const response = await fetchImpl(origin, { redirect: 'manual' })
      const header = response.headers.get('set-cookie')
      if (response.status !== 303 || header === null) {
        throw new Error(`phone-access: inner auth failed: ${String(response.status)}`)
      }
      const end = header.indexOf(';')
      cookie = end < 0 ? header : header.slice(0, end)
      return cookie
    },
    invalidate() {
      cookie = undefined
    },
  }
}

/**
 * Forward one HTTP request to the inner host and write its response back.
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {{ innerOrigin: string, innerCookie: string, beforeWrite?: (statusCode: number) => boolean }} target
 */
export async function forwardHttp(req, res, { innerOrigin, innerCookie, beforeWrite }) {
  const inner = new URL(innerOrigin)
  const headers = forwardRequestHeaders(req.headers, { innerOrigin, innerCookie })
  await new Promise((resolve) => {
    const upstream = http.request(
      {
        host: inner.hostname,
        port: inner.port,
        method: req.method,
        path: req.url ?? '/',
        headers,
      },
      (innerRes) => {
        if (beforeWrite?.(innerRes.statusCode ?? 0)) {
          innerRes.destroy()
          upstream.destroy()
          resolve()
          return
        }
        const entries = responseHeaderEntries(innerRes.rawHeaders)
        res.writeHead(innerRes.statusCode ?? 502, Object.fromEntries(entries))
        innerRes.pipe(res)
        innerRes.on('end', resolve)
        innerRes.on('error', () => {
          res.destroy()
          resolve()
        })
      },
    )
    upstream.on('error', () => {
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
        res.end('phone-access: inner host unreachable')
      } else {
        res.destroy()
      }
      resolve()
    })
    req.pipe(upstream)
  })
}

/**
 * Forward one HTTP upgrade (WebSocket) to the inner host, then splice the two
 * sockets together and keep both in the tunnel registry.
 * @param {http.IncomingMessage} req
 * @param {import('node:net').Socket} socket
 * @param {Buffer} head
 * @param {{ innerOrigin: string, innerCookie: string, tunnels: { add(client: import('node:net').Socket, upstream: import('node:net').Socket): void } }} options
 */
export function forwardUpgrade(req, socket, head, { innerOrigin, innerCookie, tunnels }) {
  const inner = new URL(innerOrigin)
  const upstream = net.connect(Number(inner.port), inner.hostname, () => {
    const headers = forwardRequestHeaders(req.headers, { innerOrigin, innerCookie, keepUpgrade: true })
    const lines = [`${req.method ?? 'GET'} ${req.url ?? '/'} HTTP/1.1`]
    for (const [name, value] of Object.entries(headers)) lines.push(`${name}: ${value}`)
    upstream.write(`${lines.join('\r\n')}\r\n\r\n`)
    if (head.length > 0) upstream.write(head)
    socket.pipe(upstream).pipe(socket)
  })
  socket.setTimeout(0)
  socket.setNoDelay(true)
  upstream.setNoDelay(true)
  upstream.on('error', () => socket.destroy())
  socket.on('error', () => upstream.destroy())
  tunnels.add(socket, upstream)
}

