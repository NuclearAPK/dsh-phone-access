import http from 'node:http'
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
 * @param {{ innerOrigin: string, innerCookie: string }} target
 */
export async function forwardHttp(req, res, { innerOrigin, innerCookie }) {
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
