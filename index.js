import os from 'node:os'
import { join } from 'node:path'
import { randomSecret } from './src/cookie.js'
import { createInnerAuth } from './src/proxy.js'
import { createPhoneServer } from './src/server.js'
import { detectAddresses, describeState } from './src/state.js'
import { certificateCovers, ensureTls } from './src/tls.js'
import { qrSvg } from './src/qr.js'
import { normalizePublicUrl, readPublicUrl, writePublicUrl } from './src/public-url.js'

export const name = 'phone-access'
export const inject = ['webServer', 'connection', 'credentials']

const CREDENTIAL_KEY = 'phone-access/session'
const TLS_MODES = new Set(['auto', 'files', 'off'])

/**
 * @param {Record<string, unknown>} [raw]
 */
export function resolveConfig(raw = {}) {
  const host = typeof raw.host === 'string' && raw.host.trim() !== '' ? raw.host.trim() : undefined
  if (host === '0.0.0.0' || host === '::' || host === '*') {
    throw new Error('phone-access: a wildcard host is not allowed; name one local address')
  }
  const port = Number(raw.port ?? 3099)
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error('phone-access: port must be an integer from 1 through 65535')
  }
  const tls = {
    mode: String(raw.tls?.mode ?? 'auto'),
    certFile: typeof raw.tls?.certFile === 'string' ? raw.tls.certFile : undefined,
    keyFile: typeof raw.tls?.keyFile === 'string' ? raw.tls.keyFile : undefined,
  }
  if (!TLS_MODES.has(tls.mode)) {
    throw new Error(`phone-access: tls mode must be auto, files or off, not ${tls.mode}`)
  }
  let publicUrl
  if (raw.publicUrl !== undefined && raw.publicUrl !== null && raw.publicUrl !== '') {
    let parsed
    try {
      parsed = new URL(String(raw.publicUrl))
    } catch {
      throw new Error(`phone-access: publicUrl must be an absolute http(s) url, not ${String(raw.publicUrl)}`)
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      throw new Error(`phone-access: publicUrl must be http or https, not ${parsed.protocol}`)
    }
    publicUrl = parsed.origin
  }
  return {
    host,
    port,
    publicUrl,
    linkTtlMinutes: Number(raw.linkTtlMinutes ?? 10),
    cookieDays: Number(raw.cookieDays ?? 30),
    tls,
  }
}

/** @param {unknown} record */
function secretOf(record) {
  if (record?.kind !== 'grant') return undefined
  const secret = record.payload?.secret
  return typeof secret === 'string' && secret.length >= 32 ? secret : undefined
}

/**
 * @param {{ modifyRecord(key: string, mutate: (current: unknown) => unknown): Promise<unknown> }} credentials
 * @param {boolean} [rotate]
 */
async function ensureSecret(credentials, rotate = false) {
  const record = await credentials.modifyRecord(CREDENTIAL_KEY, (current) => {
    if (!rotate && secretOf(current) !== undefined) return undefined
    return { kind: 'grant', payload: { version: 1, secret: randomSecret() } }
  })
  const secret = secretOf(record)
  if (secret === undefined) throw new Error('phone-access: session credential was not created')
  return secret
}

/** @param {unknown} body */
function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  })
}

/** @param {import('node:http').ServerResponse} res */
function writeJson(res, body, status = 200) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  })
  res.end(JSON.stringify(body))
}

/** @param {string} host */
function hostEntry(host) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) ? `IP:${host}` : `DNS:${host}`
}

/** @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {Record<string, unknown>} raw
 */
export async function apply(ctx, raw) {
  const config = resolveConfig(raw)
  const addresses = detectAddresses()
  const home = process.env.DSH_HOME ?? join(os.homedir(), '.dsh')
  const settingsDir = join(home, 'phone-access')
  const tlsDir = join(settingsDir, 'tls')

  /** A value typed in the card wins over the profile config. */
  let publicUrl = (await readPublicUrl(settingsDir).catch(() => undefined)) ?? config.publicUrl

  /** @type {Awaited<ReturnType<typeof createPhoneServer>> | undefined} */
  let phone
  let tls
  /** @type {{ reason: string, message: string } | undefined} */
  let failure
  let secret

  const reject = (/** @type {{ headers: unknown }} */ request) =>
    ctx.connection.requestRejection({ headers: request.headers })

  const status = () => {
    const covers = publicUrl && tls?.kind === 'auto'
      ? certificateCovers(tls.cert, [hostEntry(new URL(publicUrl).hostname)])
      : null
    const base = failure
      ? describeState({ port: config.port, tlsMode: config.tls.mode, addresses, error: failure })
      : !config.host
        ? describeState({ port: config.port, tlsMode: config.tls.mode, addresses })
        : describeState({
          host: config.host,
          port: phone?.port ?? config.port,
          tlsMode: config.tls.mode,
          addresses,
          publicUrl,
          listener: { caFingerprint: tls?.caFingerprint ?? null, tunnels: phone?.tunnels.size() ?? 0 },
        })
    return { ...base, publicUrl: publicUrl ?? null, certificateCoversPublicUrl: covers }
  }

  /** @param {import('node:http').IncomingMessage} req @param {import('node:http').ServerResponse} res */
  const guarded = (req, res) => {
    const rejection = reject(req)
    if (rejection === undefined) return false
    res.writeHead(rejection)
    res.end()
    return true
  }

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/phone-access/status',
    resource: (request) => {
      const rejection = reject(request)
      if (rejection !== undefined) return new Response(null, { status: rejection })
      return jsonResponse(status())
    },
  }))

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/phone-access/ca',
    resource: (request) => {
      const rejection = reject(request)
      if (rejection !== undefined) return new Response(null, { status: rejection })
      if (!tls?.ca) return jsonResponse({ error: 'no-ca' }, 404)
      return new Response(tls.ca, { headers: { 'content-type': 'application/x-pem-file' } })
    },
  }))

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/phone-access/qr',
    resource: (request) => {
      const rejection = reject(request)
      if (rejection !== undefined) return new Response(null, { status: rejection })
      if (!phone) return jsonResponse({ error: 'not-configured' }, 409)
      return new Response(qrSvg(phone.caUrl()), {
        headers: { 'content-type': 'image/svg+xml; charset=utf-8', 'cache-control': 'no-store' },
      })
    },
  }))

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/phone-access/qr/link',
    resource: (request) => {
      const rejection = reject(request)
      if (rejection !== undefined) return new Response(null, { status: rejection })
      if (!phone) return jsonResponse({ error: 'not-configured' }, 409)
      const token = new URL(request.url).searchParams.get('t')
      if (token === null || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
        return jsonResponse({ error: 'bad-token' }, 400)
      }
      return new Response(qrSvg(phone.urlFor(token)), {
        headers: { 'content-type': 'image/svg+xml; charset=utf-8', 'cache-control': 'no-store' },
      })
    },
  }))

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/phone-access/public-url',
    handler: (req, res) => {
      if (guarded(req, res)) return
      if (req.method !== 'POST') {
        writeJson(res, { error: 'method-not-allowed' }, 405)
        return
      }
      const value = new URL(req.url ?? '/', 'http://placeholder').searchParams.get('u')
      let next
      try {
        next = normalizePublicUrl(value ?? '')
      } catch (error) {
        writeJson(res, { error: 'bad-url', message: error instanceof Error ? error.message : String(error) }, 400)
        return
      }
      return writePublicUrl(settingsDir, next).then(
        () => {
          publicUrl = next
          phone?.setPublicUrl(next)
          const covers = tls?.kind === 'auto'
            ? certificateCovers(tls.cert, [hostEntry(new URL(next).hostname)])
            : null
          writeJson(res, { url: next, certificateCoversPublicUrl: covers })
        },
        (error) => {
          writeJson(res, { error: 'write-failed', message: String(error?.message ?? error) }, 500)
        },
      )
    },
  }))

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/phone-access/link',
    handler: (req, res) => {
      if (guarded(req, res)) return
      if (req.method !== 'POST') {
        writeJson(res, { error: 'method-not-allowed' }, 405)
        return
      }
      if (!phone) {
        writeJson(res, { error: 'not-configured', status: status() }, 409)
        return
      }
      const link = phone.link()
      writeJson(res, { url: link.url, expiresAt: link.expiresAt })
    },
  }))

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/phone-access/revoke',
    handler: (req, res) => {
      if (guarded(req, res)) return
      if (req.method !== 'POST') {
        writeJson(res, { error: 'method-not-allowed' }, 405)
        return
      }
      return ensureSecret(ctx.credentials, true).then(        (rotated) => {
          secret = rotated
          phone?.revoke()
          writeJson(res, { ok: true })
        },
        (error) => {
          writeJson(res, { error: 'credential-failed', message: String(error?.message ?? error) }, 500)
        },
      )
    },
  }))

  if (config.tls.mode === 'off') {
    console.warn('[phone-access] tls.mode is off: the phone cookie travels in clear text; use it only for debugging')
  }
  if (!config.host) return
  if (addresses.length > 0 && !addresses.includes(config.host)) {
    failure = { reason: 'host-not-local', message: `address ${config.host} is not one of this machine's IPv4 addresses` }
    return
  }
  try {
    const hosts = [`IP:${config.host}`, `DNS:${os.hostname()}`, 'DNS:localhost', 'IP:127.0.0.1']
    if (config.publicUrl) {
      const publicHost = new URL(config.publicUrl).hostname
      hosts.push(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(publicHost) ? `IP:${publicHost}` : `DNS:${publicHost}`)
    }
    tls = await ensureTls({
      mode: config.tls.mode,
      dir: tlsDir,
      hosts,
      certFile: config.tls.certFile,
      keyFile: config.tls.keyFile,
    })
    if (tls.kind === 'files') {
      const required = [`IP:${config.host}`]
      if (config.publicUrl) {
        const publicHost = new URL(config.publicUrl).hostname
        required.push(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(publicHost) ? `IP:${publicHost}` : `DNS:${publicHost}`)
      }
      if (!certificateCovers(tls.cert, required)) {
        throw Object.assign(
          new Error(`certificate in ${String(config.tls.certFile)} has no SAN for ${required.join(', ')}`),
          { code: 'CERT_SAN' },
        )
      }
    }
    secret = await ensureSecret(ctx.credentials)
    const innerOrigin = ctx.webServer.getOrigin()
    phone = await createPhoneServer({
      config: { ...config, publicUrl: publicUrl ?? undefined },
      tls,
      getSecret: () => secret,
      inner: {
        origin: innerOrigin,
        auth: createInnerAuth({ origin: ctx.connection.authenticatedUrl(innerOrigin) }),
      },
    })
    ctx.effect(() => () => {
      void phone?.close()
    })
  } catch (error) {
    const code = error?.code
    failure = {
      reason: code === 'EADDRINUSE' ? 'port-in-use' : code === 'CERT_SAN' ? 'cert-san' : 'start-failed',
      message: error instanceof Error ? error.message : String(error),
    }
    console.warn(`[phone-access] ${failure.reason}: ${failure.message}`)
  }
}


