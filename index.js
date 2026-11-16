import os from 'node:os'
import { join } from 'node:path'
import { randomSecret } from './src/cookie.js'
import { createInnerAuth } from './src/proxy.js'
import { createPhoneServer } from './src/server.js'
import { detectAddresses, describeState } from './src/state.js'
import { ensureTls } from './src/tls.js'

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
  return {
    host,
    port,
    linkTtlMinutes: Number(raw.linkTtlMinutes ?? 10),
    cookieDays: Number(raw.cookieDays ?? 30),
    tls,
  }
}

/** @param {string} value */
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

/**
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {Record<string, unknown>} raw
 */
export async function apply(ctx, raw) {
  const config = resolveConfig(raw)
  const addresses = detectAddresses()
  const home = process.env.DSH_HOME ?? join(os.homedir(), '.dsh')
  const tlsDir = join(home, 'phone-access', 'tls')

  /** @type {Awaited<ReturnType<typeof createPhoneServer>> | undefined} */
  let phone
  let tls
  let failure
  let secret

  const status = () => {
    if (failure) return describeState({ port: config.port, tlsMode: config.tls.mode, addresses, error: failure })
    if (!config.host) return describeState({ port: config.port, tlsMode: config.tls.mode, addresses })
    return describeState({
      host: config.host,
      port: phone?.port ?? config.port,
      tlsMode: config.tls.mode,
      addresses,
      listener: { caFingerprint: tls?.caFingerprint ?? null, tunnels: phone?.tunnels.size() ?? 0 },
    })
  }

  ctx.webServer.register({
    path: '/phone-access/status',
    resource: () => jsonResponse(status()),
  })
  ctx.webServer.register({
    path: '/phone-access/link',
    resource: (request) => {
      if (request.method !== 'POST') return jsonResponse({ error: 'method-not-allowed' }, 405)
      if (!phone) return jsonResponse({ error: 'not-configured', status: status() }, 409)
      const link = phone.link()
      return jsonResponse({ url: link.url, expiresAt: link.expiresAt })
    },
  })
  ctx.webServer.register({
    path: '/phone-access/revoke',
    resource: async (request) => {
      if (request.method !== 'POST') return jsonResponse({ error: 'method-not-allowed' }, 405)
      secret = await ensureSecret(ctx.credentials, true)
      phone?.revoke()
      return jsonResponse({ ok: true })
    },
  })
  ctx.webServer.register({
    path: '/phone-access/ca',
    resource: () => {
      if (!tls?.ca) return jsonResponse({ error: 'no-ca' }, 404)
      return new Response(tls.ca, { headers: { 'content-type': 'application/x-pem-file' } })
    },
  })

  if (!config.host) return
  if (addresses.length > 0 && !addresses.includes(config.host)) {
    failure = { reason: 'host-not-local', message: `address ${config.host} is not one of this machine's IPv4 addresses` }
    return
  }
  try {
    tls = await ensureTls({
      mode: config.tls.mode,
      dir: tlsDir,
      hosts: [`IP:${config.host}`, 'DNS:localhost', 'IP:127.0.0.1'],
      certFile: config.tls.certFile,
      keyFile: config.tls.keyFile,
    })
    secret = await ensureSecret(ctx.credentials)
    const innerOrigin = ctx.webServer.getOrigin()
    phone = await createPhoneServer({
      config,
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
    failure = {
      reason: error?.code === 'EADDRINUSE' ? 'port-in-use' : 'tls-failed',
      message: error instanceof Error ? error.message : String(error),
    }
  }
}
