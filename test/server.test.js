import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import net from 'node:net'
import { randomSecret } from '../src/cookie.js'
import { createPhoneServer } from '../src/server.js'

async function startFakeInner() {
  const upgraded = new Set()
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(`inner:${req.url}:${String(req.headers.cookie)}`)
  })
  server.on('upgrade', (req, socket) => {
    upgraded.add(socket)
    socket.on('close', () => upgraded.delete(socket))
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
    socket.pipe(socket)
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  return {
    origin: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => {
      for (const socket of upgraded) socket.destroy()
      server.close(resolve)
      server.closeAllConnections?.()
    }),
  }
}

async function startPhone(inner, overrides = {}) {
  const secret = randomSecret()
  const phone = await createPhoneServer({
    config: { host: '127.0.0.1', port: 0, cookieDays: 30, linkTtlMinutes: 10 },
    tls: { kind: 'off' },
    getSecret: () => secret,
    inner: { origin: inner.origin, auth: { ensure: async () => 'inner-cookie=1' } },
    ...overrides,
  })
  return { phone, secret }
}

function request(port, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, headers }, (res) => {
      const chunks = []
      res.on('data', (chunk) => chunks.push(chunk))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }))
    })
    req.on('error', reject)
    req.end()
  })
}

function cookieOf(response) {
  const header = response.headers['set-cookie']
  return Array.isArray(header) ? header[0].split(';')[0] : header.split(';')[0]
}

async function waitFor(predicate, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await predicate()) return
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
  throw new Error('waitFor: condition not met')
}

test('requests without a cookie get 401 except the token entry and the CA', async () => {
  const inner = await startFakeInner()
  const { phone } = await startPhone(inner, { tls: { kind: 'off', ca: 'CA-PEM' } })
  try {
    const denied = await request(phone.port, '/')
    assert.equal(denied.status, 401)
    const ca = await request(phone.port, '/ca.crt')
    assert.equal(ca.status, 200)
    assert.equal(ca.body, 'CA-PEM')
  } finally {
    await phone.close()
    await inner.close()
  }
})

test('token entry sets the cookie and redirects to /', async () => {
  const inner = await startFakeInner()
  const { phone } = await startPhone(inner)
  try {
    const link = phone.link()
    const entry = await request(phone.port, `/?t=${link.token}`)
    assert.equal(entry.status, 302)
    assert.equal(entry.headers.location, '/')
    assert.match(entry.headers['set-cookie'][0], /dsh-phone=.*HttpOnly.*SameSite=Lax/)
    const replay = await request(phone.port, `/?t=${link.token}`)
    assert.equal(replay.status, 401)
  } finally {
    await phone.close()
    await inner.close()
  }
})

test('cookie then proxies the request to the inner host', async () => {
  const inner = await startFakeInner()
  const { phone } = await startPhone(inner)
  try {
    const entry = await request(phone.port, `/?t=${phone.link().token}`)
    const cookie = cookieOf(entry)
    const proxied = await request(phone.port, '/api/session/list', { cookie })
    assert.equal(proxied.status, 200)
    assert.equal(proxied.body, 'inner:/api/session/list:inner-cookie=1')
  } finally {
    await phone.close()
    await inner.close()
  }
})

test('foreign origin and cross-site requests are refused', async () => {
  const inner = await startFakeInner()
  const { phone } = await startPhone(inner)
  try {
    const entry = await request(phone.port, `/?t=${phone.link().token}`)
    const cookie = cookieOf(entry)
    const foreign = await request(phone.port, '/api/session/list', { cookie, origin: 'https://evil.example' })
    assert.equal(foreign.status, 403)
    const crossSite = await request(phone.port, '/api/session/list', { cookie, 'sec-fetch-site': 'cross-site' })
    assert.equal(crossSite.status, 403)
  } finally {
    await phone.close()
    await inner.close()
  }
})

test('revoke closes open tunnels', async () => {
  const inner = await startFakeInner()
  const { phone } = await startPhone(inner)
  const entry = await request(phone.port, `/?t=${phone.link().token}`)
  const cookie = cookieOf(entry)
  const socket = net.connect(phone.port, '127.0.0.1')
  const closed = new Promise((resolve) => socket.once('close', resolve))
  try {
    await new Promise((resolve) => socket.once('connect', resolve))
    socket.resume()
    socket.write(
      `GET /api/remote.mux HTTP/1.1\r\nHost: 127.0.0.1:${String(phone.port)}\r\nOrigin: http://127.0.0.1:${String(phone.port)}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nCookie: ${cookie}\r\n\r\n`,
    )
    await waitFor(() => phone.tunnels.size() === 1)
    phone.revoke()
    await closed
    assert.equal(phone.tunnels.size(), 0)
  } finally {
    socket.destroy()
    await phone.close()
    await inner.close()
  }
})

test('revoke closes idle keep-alive connections', async () => {
  const inner = await startFakeInner()
  const { phone } = await startPhone(inner)
  const agent = new http.Agent({ keepAlive: true })
  const connections = () => new Promise((resolve) => phone.server.getConnections((_error, count) => { resolve(count) }))
  try {
    const entry = await request(phone.port, `/?t=${phone.link().token}`)
    const cookie = cookieOf(entry)
    await new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port: phone.port, path: '/api/session/list', headers: { cookie }, agent }, (res) => {
        res.resume()
        res.on('end', resolve)
      })
      req.on('error', reject)
      req.end()
    })
    assert.ok(await connections() >= 1, 'keep-alive connection is open')
    phone.revoke()
    await waitFor(async () => (await connections()) === 0)
  } finally {
    agent.destroy()
    await phone.close()
    await inner.close()
  }
})

test('a stale inner cookie is refreshed once on 401', async () => {
  const stale = http.createServer((req, res) => {
    if (req.headers.cookie === 'fresh') {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('ok')
      return
    }
    res.writeHead(401, { 'content-type': 'text/plain' })
    res.end('stale cookie')
  })
  await new Promise((resolve) => stale.listen(0, '127.0.0.1', resolve))
  let cookie = 'stale'
  const auth = {
    async ensure() { return cookie },
    invalidate() { cookie = 'fresh' },
  }
  const phone = await createPhoneServer({
    config: { host: '127.0.0.1', port: 0, cookieDays: 30, linkTtlMinutes: 10 },
    tls: { kind: 'off' },
    getSecret: () => 'secret-secret-secret-secret-secret',
    inner: { origin: `http://127.0.0.1:${String(stale.address().port)}`, auth },
  })
  try {
    const entry = await request(phone.port, `/?t=${phone.link().token}`)
    const cookieHeader = cookieOf(entry)
    const answer = await request(phone.port, '/api/session/list', { cookie: cookieHeader })
    assert.notEqual(answer.status, 401, 'the proxy must retry with a fresh inner cookie')
  } finally {
    await phone.close()
    await new Promise((resolve) => stale.close(resolve))
  }
})

