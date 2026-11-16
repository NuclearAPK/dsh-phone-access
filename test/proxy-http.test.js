import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { createInnerAuth, forwardHttp } from '../src/proxy.js'

async function startFakeInner() {
  const server = http.createServer((req, res) => {
    if (req.url === '/api/echo') {
      res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'dsh-auth-x=1; Path=/' })
      res.end(JSON.stringify({ host: req.headers.host, cookie: req.headers.cookie, origin: req.headers.origin }))
      return
    }
    if (req.url === '/boom') {
      res.writeHead(500)
      res.end('boom')
      return
    }
    res.writeHead(404)
    res.end()
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  return { origin: `http://127.0.0.1:${port}`, port, close: () => new Promise((resolve) => server.close(resolve)) }
}

async function callProxy(innerOrigin, { method = 'GET', path, headers = {}, body }) {
  const proxy = http.createServer((req, res) => {
    forwardHttp(req, res, { innerOrigin, innerCookie: 'inner-cookie=1' }).catch((error) => {
      res.writeHead(502)
      res.end(String(error))
    })
  })
  await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve))
  const { port } = proxy.address()
  try {
    return await new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
        const chunks = []
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }))
      })
      req.on('error', reject)
      req.end(body)
    })
  } finally {
    await new Promise((resolve) => proxy.close(resolve))
  }
}

test('inner auth caches the cookie and accepts only 303 with set-cookie', async () => {
  let calls = 0
  const fetchImpl = async () => {
    calls += 1
    return new Response(null, { status: 303, headers: { 'set-cookie': 'dsh-auth-x=1; Path=/; HttpOnly' } })
  }
  const auth = createInnerAuth({ origin: 'http://127.0.0.1:1', fetchImpl })
  assert.equal(await auth.ensure(), 'dsh-auth-x=1')
  assert.equal(await auth.ensure(), 'dsh-auth-x=1')
  assert.equal(calls, 1)
  const bad = createInnerAuth({ origin: 'http://127.0.0.1:1', fetchImpl: async () => new Response(null, { status: 200 }) })
  await assert.rejects(() => bad.ensure(), /inner auth failed: 200/)
})

test('proxy forwards method, body and rewritten headers', async () => {
  const inner = await startFakeInner()
  try {
    const res = await callProxy(inner.origin, {
      method: 'POST',
      path: '/api/echo',
      headers: { host: '192.168.1.237:3099', cookie: 'dsh-phone=abc', origin: 'https://192.168.1.237:3099' },
      body: '{"args":[]}',
    })
    assert.equal(res.status, 200)
    assert.deepEqual(JSON.parse(res.body), { host: `127.0.0.1:${inner.port}`, cookie: 'inner-cookie=1', origin: inner.origin })
  } finally {
    await inner.close()
  }
})

test('proxy strips the inner set-cookie and passes status through', async () => {
  const inner = await startFakeInner()
  try {
    const withCookie = await callProxy(inner.origin, { path: '/api/echo' })
    assert.equal(withCookie.headers['set-cookie'], undefined)
    const boom = await callProxy(inner.origin, { path: '/boom' })
    assert.equal(boom.status, 500)
    assert.equal(boom.body, 'boom')
  } finally {
    await inner.close()
  }
})
