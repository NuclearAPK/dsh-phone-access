import test from 'node:test'
import assert from 'node:assert/strict'
import { apply, resolveConfig } from '../index.js'

function stubCtx() {
  const routes = []
  const cleanups = []
  const store = { value: undefined }
  const ctx = {
    webServer: {
      getOrigin: () => 'http://127.0.0.1:61110',
      register(route) {
        routes.push(route)
        return () => {}
      },
    },
    connection: { authenticatedUrl: (url) => `${url}?token=t` },
    credentials: {
      async modifyRecord(_key, mutate) {
        store.value = await mutate(store.value)
        return store.value
      },
    },
    effect(fn) {
      cleanups.push(fn())
    },
    on() {},
  }
  return { ctx, routes, store }
}

function routeOf(routes, path) {
  const route = routes.find((candidate) => candidate.path === path)
  assert.ok(route, `route ${path} is not registered`)
  return route
}

test('resolveConfig applies defaults', () => {
  const config = resolveConfig({ port: 3099 })
  assert.equal(config.host, undefined)
  assert.equal(config.port, 3099)
  assert.equal(config.linkTtlMinutes, 10)
  assert.equal(config.cookieDays, 30)
  assert.equal(config.tls.mode, 'auto')
})

test('resolveConfig rejects wildcard hosts and bad tls modes', () => {
  assert.throws(() => resolveConfig({ host: '0.0.0.0' }), /wildcard/)
  assert.throws(() => resolveConfig({ host: '::' }), /wildcard/)
  assert.throws(() => resolveConfig({ tls: { mode: 'sometimes' } }), /tls mode/)
  assert.throws(() => resolveConfig({ port: 0 }), /port/)
})

test('apply registers the card routes and reports unconfigured without host', async () => {
  const { ctx, routes } = stubCtx()
  await apply(ctx, { port: 3099 })
  assert.deepEqual(routes.map((route) => route.path).sort(), [
    '/phone-access/ca',
    '/phone-access/link',
    '/phone-access/revoke',
    '/phone-access/status',
  ])
  const response = await routeOf(routes, '/phone-access/status').resource(new Request('http://127.0.0.1:61110/phone-access/status'))
  const body = await response.json()
  assert.equal(body.state, 'unconfigured')
  assert.ok(Array.isArray(body.addresses))
})

test('link is refused while unconfigured', async () => {
  const { ctx, routes } = stubCtx()
  await apply(ctx, { port: 3099 })
  const response = await routeOf(routes, '/phone-access/link').resource(
    new Request('http://127.0.0.1:61110/phone-access/link', { method: 'POST' }),
  )
  assert.equal(response.status, 409)
  const body = await response.json()
  assert.equal(body.error, 'not-configured')
})
