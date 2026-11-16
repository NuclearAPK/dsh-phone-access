import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import net from 'node:net'
import { createTunnelRegistry } from '../src/tunnels.js'
import { forwardUpgrade } from '../src/proxy.js'

async function startEchoUpgrade() {
  const server = http.createServer((_req, res) => {
    res.writeHead(404)
    res.end()
  })
  server.on('upgrade', (req, socket) => {
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
    socket.pipe(socket)
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  return { origin: `http://127.0.0.1:${port}`, port, close: () => new Promise((resolve) => server.close(resolve)) }
}

async function startProxy(innerOrigin, tunnels) {
  const server = http.createServer((_req, res) => {
    res.writeHead(404)
    res.end()
  })
  server.on('upgrade', (req, socket, head) => {
    forwardUpgrade(req, socket, head, { innerOrigin, innerCookie: 'inner-cookie=1', tunnels })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address()
  return { port, close: () => new Promise((resolve) => server.close(resolve)) }
}

function upgrade(port) {
  const socket = net.connect(port, '127.0.0.1')
  socket.setNoDelay(true)
  const chunks = []
  socket.on('data', (chunk) => chunks.push(chunk))
  const ready = new Promise((resolve) => socket.on('connect', resolve))
  return { socket, chunks, ready, text: () => Buffer.concat(chunks).toString('utf8') }
}

test('upgrade is proxied and echo comes back', async () => {
  const inner = await startEchoUpgrade()
  const tunnels = createTunnelRegistry()
  const proxy = await startProxy(inner.origin, tunnels)
  const client = upgrade(proxy.port)
  try {
    await client.ready
    client.socket.write(
      'GET /api/remote.mux HTTP/1.1\r\nHost: 192.168.1.237:3099\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n',
    )
    await new Promise((resolve) => setTimeout(resolve, 100))
    client.socket.write('hello')
    await new Promise((resolve) => setTimeout(resolve, 100))
    assert.match(client.text(), /101 Switching Protocols/)
    assert.match(client.text(), /hello/)
    assert.equal(tunnels.size(), 1)
  } finally {
    client.socket.destroy()
    await proxy.close()
    await inner.close()
    tunnels.closeAll()
  }
})

test('closeAll destroys both sides of an open tunnel', async () => {
  const inner = await startEchoUpgrade()
  const tunnels = createTunnelRegistry()
  const proxy = await startProxy(inner.origin, tunnels)
  const client = upgrade(proxy.port)
  try {
    await client.ready
    client.socket.write(
      'GET /api/remote.mux HTTP/1.1\r\nHost: 192.168.1.237:3099\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n',
    )
    await new Promise((resolve) => setTimeout(resolve, 100))
    assert.equal(tunnels.size(), 1)
    const closed = new Promise((resolve) => client.socket.on('close', resolve))
    tunnels.closeAll()
    await closed
    assert.equal(tunnels.size(), 0)
  } finally {
    client.socket.destroy()
    await proxy.close()
    await inner.close()
  }
})
