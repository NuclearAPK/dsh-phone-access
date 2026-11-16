import test from 'node:test'
import assert from 'node:assert/strict'
import { detectAddresses, describeState } from '../src/state.js'

const interfaces = {
  'Беспроводная сеть': [{ address: '192.168.1.237', family: 'IPv4', internal: false }],
  'Ethernet 3': [{ address: '10.20.22.131', family: 'IPv4', internal: false }],
  'vEthernet (Default Switch)': [{ address: '172.30.80.1', family: 'IPv4', internal: false }],
  Loopback: [{ address: '127.0.0.1', family: 'IPv4', internal: true }],
  IPv6: [{ address: 'fe80::1', family: 'IPv6', internal: false }],
}

test('detectAddresses returns non-loopback IPv4 sorted', () => {
  assert.deepEqual(detectAddresses(interfaces), ['10.20.22.131', '172.30.80.1', '192.168.1.237'])
})

test('describeState reports unconfigured with snippet when host is missing', () => {
  const state = describeState({ port: 3099, tlsMode: 'auto', addresses: ['192.168.1.237'] })
  assert.equal(state.state, 'unconfigured')
  assert.deepEqual(state.addresses, ['192.168.1.237'])
  assert.match(state.snippet, /host: 192\.168\.1\.237/)
})

test('describeState reports listening url with https for tls modes', () => {
  const state = describeState({
    host: '192.168.1.237',
    port: 3099,
    tlsMode: 'auto',
    addresses: [],
    listener: { caFingerprint: 'AB:CD', tunnels: 2 },
  })
  assert.equal(state.state, 'listening')
  assert.equal(state.url, 'https://192.168.1.237:3099')
  assert.equal(state.tunnels, 2)
})

test('describeState reports host-not-local as error', () => {
  const state = describeState({ host: '10.0.0.5', port: 3099, tlsMode: 'auto', addresses: ['192.168.1.237'] })
  assert.equal(state.state, 'error')
  assert.equal(state.reason, 'host-not-local')
  assert.deepEqual(state.addresses, ['192.168.1.237'])
})

test('describeState prefers the advertised public url', () => {
  const state = describeState({
    host: '192.168.1.237',
    port: 3099,
    tlsMode: 'auto',
    addresses: ['192.168.1.237'],
    publicUrl: 'https://dsh.example.com',
    listener: { caFingerprint: null, tunnels: 0 },
  })
  assert.equal(state.url, 'https://dsh.example.com')
  assert.equal(state.bindUrl, 'https://192.168.1.237:3099')
})
