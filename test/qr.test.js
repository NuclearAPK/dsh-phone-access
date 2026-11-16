import test from 'node:test'
import assert from 'node:assert/strict'
import { qrSvg } from '../src/qr.js'

test('qrSvg renders a self-contained svg', () => {
  const svg = qrSvg('https://192.168.1.237:3099/ca.crt')
  assert.match(svg, /^<svg[^>]*xmlns="http:\/\/www\.w3\.org\/2000\/svg"/)
  assert.match(svg, /<rect/)
  assert.match(svg, /<\/svg>$/)
})

test('different text yields a different code', () => {
  assert.notEqual(qrSvg('https://192.168.1.237:3099/ca.crt'), qrSvg('https://192.168.1.237:3099/?t=abc'))
})

test('a long url still renders', () => {
  const svg = qrSvg(`https://192.168.1.237:3099/?t=${'a'.repeat(43)}`)
  assert.match(svg, /<rect/)
})
