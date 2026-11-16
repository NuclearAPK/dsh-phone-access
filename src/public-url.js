import { existsSync } from 'node:fs'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

const FILE = 'public-url.txt'

/**
 * The address the phone dials. Accepts a bare host (optionally with a port)
 * and assumes https, because a phone link without a scheme is ambiguous and
 * the plain-http mode is the debugging exception.
 * @param {string} input
 * @returns {string} an origin such as `https://dsh.example.com:3099`
 */
export function normalizePublicUrl(input) {
  const text = String(input ?? '').trim()
  if (text === '') throw new Error('phone-access: public url is empty')
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `https://${text}`
  let url
  try {
    url = new URL(withScheme)
  } catch {
    throw new Error(`phone-access: public url is not a valid address: ${text}`)
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`phone-access: public url must be http or https, not ${url.protocol}`)
  }
  if (url.pathname !== '/' || url.search !== '' || url.hash !== '') {
    throw new Error(`phone-access: public url must be an origin without a path: ${text}`)
  }
  return url.origin
}

/**
 * @param {string} dir
 * @returns {Promise<string | undefined>}
 */
export async function readPublicUrl(dir) {
  const path = join(dir, FILE)
  if (!existsSync(path)) return undefined
  const text = (await readFile(path, 'utf8')).trim()
  if (text === '') return undefined
  return normalizePublicUrl(text)
}

/**
 * @param {string} dir
 * @param {string} value
 */
export async function writePublicUrl(dir, value) {
  await mkdir(dir, { recursive: true })
  await writeFile(join(dir, FILE), `${normalizePublicUrl(value)}\n`, 'utf8')
}

