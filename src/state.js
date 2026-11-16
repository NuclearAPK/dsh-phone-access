import os from 'node:os'

/**
 * Non-loopback IPv4 addresses of this machine, sorted, unique.
 * @param {NodeJS.Dict<os.NetworkInterfaceInfo[]>} [interfaces]
 * @returns {string[]}
 */
export function detectAddresses(interfaces = os.networkInterfaces()) {
  const found = new Set()
  for (const entries of Object.values(interfaces ?? {})) {
    for (const entry of entries ?? []) {
      const family = entry.family
      if (family !== 'IPv4' && family !== 4) continue
      if (entry.internal) continue
      if (entry.address) found.add(entry.address)
    }
  }
  return [...found].sort()
}

/**
 * @param {{
 *   host?: string,
 *   port: number,
 *   tlsMode: string,
 *   addresses: string[],
 *   listener?: { caFingerprint: string | null, tunnels: number },
 *   error?: { reason: string, message: string },
 * }} input
 * @returns {object} the state the settings card renders
 */
export function describeState(input) {
  const { host, port, tlsMode, addresses, listener, error } = input
  if (error) return { state: 'error', reason: error.reason, message: error.message, addresses }
  if (!host) {
    const suggested = addresses[0] ?? '127.0.0.1'
    return {
      state: 'unconfigured',
      addresses,
      snippet: `host: ${suggested}\nport: ${port}\ntls:\n  mode: ${tlsMode}`,
    }
  }
  if (addresses.length > 0 && !addresses.includes(host)) {
    return {
      state: 'error',
      reason: 'host-not-local',
      message: `address ${host} is not one of this machine's IPv4 addresses`,
      addresses,
    }
  }
  const scheme = tlsMode === 'off' ? 'http' : 'https'
  return {
    state: 'listening',
    host,
    port,
    tlsMode,
    caFingerprint: listener?.caFingerprint ?? null,
    tunnels: listener?.tunnels ?? 0,
    url: `${scheme}://${host}:${port}`,
  }
}
