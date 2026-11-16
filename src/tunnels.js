/**
 * Live upgraded connections, kept so revoking access can actually close them.
 */
export function createTunnelRegistry() {
  /** @type {Set<{ client: import('node:net').Socket, upstream: import('node:net').Socket }>} */
  const live = new Set()
  return {
    /**
     * @param {import('node:net').Socket} client
     * @param {import('node:net').Socket} upstream
     */
    add(client, upstream) {
      const entry = { client, upstream }
      live.add(entry)
      const drop = () => {
        live.delete(entry)
        client.destroy()
        upstream.destroy()
      }
      client.once('close', drop)
      upstream.once('close', drop)
    },
    size() {
      return live.size
    },
    closeAll() {
      for (const entry of [...live]) {
        live.delete(entry)
        entry.client.destroy()
        entry.upstream.destroy()
      }
    },
  }
}
