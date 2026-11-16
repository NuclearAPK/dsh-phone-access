window.__ModuleLoader__.load({
  id: '@local/dsh-phone-access',
  factory(require) {
    const React = require('react')
    const h = React.createElement

    const styles = {
      wrap: { display: 'flex', flexDirection: 'column', gap: 12, fontSize: 14 },
      title: { fontSize: 16, fontWeight: 600, margin: 0 },
      row: { display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' },
      muted: { opacity: 0.7 },
      code: {
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
        fontSize: 12,
        padding: '8px 10px',
        borderRadius: 6,
        background: 'rgba(127, 127, 127, 0.12)',
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-all',
        margin: 0,
      },
      button: {
        font: 'inherit',
        padding: '6px 12px',
        borderRadius: 6,
        border: '1px solid rgba(127, 127, 127, 0.4)',
        background: 'transparent',
        color: 'inherit',
        cursor: 'pointer',
      },
      error: { color: 'var(--dsw-alias-label-danger, #c0392b)' },
    }

    async function call(path, method) {
      const response = await fetch(path, { method })
      const body = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(body.error ?? `HTTP ${String(response.status)}`)
      return body
    }

    function Card() {
      const [status, setStatus] = React.useState(null)
      const [link, setLink] = React.useState(null)
      const [error, setError] = React.useState(null)

      const refresh = React.useCallback(() => {
        fetch('/phone-access/status')
          .then((response) => response.json())
          .then(setStatus)
          .catch((failure) => setError(String(failure)))
      }, [])

      React.useEffect(() => {
        refresh()
      }, [refresh])

      const showLink = async () => {
        try {
          setError(null)
          setLink(await call('/phone-access/link', 'POST'))
        } catch (failure) {
          setError(String(failure.message ?? failure))
        }
      }
      const revoke = async () => {
        try {
          setError(null)
          setLink(null)
          await call('/phone-access/revoke', 'POST')
          refresh()
        } catch (failure) {
          setError(String(failure.message ?? failure))
        }
      }

      if (status === null) return h('div', { style: styles.wrap }, h('p', { style: styles.muted }, 'Загрузка…'))

      return h('div', { style: styles.wrap },
        h('h3', { style: styles.title }, 'Доступ с телефона'),
        h('p', { style: styles.muted },
          'Телефон получает полный доступ к этому хосту: сессии, промпты, аппрувы, файлы. Только доверенная сеть.'),
        status.state === 'unconfigured'
          ? h('div', { style: styles.wrap },
            h('p', null, 'Адрес не задан. Впишите в конфиг плагина один из адресов этой машины:'),
            h('pre', { style: styles.code }, status.snippet),
            h('p', { style: styles.muted }, `Найдены: ${(status.addresses ?? []).join(', ') || 'ни одного'}`),
          )
          : null,
        status.state === 'error'
          ? h('div', { style: styles.wrap },
            h('p', { style: styles.error }, `Ошибка: ${status.reason}`),
            h('p', { style: styles.muted }, status.message),
            h('p', { style: styles.muted }, `Адреса: ${(status.addresses ?? []).join(', ') || 'ни одного'}`),
          )
          : null,
        status.state === 'listening'
          ? h('div', { style: styles.wrap },
            h('div', { style: styles.row },
              h('strong', null, status.url),
              h('span', { style: styles.muted }, `TLS: ${status.tlsMode} · туннелей: ${String(status.tunnels)}`),
            ),
            status.caFingerprint
              ? h('pre', { style: styles.code }, `CA SHA-256: ${status.caFingerprint}`)
              : null,
            h('div', { style: styles.row },
              h('button', { type: 'button', style: styles.button, onClick: showLink }, 'Показать ссылку'),
              h('a', { style: styles.button, href: '/phone-access/ca', download: 'dsh-phone-ca.pem' }, 'Скачать CA'),
              h('button', { type: 'button', style: styles.button, onClick: revoke }, 'Отозвать все'),
            ),
            h('div', { style: styles.row },
              h('img', {
                src: '/phone-access/qr',
                alt: 'QR-код: скачать сертификат CA',
                width: 168,
                height: 168,
                style: { background: '#fff', padding: 6, borderRadius: 8 },
              }),
              h('p', { style: styles.muted },
                'Наведите камеру телефона на QR — откроется файл сертификата. Установите его как сертификат ЦС, затем повторите со ссылкой из «Показать ссылку».'),
            ),
            link
              ? h('div', { style: styles.wrap },
                h('p', { style: styles.muted }, 'Ссылка одноразовая. На телефоне сначала установите CA, потом откройте ссылку.'),
                h('pre', { style: styles.code }, link.url),
                h('div', { style: styles.row },
                  h('a', { style: styles.button, href: link.url, target: '_blank', rel: 'noreferrer' }, 'Открыть ссылку на этом ПК'),
                  h('button', {
                    type: 'button',
                    style: styles.button,
                    onClick: () => { void navigator.clipboard?.writeText(link.url) },
                  }, 'Скопировать ссылку'),
                ),
              )
              : null,
            status.tlsMode === 'off'
              ? h('p', { style: styles.error }, 'TLS выключен: кука ходит по сети открытым текстом. Включайте только для отладки.')
              : null,
            h('p', { style: styles.muted },
              'Если телефон не открывает адрес, разрешите порт в брандмауэре Windows. Отзыв закрывает и открытые потоки.'),
          )
          : null,
        error ? h('p', { style: styles.error }, error) : null,
      )
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('settings.section', () => ctx.slots.register({
          name: 'settings.section',
          id: 'phone-access',
          label: 'Телефон',
        }, Card))
      },
    }
  },
})

