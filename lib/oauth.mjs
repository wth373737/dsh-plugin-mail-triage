/**
 * OAuth2 token exchange for the accounts that cannot use a plain password.
 *
 * Microsoft returns a *rotated* refresh token on every refresh, so the caller
 * must persist the new one; otherwise the next process start would fall back to
 * an older token and eventually fail. Rotated tokens are written back through
 * the credentials service so the plugin owns its own chain after import.
 */

const MS_CLIENT_ID = '9e5f94bc-e8a4-4e73-b8be-63364c29d753'

/**
 * @param {{refreshToken: string, clientId?: string, tenant?: string, scope?: string, signal?: AbortSignal}} options
 * @returns {Promise<{accessToken: string, refreshToken?: string, expiresAt: number}>}
 */
export async function refreshMicrosoftToken(options) {
  const clientId = options.clientId || MS_CLIENT_ID
  const tenant = options.tenant || 'common'
  const scope = options.scope || 'https://outlook.office.com/IMAP.AccessAsUser.All offline_access'
  const body = new URLSearchParams({
    client_id: clientId,
    grant_type: 'refresh_token',
    refresh_token: options.refreshToken,
    scope,
  })
  const response = await fetch(`https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
    signal: options.signal,
  })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok || !payload.access_token) {
    const detail = payload.error_description || payload.error || `HTTP ${response.status}`
    throw new Error(`Microsoft 令牌刷新失败：${String(detail).slice(0, 200)}`)
  }
  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token,
    expiresAt: Date.now() + Math.max(60, Number(payload.expires_in) || 3600) * 1000 - 120_000,
  }
}

/**
 * @param {{refreshToken: string, clientId: string, clientSecret?: string, signal?: AbortSignal}} options
 * @returns {Promise<{accessToken: string, refreshToken?: string, expiresAt: number}>}
 */
export async function refreshGoogleToken(options) {
  const body = new URLSearchParams({
    client_id: options.clientId,
    grant_type: 'refresh_token',
    refresh_token: options.refreshToken,
  })
  if (options.clientSecret) body.set('client_secret', options.clientSecret)
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
    signal: options.signal,
  })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok || !payload.access_token) {
    const detail = payload.error_description || payload.error || `HTTP ${response.status}`
    throw new Error(`Google 令牌刷新失败：${String(detail).slice(0, 200)}`)
  }
  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token,
    expiresAt: Date.now() + Math.max(60, Number(payload.expires_in) || 3600) * 1000 - 120_000,
  }
}

/**
 * Small process-local cache so one scan does not refresh a token per message.
 * The cache never outlives the process; the persisted refresh token is the only
 * durable state.
 */
export function createTokenCache() {
  const cache = new Map()
  return {
    get(accountId) {
      const hit = cache.get(accountId)
      if (hit && hit.expiresAt > Date.now()) return hit
      cache.delete(accountId)
      return undefined
    },
    set(accountId, value) {
      cache.set(accountId, value)
    },
    clear(accountId) {
      cache.delete(accountId)
    },
  }
}

/**
 * Resolve an access token for an xoauth2 account, refreshing when needed.
 * @param {object} account stored account descriptor
 * @param {{cache: ReturnType<typeof createTokenCache>, persistRefreshToken: (account: object, token: string) => Promise<void>, signal?: AbortSignal}} deps
 */
export async function resolveAccessToken(account, deps) {
  const cached = deps.cache?.get(account.id)
  if (cached) return cached.accessToken

  const auth = account.auth ?? {}
  const options = {
    refreshToken: auth.refreshToken,
    clientId: auth.clientId,
    clientSecret: auth.clientSecret,
    signal: deps.signal,
  }
  const refreshed =
    auth.oauthProvider === 'google'
      ? await refreshGoogleToken({ ...options, clientId: auth.clientId })
      : await refreshMicrosoftToken({ ...options, tenant: auth.tenant, scope: auth.scope })

  if (refreshed.refreshToken && refreshed.refreshToken !== auth.refreshToken) {
    await deps.persistRefreshToken?.(account, refreshed.refreshToken)
  }
  deps.cache?.set(account.id, refreshed)
  return refreshed.accessToken
}

