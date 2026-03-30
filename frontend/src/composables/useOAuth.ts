import { useAuthStore } from '@/stores/auth'
import { apiFetch, DEVICE_SERVICE_BASE_URL } from '@/lib/api'
import { buildAuthUrl, exchangeCode, hasOAuthCallbackParams, clearOAuthQueryParams } from '@/lib/oauth'
import { useDeviceStore } from '@/stores/device'

export function useOAuth() {
  const auth = useAuthStore()
  const device = useDeviceStore()

  async function discover() {
    console.log(`${DEVICE_SERVICE_BASE_URL}/discover`);
    
    const data = await apiFetch(`${DEVICE_SERVICE_BASE_URL}/discover`)
    if (!data.auth_base_url || !data.realm || !data.client_id) throw new Error('/discover incomplet')
    return data
  }

  async function redirectToLogin(options: { redirectUri?: string } = {}) {
    const disc = await discover()
    const redirectUri = options.redirectUri ?? `${window.location.origin}/`
    const url = await buildAuthUrl(disc, {
      redirectUri,
      deviceId: device.deviceId
    })
    window.location.assign(url)
  }

  /**
   * Handles OAuth callback on page load.
   * Returns the access token or null if no callback params.
   */
  async function handleCallback() {
    if (!hasOAuthCallbackParams()) return null

    const params = new URLSearchParams(window.location.search)
    const error = params.get('error')
    if (error) {
      clearOAuthQueryParams()
      throw new Error(`Erreur OAuth: ${error} — ${params.get('error_description') || ''}`)
    }

    const code = params.get('code')
    const state = params.get('state')
    if (!code) return null

    const token = await exchangeCode(code, state)
    auth.setToken(token)
    clearOAuthQueryParams()
    return token
  }

  async function logout() {
    const disc = await discover()
    const postLogoutUri = window.location.origin + window.location.pathname
    auth.clear()
    const url = new URL(`${disc.auth_base_url}/realms/${encodeURIComponent(disc.realm)}/protocol/openid-connect/logout`)
    url.searchParams.set('client_id', disc.client_id)
    url.searchParams.set('post_logout_redirect_uri', postLogoutUri)
    window.location.assign(url.toString())
  }

  return { discover, redirectToLogin, handleCallback, logout }
}
