import { apiFetch, EXAMPLE_API_URL } from '@/lib/example-api'
import { useAuthStore } from '@/stores/auth'
import { useDeviceCrypto } from './useDeviceCrypto'

export function useExampleApi() {
  const auth = useAuthStore()
  const deviceCrypto = useDeviceCrypto()

  async function authHeader() {
    const headers = await deviceCrypto.makeDeviceHeaders(auth.deviceId)
    const headersWithAuth = { 
      'Authorization': `Bearer ${auth.accessToken}`,
      ...headers,
    }
    return headersWithAuth
  }

  const call = async () =>
    apiFetch(`${EXAMPLE_API_URL}`, {
      method: 'GET',
      headers: await authHeader(),
    })

  const callHead = async () =>
    apiFetch(`${EXAMPLE_API_URL}`, {
      method: 'HEAD',
      headers: await authHeader(),
    })

  return { call, callHead, enabled: !!EXAMPLE_API_URL }
}
