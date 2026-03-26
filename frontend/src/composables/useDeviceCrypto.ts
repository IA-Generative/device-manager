import { apiFetch, DEVICE_SERVICE_BASE_URL } from '@/lib/api'
import { useSettingsStore } from '@/stores/settings'
import {
  getOrCreateKeyPair, exportPublicKeyPEM, signRegisterChallenge,
  signChallenge, detectHardwareLevel, loadKeyPair, resetKeys, makeDeviceHeaders as _makeDeviceHeaders
} from '@/lib/crypto'
import { useDeviceStore } from '@/stores/device'

export function useDeviceCrypto() {
  const device = useDeviceStore()
  const settings = useSettingsStore()

  /**
   * Full register ceremony: challenge → key → sign → return payload fields
   * hwMode: 'auto' | 'none' | 'software' | 'hardware'
   */
  async function buildRegisterPayload(accessToken: string) {
    const hwMode = settings.hardwareLevel
    let publicKeyPEM = '', keyAlgorithm = '',
      providerName = '', challenge = '', challengeSignature = ''

    if (hwMode === 'none') return { publicKeyPEM, keyAlgorithm, providerName, challenge, challengeSignature }

    try {
      const challengeResp = await apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/register/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` }
      })
      challenge = challengeResp.challenge

      const keyPair = await getOrCreateKeyPair()
      publicKeyPEM = await exportPublicKeyPEM(keyPair.publicKey)
      keyAlgorithm = 'ES256'

      const signResult = await signRegisterChallenge(challenge)
      challengeSignature = signResult.signature

      if (hwMode === 'software') {
        providerName = 'software'
      } else {
        const hwInfo = await detectHardwareLevel()
        providerName = hwInfo.provider
      }
    } catch (err) {
      console.warn('Attestation ceremony failed:', err.message)
      return { publicKeyPEM: '', keyAlgorithm: '', providerName: 'software', challenge: '', challengeSignature: '' }
    }

    const result = { 
      public_key: publicKeyPEM,
      key_algorithm: keyAlgorithm,
      provider_name: providerName,
      challenge,
      challenge_signature: challengeSignature,
    }
    console.log('Register payload:', result)
    return result
  }

  async function buildReattestPayload(deviceId, accessToken) {
    const challengeResp = await apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/${encodeURIComponent(deviceId)}/challenge`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${accessToken}` }
    })
    const signData = await signChallenge(challengeResp.challenge)
    const hwInfo = await detectHardwareLevel()

    let publicKeyPEM = ''
    try {
      const kp = await loadKeyPair()
      if (kp?.publicKey) publicKeyPEM = await exportPublicKeyPEM(kp.publicKey)
    } catch (_) {}
    if (!publicKeyPEM) {
      console.warn('No key available for re-attestation, proceeding without public key')
      hwInfo.level = ''
      hwInfo.provider = ''
    }
    const result = {
      signature: signData.signature,
      timestamp: signData.timestamp,
      nonce: signData.nonce,
      public_key: publicKeyPEM,
      key_algorithm: 'ES256',
      provider_name: hwInfo.provider
    }
    console.log(result);
    
    return result
  }

  async function makeDeviceHeaders(deviceId) {
    return _makeDeviceHeaders(deviceId)
  }

  async function reset() {
    device.setDeviceId('')
    await resetKeys()
  }

  return { buildRegisterPayload, buildReattestPayload, makeDeviceHeaders, reset }
}
