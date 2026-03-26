/**
 * crypto.js — Web Crypto API + device-bound session signatures (ES module)
 */

const DB_NAME = 'device-crypto-keys'
const STORE_NAME = 'keys'
const KEY_ID = 'device-ecdsa-key'

// ── IndexedDB helpers ──────────────────────────────────────────────────────────
function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1)
    req.onupgradeneeded = () => req.result.createObjectStore(STORE_NAME)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function storeKeyPair(keyPair: CryptoKeyPair): Promise<void> {
  const db = await openDB()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite')
    tx.objectStore(STORE_NAME).put(keyPair, KEY_ID)
    tx.oncomplete = () => resolve()
    tx.onerror = () => reject(tx.error)
  })
}

export async function loadKeyPair(): Promise<CryptoKeyPair | null> {
  const db = await openDB()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly')
    const req = tx.objectStore(STORE_NAME).get(KEY_ID)
    req.onsuccess = () => resolve(req.result || null)
    req.onerror = () => reject(req.error)
  })
}

async function clearKeyPair(): Promise<void> {
  const db = await openDB()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite')
    tx.objectStore(STORE_NAME).delete(KEY_ID)
    tx.oncomplete = () => resolve()
    tx.onerror = () => reject(tx.error)
  })
}

// ── Key generation ─────────────────────────────────────────────────────────────
export async function generateKeyPair(): Promise<CryptoKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, // non-extractible
    ['sign', 'verify']
  )
  await storeKeyPair(keyPair)
  return keyPair
}

export async function getOrCreateKeyPair(): Promise<CryptoKeyPair> {
  const kp = await loadKeyPair()
  if (kp?.privateKey && kp?.publicKey) return kp
  return generateKeyPair()
}

// ── Key export ─────────────────────────────────────────────────────────────────
export async function exportPublicKeyPEM(publicKey: CryptoKey): Promise<string> {
  const spki = await crypto.subtle.exportKey('spki', publicKey)
  const b64 = arrayBufferToBase64(spki)
  const lines = b64.match(/.{1,64}/g).join('\n')
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`
}

// ── Signing ────────────────────────────────────────────────────────────────────
export async function signPayload(privateKey: CryptoKey, payload: string): Promise<string> {
  const data = new TextEncoder().encode(payload)
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data)
  return arrayBufferToBase64(signature)
}

export async function signChallenge(challenge: string): Promise<{ nonce: string, timestamp: string, signature: string, challenge: string }> {
  const keyPair = await getOrCreateKeyPair()
  const nonce = crypto.randomUUID()
  const timestamp = new Date().toISOString()
  const signature = await signPayload(keyPair.privateKey, nonce + '|' + timestamp)
  return { nonce, timestamp, signature, challenge }
}

export async function signRegisterChallenge(challenge: string): Promise<{ challenge: string, signature: string }> {
  const keyPair = await getOrCreateKeyPair()
  const signature = await signPayload(keyPair.privateKey, challenge)
  return { challenge, signature }
}

// ── Device-bound session headers ───────────────────────────────────────────────
export async function makeSignature(): Promise<{ nonce: string, timestamp: string, signature: string }> {
  try {
    const kp = await loadKeyPair()
    if (!kp?.privateKey) return
    const nonce = crypto.randomUUID()
    const timestamp = new Date().toISOString()
    const signature = await signPayload(kp.privateKey, nonce + '|' + timestamp)
    return { 
      nonce,
      timestamp,
      signature,
    }
  } catch (_) {
    return
  }
}

export async function makeDeviceHeaders(deviceId: string): Promise<{ [key: string]: string } | {}> {
  if (!deviceId) return {}
  try {
    const kp = await makeSignature()
    if (kp) {
      return { 
        'X-Device-ID': deviceId,
        'X-Device-Nonce': kp.nonce,
        'X-Device-Timestamp': kp.timestamp,
        'X-Device-Signature': kp.signature,
      }
    }
    return {
      'X-Device-ID': deviceId,
    }
  } catch (_) {
    return {}
  }
}

// ── Hardware detection ─────────────────────────────────────────────────────────
export async function detectHardwareLevel(): Promise<{ level: string, provider: string }> {
  try {
    if (!window.PublicKeyCredential) return { level: 'software', provider: 'software' }
    const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
    if (available) {
      const p = navigator.platform || ''
      let provider = 'tee'
      if (/Mac|iPhone|iPad/.test(p)) provider = 'secure_enclave'
      else if (/Win/.test(p)) provider = 'tpm'
      else if (/Linux/.test(p)) provider = 'tpm'
      return { level: 'tee', provider }
    }
    return { level: 'software', provider: 'software' }
  } catch (_) {
    return { level: 'software', provider: 'software' }
  }
}

// ── Utils ──────────────────────────────────────────────────────────────────────
export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  bytes.forEach(b => binary += String.fromCharCode(b))
  return btoa(binary)
}

export async function resetKeys() {
  await clearKeyPair()
}
