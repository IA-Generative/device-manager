import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { decodeJWT, isTokenExpired } from '@/lib/api'

const ACCESS_TOKEN_KEY = 'device-service:access-token'

export const useAuthStore = defineStore('auth', () => {
  const accessToken = ref(sessionStorage.getItem(ACCESS_TOKEN_KEY) || '')

  const isAuthenticated = computed(() => !!accessToken.value && !isTokenExpired(accessToken.value))

  const user = computed(() => {
    if (!accessToken.value) return null
    try { return decodeJWT(accessToken.value) } catch (_) { return null }
  })

  const username = computed(() => user.value?.preferred_username || user.value?.sub || '')

  function setToken(token) {
    accessToken.value = token
    sessionStorage.setItem(ACCESS_TOKEN_KEY, token)
  }


  function clear() {
    accessToken.value = ''
    sessionStorage.removeItem(ACCESS_TOKEN_KEY)
  }

  return {
    accessToken,
    isAuthenticated,
    user,
    username,
    setToken,
    clear
  }
})
