import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useHomeStore = defineStore('home', () => {
  const busy = ref(false)
  const deviceStatusType = ref("")
  const deviceStatusMsg = ref("")
  const pendingDeviceId = ref("")
  return {
    busy,
    deviceStatusType,
    deviceStatusMsg,
    pendingDeviceId
  }
})
