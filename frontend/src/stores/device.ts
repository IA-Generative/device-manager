import { defineStore } from 'pinia'
import { ref } from 'vue'

const DEVICE_ID_KEY = 'device-service:last-device-id'

type DeviceState = {
  "device_id": string,
  "user_id": string,
  "status": string,
  "hardware_level": string,
  "trust_score": number,
  "attested_at": string,
  "reattest_at": string,
  "signed": boolean
}
export const useDeviceStore = defineStore('device', () => {
  const deviceId = ref(localStorage.getItem(DEVICE_ID_KEY) || '')
  const device = ref<DeviceState | null>(null)

  function setDeviceId(id: string) {
    deviceId.value = id
    localStorage.setItem(DEVICE_ID_KEY, id)
  }

  function clear() {
    localStorage.removeItem(DEVICE_ID_KEY)
  }

  async function setDevice(status: DeviceState) {
    device.value = status
  }

  return {
    deviceId,
    device,
    setDeviceId,
    setDevice,
    clear
  }
})
