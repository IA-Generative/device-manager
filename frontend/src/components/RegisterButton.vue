<template>
  <div class="button-row">
    <div>Appareil</div>
    <div>
      <button :disabled="!!device.deviceId || home.busy" @click="doRegister">
        Register
      </button>
      <button @click="reset" :disabled="!device.deviceId">Reset</button>
      <button :disabled="!device.deviceId" @click="getStatus">
        Status
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">

import { useDeviceCrypto } from '@/composables/useDeviceCrypto.js'
import { useDeviceApi } from '@/composables/useDeviceApi';
import { useDeviceStore } from '@/stores/device';
import { useHomeStore } from '@/stores/home';
import { useAuthStore } from '@/stores/auth';


const emit = defineEmits<{
  reset: []
  data: [data: any],
}>()
const auth = useAuthStore()
const device = useDeviceStore()
const home = useHomeStore()
const api = useDeviceApi()

const deviceCrypto = useDeviceCrypto()

function setDeviceStatus(type: string, msg: string) {
  home.deviceStatusType = type
  home.deviceStatusMsg = msg
}



// ── Device actions ────────────────────────────────────────────────────────────
async function doRegister() {
  home.busy = true
  setDeviceStatus('info', 'Enregistrement du device…')
  try {
    const payload = await deviceCrypto.buildRegisterPayload(auth.accessToken)
    emit('data', { ...payload, public_key: payload.public_key ? payload.public_key.slice(0, 40) + '…' : '' })

    const result = await api.register({
      ...payload,
      device_id: device.deviceId,
      name: navigator.userAgent.slice(0, 64),
      user_agent: navigator.userAgent,
      platform: navigator.platform || 'browser',
    })
    device.setDeviceId(result.device_id)
    const response = await api.getStatus(device.deviceId)
    device.setDevice(response)

    if (result.status === 'pending_approval') {
      home.pendingDeviceId = result.device_id
      setDeviceStatus('warn', 'Appareil enregistré — en attente d\'approbation.')
    } else {
      setDeviceStatus('ok', `Appareil actif ! (${result.device_id.slice(0, 8)}…)`)
    }
  } catch (err: any) {
    setDeviceStatus('ko', err.message)
  } finally {
    home.busy = false
  }
}


function reset() {
  emit('reset')
}

async function getStatus() {
  try {
    const response = await api.getStatus(device.deviceId)
    if (response) {
      device.setDevice(response)
      if (response.status === 'pending_approval') {
        home.pendingDeviceId = response.device_id
        setDeviceStatus('warn', 'Appareil enregistré — en attente d\'approbation.')
      } else {
        setDeviceStatus('ok', `Appareil actif ! (${response.device_id.slice(0, 8)}…)`)
      }
    }
    
    emit('data', response)
  } catch (err) {
    console.error('API Call Error:', err)
  }
}

</script>