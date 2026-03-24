<template>

  <button @click="call">
    Verify Call
  </button>
</template>

<script setup lang="ts">
import { useDeviceApi } from '@/composables/useDeviceApi';
import { useAuthStore } from '@/stores/auth';


const props = defineProps<{
  logFn: (label: string, data: unknown) => void
}>()

const auth = useAuthStore()
const api = useDeviceApi()

async function call() {
  try {
    const response = await api.verifyDevice(auth.deviceId)
    props.logFn('API CALL response headers', response)
  } catch (err) {
    console.error('API Call Error:', err)
  }
}

</script>