<template>

  <button :disabled="!auth.deviceId" @click="call">
    Generate tmp Signature
  </button>
</template>

<script setup lang="ts">
import { useAuthStore } from '@/stores/auth';
import { makeDeviceHeaders } from '@/lib/crypto';

const emits = defineEmits<{
  data: [headers: Record<string, string>]
}>()

const auth = useAuthStore()

async function call() {
  try {
    emits('data', {
      Authorization: `Bearer ${auth.accessToken}`,
      ...await makeDeviceHeaders(auth.deviceId)
    })
  } catch (err) {
    console.error('API Call Error:', err)
  }
}

</script>