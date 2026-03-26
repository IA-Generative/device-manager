<template>
  <div class="button-row">
    <div>Mock</div>
    <div>
      <button :disabled="!device.deviceId" @click="call">
        Generate Signature
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { makeSignature } from '@/lib/crypto';
import { useDeviceStore } from '@/stores/device';
import { useAuthStore } from '@/stores/auth';

const emits = defineEmits<{
  data: [headers: Record<string, string>]
}>()

const device = useDeviceStore()
const auth = useAuthStore()

async function call() {
  const signature = await makeSignature()

  try {
    emits('data', {
      "x-device-id": device.deviceId,
      "x-device-signature": signature.signature,
      "x-device-timestamp": signature.timestamp,
      "x-device-nonce": signature.nonce,
      authorization: `Bearer ${auth.accessToken}`,
    })
  } catch (err) {
    console.error('API Call Error:', err)
  }
}

</script>