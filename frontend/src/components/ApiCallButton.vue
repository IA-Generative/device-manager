<template>
  <div class="button-row">
    <div>
      External API
    </div>
    <div>
      <button :disabled="!exampleApi.enabled || !device.deviceId" @click="call">
        GET
      </button>
      <button :disabled="!exampleApi.enabled || !device.deviceId" @click="callHead">
        HEAD
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useExampleApi } from '@/composables/useExampleApi';
import { useDeviceStore } from '@/stores/device';

const device = useDeviceStore();

const emits = defineEmits<{
  data: [data: any]
}>()

const exampleApi = useExampleApi()

async function call() {
  try {
    const response = await exampleApi.call()
    emits('data', await response.text())
  } catch (err) {
    console.error('API Call Error:', err)
  }
}

async function callHead() {
  try {
    const response = await exampleApi.callHead()
    emits('data', await response.text())
  } catch (err) {
    console.error('API HEAD Call Error:', err)
  }
}
</script>