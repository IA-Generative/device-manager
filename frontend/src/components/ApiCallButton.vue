<template>

  <button :disabled="!api.enabled" @click="call">
    True API Call
  </button>
  <button :disabled="!api.enabled" @click="callHead">
    True HEAD Call
  </button>
</template>

<script setup lang="ts">
import { useExampleApi } from '@/composables/useExampleApi';

const props = defineProps<{
  logFn: (label: string, data: unknown) => void
}>()

const api = useExampleApi()

async function call() {
  try {
    const response = await api.call()
    props.logFn('API CALL response headers', response)
  } catch (err) {
    console.error('API Call Error:', err)
  }
}

async function callHead() {
  try {
    const response = await api.callHead()
    props.logFn('API HEAD CALL response headers', response)
  } catch (err) {
    console.error('API HEAD Call Error:', err)
  }
}
</script>