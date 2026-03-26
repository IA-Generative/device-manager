<template>

</template>

<script setup lang="ts">
import { useDeviceApi } from '@/composables/useDeviceApi';
import { useDeviceStore } from '@/stores/device';

const emits = defineEmits<{
  data: [data: any]
}>()

const device = useDeviceStore()
const api = useDeviceApi()
</script>