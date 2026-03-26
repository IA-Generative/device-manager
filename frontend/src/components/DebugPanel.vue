<template>
  <div>
    <template v-if="isHtml && !raw">
      <iframe :srcdoc="props.data" style="width: 100%; height: 400px; border: none;">
      </iframe>
    </template>
    <template v-else>
      <textarea readonly :value="formatted" placeholder="— debug —"></textarea>
    </template>
    <div class="buttons">
      <button :disabled="!props.data" @click="copy">
        {{ copied ? 'Copied!' : 'Copy' }}
      </button>
      <button :disabled="!props.data" @click="raw = !raw">
        {{ raw ? 'Raw' : 'Formatted' }}
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
const props = defineProps<{ data: any }>()

const raw = ref(false)
const isHtml = computed(() => typeof props.data === 'string' && props.data.trim().startsWith('<'))
const formatted = computed(() => {
  if (
    typeof props.data === 'string'
    || typeof props.data === 'number'
    || typeof props.data === 'boolean'
  ) {
    return props.data
  }
  if (raw.value) {
    return JSON.stringify(props.data)
  }
  return JSON.stringify(props.data, null, 2)
})

function copy() {
  navigator.clipboard.writeText(formatted.value)
  copied.value = true
}

const copied = ref(false)
watch(copied, (val) => {
  if (val) {
    setTimeout(() => copied.value = false, 2000)
  }
})
</script>

<style scoped>
textarea {
  width: 100%;
  height: 300px;
  font-family: monospace;
  font-size: 11px;
  color: #555;
  resize: vertical;
  box-sizing: border-box;
}

.buttons {
  position: absolute;
  top: -15px;
  right: 10px;
  margin-top: 6px;
}

.buttons button {
  padding: 6px 12px;
  font-size: 11px;

}

div {
  position: relative;
}
</style>
