<template>
  <AppNav />
  <main>
    <RouterView />
  </main>
</template>

<script setup lang="ts">
import AppNav from '@/components/AppNav.vue'
</script>

<style>
main {
  max-width: 1080px;
  margin: 24px auto;
  padding: 0 16px;
}
</style>
