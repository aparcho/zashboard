<template>
  <div
    class="text-base-content/40 flex shrink-0 items-center gap-1.5 text-xs whitespace-nowrap tabular-nums"
    :data-speed-group="name"
  >
    <span
      :aria-label="`下载速度 ${download}/s`"
      title="下载速度"
      >↓ {{ download }}/s</span
    >
    <span
      class="text-base-content/25"
      aria-hidden="true"
      >·</span
    >
    <span
      :aria-label="`上传速度 ${upload}/s`"
      title="上传速度"
      >↑ {{ upload }}/s</span
    >
  </div>
</template>
<script setup lang="ts">
import {
  getDownloadSpeedByProxyGroup,
  getUploadSpeedByProxyGroup,
} from '@/helper/proxy-group-traffic'
import { prettyBytesHelper } from '@/helper/utils'
import { computed } from 'vue'
const props = defineProps<{ name: string }>()
const download = computed(() => prettyBytesHelper(getDownloadSpeedByProxyGroup(props.name)))
const upload = computed(() => prettyBytesHelper(getUploadSpeedByProxyGroup(props.name)))
</script>
