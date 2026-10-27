<template>
  <button
    class="text-base-content/55 hover:text-base-content mt-2 flex w-full flex-wrap items-center gap-x-3 gap-y-0.5 text-left text-[11px] tabular-nums"
    :data-traffic-group="name"
    :title="tooltip"
    @click.stop="handleClick"
    @contextmenu.stop
  >
    <template v-if="groupTotals?.since">
      <span
        >累计
        <span class="text-base-content/80 font-medium">{{
          bytes(total.upload + total.download)
        }}</span></span
      >
      <span>↓ {{ bytes(total.download) }}</span>
      <span>↑ {{ bytes(total.upload) }}</span>
      <span
        v-if="stale"
        class="text-warning"
        >未更新</span
      >
    </template>
    <span v-else>{{ groupTotalsError ? '累计统计暂不可用 · 点击设置' : '启用累计统计' }}</span>
  </button>
</template>
<script setup lang="ts">
import { prettyBytesHelper } from '@/helper/utils'
import {
  groupTotals,
  groupTotalsError,
  groupTotalsMap,
  statsSettingsOpen,
  trafficDetailsGroup,
} from '@/store/traffic-stats'
import { computed } from 'vue'
const props = defineProps<{ name: string }>()
const total = computed(() => groupTotalsMap.value.get(props.name) ?? { upload: 0, download: 0 })
const stale = computed(() => !!groupTotalsError.value || !groupTotals.value?.healthy)
const bytes = (value: number) => prettyBytesHelper(value, { binary: true })
const tooltip = computed(() => {
  if (!groupTotals.value)
    return groupTotalsError.value || '连接统计服务后，自动在各分流卡片显示累计流量'
  const since = groupTotals.value.since
    ? new Date(groupTotals.value.since * 1000).toLocaleString('zh-CN', {
        timeZone: 'Asia/Shanghai',
      })
    : '首次采样'
  return `自 ${since} 起，按实际经过该组的连接累计。点击查看详情；嵌套组有重叠，不能相加为全局流量。${stale.value ? ' 当前显示上次成功获取的数据。' : ''}`
})
function handleClick() {
  if (groupTotals.value) trafficDetailsGroup.value = props.name
  else statsSettingsOpen.value = true
}
</script>
