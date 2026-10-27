<template>
  <button
    class="text-base-content/45 hover:text-base-content min-w-0 truncate text-center text-[11px] whitespace-nowrap tabular-nums"
    :data-traffic-group="name"
    :title="tooltip"
    @click.stop="handleClick"
    @contextmenu.stop
  >
    <template v-if="groupTotals?.since">
      <span class="mr-1 opacity-70">累计</span
      ><span class="text-base-content/65">{{ bytes(total.upload + total.download) }}</span>
      <span
        v-if="stale"
        class="text-warning ml-1"
        >未更新</span
      >
    </template>
    <span
      v-else
      class="opacity-60"
      >{{ groupTotalsError ? '统计暂不可用' : '统计加载中' }}</span
    >
  </button>
</template>
<script setup lang="ts">
import { prettyBytesHelper } from '@/helper/utils'
import {
  groupTotals,
  groupTotalsError,
  groupTotalsMap,
  refreshGroupTotals,
  trafficDetailsGroup,
} from '@/store/traffic-stats'
import { computed } from 'vue'
const props = defineProps<{ name: string }>()
const total = computed(() => groupTotalsMap.value.get(props.name) ?? { upload: 0, download: 0 })
const stale = computed(() => !!groupTotalsError.value || !groupTotals.value?.healthy)
const bytes = (value: number) => prettyBytesHelper(value, { binary: true })
const tooltip = computed(() => {
  if (!groupTotals.value) return groupTotalsError.value || '累计流量自动加载'
  const since = groupTotals.value.since
    ? new Date(groupTotals.value.since * 1000).toLocaleString('zh-CN', {
        timeZone: 'Asia/Shanghai',
      })
    : '首次采样'
  return `下载 ${bytes(total.value.download)} · 上传 ${bytes(total.value.upload)}\n自 ${since} 起累计。点击查看详情。嵌套组有重叠，不能相加为全局流量。${stale.value ? ' 当前显示上次成功获取的数据。' : ''}`
})
function handleClick() {
  if (groupTotals.value) trafficDetailsGroup.value = props.name
  else void refreshGroupTotals()
}
</script>
