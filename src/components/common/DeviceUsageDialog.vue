<template>
  <DialogWrapper
    v-model="deviceUsageOpen"
    title="设备用量"
    box-class="md:max-w-3xl"
  >
    <div class="stats-integration-content flex flex-col gap-4 text-sm">
      <div class="flex flex-wrap items-center gap-2">
        <input
          v-model="month"
          type="month"
          class="input input-sm w-40"
          aria-label="设备用量月份"
        />
        <input
          v-model="search"
          class="input input-sm min-w-32 flex-1"
          placeholder="源主机 / IP"
          aria-label="筛选设备用量"
        />
        <button
          class="btn btn-sm"
          :disabled="busy"
          @click="load"
        >
          刷新
        </button>
      </div>
      <p
        v-if="error"
        class="text-error"
        role="alert"
      >
        {{ error }}
      </p>
      <div class="overflow-x-auto">
        <table class="table-sm table w-full table-fixed text-xs whitespace-nowrap md:text-sm">
          <thead>
            <tr>
              <th class="w-2/5">源主机 / IP</th>
              <th class="text-right">下载</th>
              <th class="text-right">上传</th>
              <th class="text-right">合计</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="row in rows"
              :key="row.source_ip"
            >
              <td>
                <button
                  class="w-full truncate text-left hover:underline"
                  :title="row.source_ip"
                  :disabled="!ipaddr.isValid(row.source_ip)"
                  @click="openDeviceEditor(row.source_ip)"
                >
                  <span class="block truncate">{{ row.name || row.source_ip }}</span
                  ><span
                    v-if="row.name"
                    class="block truncate text-[11px] opacity-50 md:text-xs"
                    >{{ row.source_ip }}</span
                  >
                </button>
              </td>
              <td class="text-right tabular-nums">{{ bytes(row.download) }}</td>
              <td class="text-right tabular-nums">{{ bytes(row.upload) }}</td>
              <td class="text-right tabular-nums">{{ bytes(row.upload + row.download) }}</td>
            </tr>
            <tr v-if="!rows.length">
              <td
                colspan="4"
                class="py-8 text-center opacity-50"
              >
                {{ busy ? '加载中…' : '暂无记录' }}
              </td>
            </tr>
          </tbody>
          <tfoot v-if="rows.length">
            <tr>
              <td>{{ search ? '筛选合计' : '合计' }}</td>
              <td class="text-right tabular-nums">{{ bytes(totals.download) }}</td>
              <td class="text-right tabular-nums">{{ bytes(totals.upload) }}</td>
              <td class="text-right tabular-nums">{{ bytes(totals.upload + totals.download) }}</td>
            </tr>
          </tfoot>
        </table>
      </div>
      <p class="text-xs opacity-50">按 IP 汇总 · 名称为当前绑定 · 北京时间自然月 · 历史按月保留</p>
    </div>
  </DialogWrapper>
</template>
<script setup lang="ts">
import * as ipaddr from 'ipaddr.js'
import { prettyBytesHelper } from '@/helper/utils'
import { activeBackend } from '@/store/setup'
import {
  deviceUsageOpen,
  openDeviceEditor,
  shanghaiMonth,
  statsRequest,
  verifyStatsSource,
  statsDevices,
} from '@/store/traffic-stats'
import { computed, ref, watch } from 'vue'
import { useIntervalFn } from '@vueuse/core'
import DialogWrapper from './DialogWrapper.vue'
type Usage = {
  month: string
  rows: { source_ip: string; name: string; upload: number; download: number }[]
}
const month = ref(shanghaiMonth())
const search = ref('')
const usage = ref<Usage | null>(null)
const busy = ref(false)
const error = ref('')
let generation = 0
async function load() {
  const current = ++generation
  busy.value = true
  error.value = ''
  try {
    await verifyStatsSource()
    const result = await statsRequest<Usage>(
      `device-usage?month=${encodeURIComponent(month.value)}`,
    )
    if (current === generation) usage.value = result
  } catch (e) {
    if (current === generation) error.value = e instanceof Error ? e.message : '加载失败'
  } finally {
    if (current === generation) busy.value = false
  }
}
watch(deviceUsageOpen, (open) => {
  generation++
  if (open) {
    month.value = shanghaiMonth()
    search.value = ''
    usage.value = null
    void load()
  }
})
watch(month, () => {
  if (deviceUsageOpen.value) {
    usage.value = null
    void load()
  }
})
watch(statsDevices, () => {
  if (deviceUsageOpen.value) void load()
})
watch(
  () => activeBackend.value?.uuid,
  () => {
    generation++
    deviceUsageOpen.value = false
    usage.value = null
  },
)
useIntervalFn(() => {
  if (deviceUsageOpen.value && document.visibilityState === 'visible' && !busy.value) void load()
}, 10000)
const rows = computed(() =>
  (usage.value?.rows ?? []).filter((r) =>
    `${r.name} ${r.source_ip}`.toLowerCase().includes(search.value.trim().toLowerCase()),
  ),
)
const totals = computed(() =>
  rows.value.reduce(
    (sum, r) => ({ upload: sum.upload + r.upload, download: sum.download + r.download }),
    { upload: 0, download: 0 },
  ),
)
const bytes = (value: number) => prettyBytesHelper(value, { binary: true })
</script>

<style scoped>
@media (width < 48rem) {
  th,
  td {
    padding-inline: 4px;
  }
}
</style>
