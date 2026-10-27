<template>
  <DeviceUsageDialog />
  <DialogWrapper
    v-model="statsSettingsOpen"
    title="累计统计连接"
  >
    <form
      class="stats-integration-content flex flex-col gap-4 text-sm"
      @submit.prevent="connect"
    >
      <p class="opacity-60">
        连接一次后，累计流量直接显示在代理卡片中，设备名称在连接列表中同步显示。
      </p>
      <label class="flex flex-col gap-1"
        >访问令牌<input
          v-model="token"
          class="input w-full"
          type="password"
          autocomplete="off"
          required
      /></label>
      <label class="flex items-center gap-2"
        ><input
          v-model="remember"
          class="checkbox checkbox-sm"
          type="checkbox"
        />在此浏览器记住（仅限可信设备）</label
      >
      <details>
        <summary class="cursor-pointer opacity-60">高级连接设置</summary>
        <label class="mt-3 flex flex-col gap-1"
          >统计服务地址<input
            v-model="url"
            class="input w-full"
            placeholder="留空使用当前站点"
        /></label>
      </details>
      <p
        v-if="error"
        class="text-error"
        role="alert"
      >
        {{ error }}
      </p>
      <button
        class="btn btn-primary btn-sm self-end"
        :disabled="busy"
      >
        {{ busy ? '连接中…' : '连接' }}
      </button>
    </form>
  </DialogWrapper>
  <DialogWrapper
    v-model="deviceOpen"
    title="设备绑定"
  >
    <form
      class="stats-integration-content flex flex-col gap-4 text-sm"
      @submit.prevent="saveDevice"
    >
      <p class="break-all opacity-60">来源 IP：{{ deviceEditorIP }}</p>
      <label class="flex flex-col gap-1"
        >主机名<input
          v-model="deviceName"
          class="input w-full"
          required
          maxlength="100"
          placeholder="例如：工作电脑"
      /></label>
      <label class="flex flex-col gap-1"
        >关联 IP（每行一个）<textarea
          v-model="deviceIPs"
          class="textarea w-full"
          rows="4"
        />
      </label>
      <p class="text-xs opacity-60">
        多个 IPv4 / IPv6 地址可以归入同一设备。绑定从保存后生效，历史流量归属保持不变。
      </p>
      <p
        v-if="deviceError"
        class="text-error"
        role="alert"
      >
        {{ deviceError }}
      </p>
      <button
        class="btn btn-primary btn-sm self-end"
        :disabled="deviceBusy"
      >
        {{ deviceBusy ? '保存中…' : '保存绑定' }}
      </button>
    </form>
  </DialogWrapper>
  <DialogWrapper
    v-model="groupOpen"
    :title="`${trafficDetailsGroup ?? ''} · 流量`"
  >
    <div class="stats-integration-content flex flex-col gap-4 text-sm">
      <label class="flex items-center gap-3 opacity-70"
        >月份
        <input
          v-model="detailMonth"
          type="month"
          class="input input-sm"
          aria-label="流量月份"
        />
      </label>
      <p
        v-if="detailError"
        class="text-error"
        role="alert"
      >
        {{ detailError }}
      </p>
      <div class="grid grid-cols-3 gap-3">
        <div
          v-for="item in detailCards"
          :key="item.label"
          class="bg-base-200 rounded-lg p-3"
        >
          <div class="opacity-60">{{ item.label }}</div>
          <div class="mt-2 font-semibold tabular-nums">
            {{ detailTotals ? bytes(item.value) : '—' }}
          </div>
        </div>
      </div>
      <p class="opacity-60">统计起点：{{ since }}</p>
      <p class="text-xs opacity-60">
        每月 1
        日按北京时间重新计数，历史按月保留。切换节点不会清零。按连接实际经过的代理组统计。同一条连接可能经过多个嵌套组，因此各组不能直接相加为全局用量。此处为连接采样统计。
      </p>
      <p
        v-if="groupTotalsError || !groupTotals?.healthy"
        class="text-warning"
      >
        统计暂未更新，当前为上次获取的数据。
      </p>
      <button
        class="btn btn-sm self-end"
        @click="loadDetail"
      >
        刷新
      </button>
    </div>
  </DialogWrapper>
</template>
<script setup lang="ts">
import DeviceUsageDialog from './DeviceUsageDialog.vue'
import DialogWrapper from '@/components/common/DialogWrapper.vue'
import { prettyBytesHelper } from '@/helper/utils'
import { activeBackend } from '@/store/setup'
import {
  connectIntegratedStats,
  shanghaiMonth,
  type GroupTotals,
  deviceEditorIP,
  getStatsDeviceLabel,
  getStatsDeviceByIP,
  groupTotals,
  groupTotalsError,
  refreshGroupTotals,
  refreshStatsLabels,
  remembersStatsToken,
  statsConfig,
  statsRequest,
  statsSettingsOpen,
  statsToken,
  trafficDetailsGroup,
  verifyStatsSource,
} from '@/store/traffic-stats'
import { computed, ref, watch } from 'vue'
const token = ref('')
const url = ref('')
const remember = ref(false)
const error = ref('')
const busy = ref(false)
watch(statsSettingsOpen, (open) => {
  if (open) {
    remember.value = remembersStatsToken.value
    token.value = statsToken.value
    url.value = statsConfig.value?.url ?? ''
    error.value = ''
  }
})
async function connect() {
  busy.value = true
  error.value = ''
  try {
    await connectIntegratedStats(url.value, token.value, remember.value)
    statsSettingsOpen.value = false
  } catch (e) {
    error.value = e instanceof Error ? e.message : '连接失败'
  } finally {
    busy.value = false
  }
}
const deviceOpen = computed({
  get: () => deviceEditorIP.value !== null,
  set: (open) => {
    if (!open) deviceEditorIP.value = null
  },
})
const deviceName = ref('')
const deviceIPs = ref('')
const deviceId = ref('')
const deviceError = ref('')
const deviceBusy = ref(false)
watch(deviceEditorIP, (address) => {
  if (address === null) return
  const label = getStatsDeviceLabel(address)
  const device = getStatsDeviceByIP(address)
  deviceId.value = device?.id ?? ''
  deviceName.value = device?.name ?? label ?? ''
  deviceIPs.value = device?.ips.join('\n') ?? address
  deviceError.value = ''
})
async function saveDevice() {
  if (deviceBusy.value) return
  const backendId = activeBackend.value?.uuid
  deviceBusy.value = true
  deviceError.value = ''
  try {
    await verifyStatsSource()
    if (backendId !== activeBackend.value?.uuid) throw new Error('后端已切换，请重试')
    await statsRequest('devices', {
      id: deviceId.value,
      name: deviceName.value,
      ips: deviceIPs.value.split(/[\s,，]+/).filter(Boolean),
    })
    await refreshStatsLabels()
    deviceEditorIP.value = null
  } catch (e) {
    deviceError.value = e instanceof Error ? e.message : '保存失败'
  } finally {
    deviceBusy.value = false
  }
}
const groupOpen = computed({
  get: () => trafficDetailsGroup.value !== null,
  set: (open) => {
    if (!open) trafficDetailsGroup.value = null
  },
})
const detailMonth = ref(shanghaiMonth())
const detailTotals = ref<GroupTotals | null>(null)
const detailError = ref('')
let detailGeneration = 0
async function loadDetail() {
  const generation = ++detailGeneration
  detailTotals.value = null
  detailError.value = ''
  try {
    await verifyStatsSource()
    const value = await statsRequest<GroupTotals>(
      `group-totals?month=${encodeURIComponent(detailMonth.value)}`,
    )
    if (generation === detailGeneration) detailTotals.value = value
    if (detailMonth.value === shanghaiMonth()) void refreshGroupTotals()
  } catch (e) {
    if (generation === detailGeneration)
      detailError.value = e instanceof Error ? e.message : '加载失败'
  }
}
watch(trafficDetailsGroup, (group) => {
  detailGeneration++
  if (group !== null) {
    detailMonth.value = shanghaiMonth()
    void loadDetail()
  }
})
watch(detailMonth, () => {
  if (groupOpen.value) void loadDetail()
})
const total = computed(
  () =>
    detailTotals.value?.rows.find((r) => r.name === trafficDetailsGroup.value) ?? {
      upload: 0,
      download: 0,
    },
)
const detailCards = computed(() => [
  { label: '合计', value: total.value.upload + total.value.download },
  { label: '下载', value: total.value.download },
  { label: '上传', value: total.value.upload },
])
const since = computed(() =>
  detailTotals.value?.since
    ? new Date(detailTotals.value.since * 1000).toLocaleString('zh-CN', {
        timeZone: 'Asia/Shanghai',
      })
    : '尚未开始',
)
const bytes = (n: number) => prettyBytesHelper(n, { binary: true })
watch(
  () => activeBackend.value?.uuid,
  () => {
    statsSettingsOpen.value = false
    deviceEditorIP.value = null
    trafficDetailsGroup.value = null
  },
)
</script>

<style>
/* These contextual dialogs may open above an existing connection detail dialog. */
.modal:has(.stats-integration-content) {
  z-index: 1100;
}
</style>
