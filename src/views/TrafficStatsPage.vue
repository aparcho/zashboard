<template>
  <div
    class="h-full overflow-y-auto"
    :style="padding"
  >
    <div class="mx-auto flex max-w-7xl flex-col gap-4 p-3 md:p-6">
      <header class="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 class="text-2xl font-semibold">流量统计</h1>
          <p class="mt-1 text-sm opacity-60">
            设备、策略与 VPS 的使用情况 · 关闭页面后继续统计 · Asia/Shanghai
          </p>
        </div>
        <button
          class="btn btn-sm"
          :disabled="busy"
          @click="reload"
        >
          {{ busy ? '加载中…' : '刷新' }}
        </button>
      </header>

      <details
        v-if="!statsAutoMode"
        class="base-container p-4"
        :open="!status"
      >
        <summary class="cursor-pointer font-medium">统计服务连接</summary>
        <form
          class="mt-4 grid gap-3 md:grid-cols-3"
          @submit.prevent="connect"
        >
          <label class="flex flex-col gap-1 text-sm"
            >服务地址
            <input
              v-model="serviceUrl"
              class="input w-full"
              placeholder="留空使用当前站点"
            />
          </label>
          <label class="flex flex-col gap-1 text-sm"
            >采集源 ID
            <input
              v-model="sourceId"
              class="input w-full"
              required
              placeholder="nikki-home"
            />
          </label>
          <label class="flex flex-col gap-1 text-sm"
            >访问令牌（当前标签页会话）
            <input
              v-model="token"
              class="input w-full"
              type="password"
              autocomplete="off"
              required
            />
          </label>
          <p class="text-xs opacity-60 md:col-span-3">
            每个 Nikki 后端分别绑定服务与采集源 ID。令牌仅保存在当前标签页会话中。
          </p>
          <button
            class="btn btn-primary btn-sm justify-self-start"
            :disabled="busy"
          >
            连接并加载
          </button>
        </form>
      </details>

      <p
        v-if="error"
        role="alert"
        class="alert alert-error text-sm"
      >
        {{ error }}
      </p>
      <template v-if="status">
        <div
          class="base-container flex flex-wrap items-center gap-3 p-4 text-sm"
          role="status"
        >
          <span
            class="badge"
            :class="status.healthy ? 'badge-success' : 'badge-warning'"
            >{{ status.healthy ? '采集中' : '采集异常' }}</span
          >
          <span>{{ status.controller_label || status.source_id }}</span>
          <span class="opacity-60"
            >最后采样：{{ date(status.last_sample) }} · {{ status.interval }} 秒间隔 · 保留
            {{ status.retention_days }} 天</span
          >
        </div>
        <div
          role="tablist"
          class="tabs tabs-box self-start"
        >
          <button
            v-for="item in tabs"
            :key="item.key"
            role="tab"
            class="tab"
            :class="{ 'tab-active': tab === item.key }"
            :aria-selected="tab === item.key"
            @click="tab = item.key"
          >
            {{ item.label }}
          </button>
        </div>

        <template v-if="tab === 'stats'">
          <form
            class="base-container grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-4"
            @submit.prevent="reload"
          >
            <label class="flex flex-col gap-1 text-sm"
              >时间范围
              <select
                v-model="period"
                class="select w-full"
                @change="reload"
              >
                <option value="today">今日</option>
                <option value="yesterday">昨日</option>
                <option value="week">最近七天</option>
                <option value="month">本月</option>
              </select>
            </label>
            <label class="flex flex-col gap-1 text-sm"
              >统计维度
              <select
                v-model="dimension"
                class="select w-full"
                @change="reload"
              >
                <option
                  v-for="d in dimensions"
                  :key="d.key"
                  :value="d.key"
                >
                  {{ d.label }}
                </option>
              </select>
            </label>
            <label class="flex flex-col gap-1 text-sm"
              >设备
              <select
                v-model="deviceFilter"
                class="select w-full"
                @change="reload"
              >
                <option value="">全部设备</option>
                <option
                  v-for="d in devices"
                  :key="d.id"
                  :value="d.id"
                >
                  {{ d.name }}
                </option>
              </select>
            </label>
            <label class="flex flex-col gap-1 text-sm"
              >分流策略（完整名称）
              <input
                v-model="policyFilter"
                class="input w-full"
                placeholder="全部策略"
              />
            </label>
            <label class="flex flex-col gap-1 text-sm"
              >入口 VPS（完整名称）<input
                v-model="entryFilter"
                class="input w-full"
                placeholder="全部入口"
            /></label>
            <label class="flex flex-col gap-1 text-sm"
              >落地 VPS（完整名称）<input
                v-model="exitFilter"
                class="input w-full"
                placeholder="全部落地"
            /></label>
            <label class="flex flex-col gap-1 text-sm"
              >来源 IP<input
                v-model="ipFilter"
                class="input w-full"
                placeholder="全部地址"
            /></label>
            <div class="flex items-end gap-2">
              <button
                class="btn btn-primary"
                :disabled="busy"
              >
                查询</button
              ><button
                type="button"
                class="btn"
                @click="clearFilters"
              >
                清除筛选
              </button>
            </div>
          </form>
          <template v-if="summary">
            <div class="grid gap-3 sm:grid-cols-3">
              <div
                v-for="card in totalCards"
                :key="card.label"
                class="base-container p-5"
              >
                <div class="text-sm opacity-60">{{ card.label }}</div>
                <div class="mt-2 text-2xl font-semibold tabular-nums">{{ bytes(card.value) }}</div>
              </div>
            </div>
            <div class="base-container p-4">
              <h2 class="font-medium">
                流量趋势 <span class="text-xs font-normal opacity-60">每小时汇总 · 可横向滚动</span>
              </h2>
              <p
                v-if="!summary.series.length"
                class="py-8 text-center text-sm opacity-60"
              >
                该时段暂无已归属流量
              </p>
              <div
                v-else
                class="mt-4 overflow-x-auto"
              >
                <div
                  class="flex h-40 items-end gap-2"
                  :style="{ minWidth: `${Math.max(summary.series.length * 42, 240)}px` }"
                >
                  <div
                    v-for="point in summary.series"
                    :key="point.at"
                    class="flex h-full w-16 shrink-0 flex-col justify-end gap-1"
                    :title="`${date(point.at)} 上传 ${bytes(point.upload)}，下载 ${bytes(point.download)}`"
                  >
                    <span
                      class="bg-primary/70 min-h-0.5 rounded-t"
                      :style="{
                        height: `${((point.upload + point.download) / seriesMax) * 110}px`,
                      }"
                    />
                    <span class="text-center text-[10px] opacity-60">{{ hour(point.at) }}</span>
                  </div>
                </div>
              </div>
            </div>
            <div class="base-container overflow-x-auto p-4">
              <h2 class="mb-3 font-medium">
                {{ dimensions.find((d) => d.key === dimension)?.label }}排行
              </h2>
              <table class="table w-full">
                <thead>
                  <tr>
                    <th>名称</th>
                    <th>上传</th>
                    <th>下载</th>
                    <th>合计</th>
                    <th>占比</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="row in summary.rows"
                    :key="row.key"
                    class="hover:bg-base-200"
                  >
                    <td class="max-w-64 break-all whitespace-normal">
                      {{ row.label
                      }}<span
                        v-if="dimension === 'source_ip' && getStatsDeviceLabel(row.key)"
                        class="mt-1 block text-xs opacity-60"
                        >{{ getStatsDeviceLabel(row.key) }}</span
                      >
                    </td>
                    <td class="whitespace-nowrap tabular-nums">{{ bytes(row.upload) }}</td>
                    <td class="whitespace-nowrap tabular-nums">{{ bytes(row.download) }}</td>
                    <td class="whitespace-nowrap tabular-nums">
                      {{ bytes(row.upload + row.download) }}
                    </td>
                    <td>
                      {{
                        percent(
                          row.upload + row.download,
                          summary.total.upload + summary.total.download,
                        )
                      }}
                    </td>
                  </tr>
                  <tr v-if="!summary.rows.length">
                    <td
                      colspan="5"
                      class="py-10 text-center opacity-60"
                    >
                      暂无数据。首次采样建立基线，后续流量才开始累计。
                    </td>
                  </tr>
                </tbody>
              </table>
              <p
                v-if="summary.truncated"
                class="mt-2 text-xs opacity-60"
              >
                最多显示前 500 项，总计包含全部项目。
              </p>
            </div>
            <div class="base-container space-y-2 p-4 text-xs opacity-70">
              <p>
                连接采样统计，非供应商账单；仅包含经过该 Mihomo 的流量。目标 IP 为内核报告值，可能是
                fake-ip。
              </p>
              <p>
                所选时段内核总增量：↑ {{ bytes(summary.coverage.upload) }} / ↓
                {{ bytes(summary.coverage.download) }}；全部连接归属量：↑
                {{ bytes(summary.coverage.observed_upload) }} / ↓
                {{ bytes(summary.coverage.observed_download) }}。
              </p>
              <p>
                未归属差额：↑
                {{ bytes(Math.max(0, summary.coverage.upload - summary.coverage.observed_upload)) }}
                / ↓
                {{
                  bytes(
                    Math.max(0, summary.coverage.download - summary.coverage.observed_download),
                  )
                }}。差额与采集状态为全局口径，不受上方设备等筛选影响。
              </p>
              <p>
                基线 {{ eventCount('baseline') }} 次 · 重启/计数重置 {{ eventCount('reset') }} 次 ·
                重连/间隔异常 {{ eventCount('gap') }} 次 · 请求失败
                {{ eventCount('fetch_error') }}
                次。断线及基线期间的流量不回填，短连接及关闭前尾部流量可能漏采。
              </p>
            </div>
          </template>
        </template>

        <template v-if="tab === 'devices'">
          <div class="base-container p-4">
            <h2 class="font-medium">{{ deviceId ? '编辑设备' : '添加设备' }}</h2>
            <form
              class="mt-3 grid gap-3 md:grid-cols-2"
              @submit.prevent="saveDevice"
            >
              <label class="flex flex-col gap-1 text-sm"
                >机器名称<input
                  v-model="deviceName"
                  class="input w-full"
                  required
                  maxlength="100"
                  placeholder="例如：MacBook"
              /></label>
              <label class="flex flex-col gap-1 text-sm"
                >IP 地址（每行一个，支持 IPv4 / IPv6）<textarea
                  v-model="deviceIPs"
                  class="textarea w-full"
                  rows="3"
                  placeholder="192.168.50.10"
                />
              </label>
              <p class="text-xs opacity-60 md:col-span-2">
                一个设备可绑定多个地址。绑定与解绑从保存后生效，历史归属不重写；修改机器名称会更新历史显示。清空地址即可解除绑定。
              </p>
              <div class="flex gap-2">
                <button
                  class="btn btn-primary btn-sm"
                  :disabled="busy"
                >
                  保存设备</button
                ><button
                  type="button"
                  class="btn btn-sm"
                  @click="resetDevice"
                >
                  清空表单
                </button>
              </div>
            </form>
          </div>
          <div class="grid gap-3 md:grid-cols-2">
            <button
              v-for="d in devices"
              :key="d.id"
              class="base-container hover:bg-base-300/40 p-4 text-left"
              @click="editDevice(d)"
            >
              <div class="font-medium">{{ d.name }}</div>
              <div class="mt-2 text-sm break-all opacity-60">
                {{ d.ips.join(' · ') || '暂无绑定地址' }}
              </div>
              <div class="text-primary mt-2 text-xs">编辑绑定</div>
            </button>
          </div>
          <p
            v-if="!devices.length"
            class="p-6 text-center opacity-60"
          >
            添加设备后，连接列表和统计将显示机器名称。
          </p>
        </template>

        <template v-if="tab === 'nodes'">
          <div class="base-container p-4">
            <h2 class="font-medium">节点与 VPS 对应关系</h2>
            <form
              class="mt-3 grid gap-3 md:grid-cols-3"
              @submit.prevent="saveNode"
            >
              <label class="flex flex-col gap-1 text-sm"
                >节点完整名称<input
                  v-model="nodeName"
                  class="input w-full"
                  required
                  placeholder="与连接中的最终节点名称一致"
              /></label>
              <label class="flex flex-col gap-1 text-sm"
                >入口 VPS<input
                  v-model="entryVps"
                  class="input w-full"
                  placeholder="例如：HK2"
              /></label>
              <label class="flex flex-col gap-1 text-sm"
                >落地 VPS<input
                  v-model="exitVps"
                  class="input w-full"
                  placeholder="例如：HKG"
              /></label>
              <p class="text-xs opacity-60 md:col-span-3">
                直连节点入口与落地填写同一
                VPS。中转节点分别填写；不根据名称自动猜测。修改从保存后生效，历史统计保留原归属。DIRECT
                等内置出口无需映射。
              </p>
              <button
                class="btn btn-primary btn-sm justify-self-start"
                :disabled="busy"
              >
                保存映射
              </button>
            </form>
          </div>
          <div class="base-container overflow-x-auto p-4">
            <table class="table w-full">
              <thead>
                <tr>
                  <th>节点</th>
                  <th>入口 VPS</th>
                  <th>落地 VPS</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="n in nodes"
                  :key="n.node"
                >
                  <td class="break-all">{{ n.node }}</td>
                  <td>{{ n.entry_vps }}</td>
                  <td>{{ n.exit_vps }}</td>
                  <td>
                    <button
                      class="btn btn-ghost btn-xs"
                      @click="editNode(n)"
                    >
                      编辑
                    </button>
                  </td>
                </tr>
                <tr v-if="!nodes.length">
                  <td
                    colspan="4"
                    class="py-8 text-center opacity-60"
                  >
                    暂无映射。可先在节点排行中查看实际节点名称。
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </template>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { usePaddingForViews } from '@/composables/use-padding-for-views'
import { activeBackend } from '@/store/setup'
import {
  getStatsDeviceLabel,
  refreshStatsLabels,
  saveStatsConfig,
  statsConfig,
  statsRequest,
  statsToken,
  statsAutoMode,
  ensureAutoStats,
  verifyStatsSource,
  type Device,
  type NodeMapping,
  type StatsStatus,
  type StatsSummary,
} from '@/store/traffic-stats'
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'

const { padding } = usePaddingForViews()
const serviceUrl = ref(statsConfig.value?.url ?? '')
const sourceId = ref(statsConfig.value?.sourceId ?? '')
const token = ref(statsToken.value)
const busy = ref(false)
const error = ref('')
const status = ref<StatsStatus | null>(null)
const summary = ref<StatsSummary | null>(null)
const devices = ref<Device[]>([])
const nodes = ref<NodeMapping[]>([])
const tabs = [
  { key: 'stats', label: '统计概览' },
  { key: 'devices', label: '设备绑定' },
  { key: 'nodes', label: 'VPS 映射' },
]
const tab = ref('stats')
const dimensions = [
  { key: 'device', label: '设备' },
  { key: 'policy', label: '分流策略' },
  { key: 'node', label: '代理节点' },
  { key: 'entry_vps', label: '入口 VPS' },
  { key: 'exit_vps', label: '落地 VPS' },
  { key: 'source_ip', label: '来源 IP' },
  { key: 'host', label: '目标域名' },
  { key: 'target_ip', label: '目标 IP' },
]
const dimension = ref('device')
const period = ref('today')
const deviceFilter = ref('')
const policyFilter = ref('')
const entryFilter = ref('')
const exitFilter = ref('')
const ipFilter = ref('')
const deviceId = ref('')
const deviceName = ref('')
const deviceIPs = ref('')
const nodeName = ref('')
const entryVps = ref('')
const exitVps = ref('')
const totalCards = computed(() => [
  { label: '已归属上传', value: summary.value?.total.upload ?? 0 },
  { label: '已归属下载', value: summary.value?.total.download ?? 0 },
  {
    label: '已归属合计',
    value: (summary.value?.total.upload ?? 0) + (summary.value?.total.download ?? 0),
  },
])
const seriesMax = computed(() =>
  Math.max(1, ...(summary.value?.series.map((p) => p.upload + p.download) ?? [])),
)
const bytes = (n: number) => {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  const exponent = n > 0 ? Math.min(4, Math.floor(Math.log(n) / Math.log(1024))) : 0
  return `${(n / 1024 ** exponent).toFixed(exponent ? 2 : 0)} ${units[exponent]}`
}
const date = (at: number | null) =>
  at
    ? new Date(at * 1000).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false })
    : '尚未采样'
const hour = (at: number) =>
  new Date(at * 1000).toLocaleString('zh-CN', {
    timeZone: 'Asia/Shanghai',
    month: 'numeric',
    day: 'numeric',
    hour: '2-digit',
    hour12: false,
  })
const percent = (n: number, total: number) => `${total ? ((n / total) * 100).toFixed(1) : '0'}%`
const eventCount = (kind: string) => summary.value?.events.find((e) => e.kind === kind)?.count ?? 0
function range() {
  const now = Date.now() / 1000
  const cn = new Date((now + 8 * 3600) * 1000)
  const midnight =
    Date.UTC(cn.getUTCFullYear(), cn.getUTCMonth(), cn.getUTCDate()) / 1000 - 8 * 3600
  const month = Date.UTC(cn.getUTCFullYear(), cn.getUTCMonth(), 1) / 1000 - 8 * 3600
  return {
    start:
      period.value === 'month'
        ? month
        : period.value === 'week'
          ? midnight - 6 * 86400
          : period.value === 'yesterday'
            ? midnight - 86400
            : midnight,
    end: period.value === 'yesterday' ? midnight : Math.ceil(now),
  }
}
let generation = 0
async function reload() {
  if (busy.value) return
  const current = ++generation
  busy.value = true
  error.value = ''
  try {
    const nextStatus = await verifyStatsSource()
    const { start, end } = range()
    const query = new URLSearchParams({
      dimension: dimension.value,
      start: String(start),
      end: String(end),
      device: deviceFilter.value,
      policy: policyFilter.value.trim(),
      entry_vps: entryFilter.value.trim(),
      exit_vps: exitFilter.value.trim(),
      source_ip: ipFilter.value.trim(),
    })
    const [nextSummary, nextDevices, nextNodes] = await Promise.all([
      statsRequest<StatsSummary>(`summary?${query}`),
      statsRequest<Device[]>('devices'),
      statsRequest<NodeMapping[]>('nodes'),
    ])
    if (current !== generation) return
    status.value = nextStatus
    summary.value = nextSummary
    devices.value = nextDevices
    nodes.value = nextNodes
    await refreshStatsLabels()
  } catch (e) {
    if (current !== generation) return
    error.value = e instanceof Error ? e.message : '统计服务连接失败'
    status.value = null
    summary.value = null
  } finally {
    if (current === generation) busy.value = false
  }
}
async function connect() {
  try {
    saveStatsConfig({ url: serviceUrl.value, sourceId: sourceId.value }, token.value)
    await reload()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '配置无效'
  }
}
function clearFilters() {
  deviceFilter.value =
    policyFilter.value =
    entryFilter.value =
    exitFilter.value =
    ipFilter.value =
      ''
  void reload()
}
function resetDevice() {
  deviceId.value = deviceName.value = deviceIPs.value = ''
}
function editDevice(d: Device) {
  deviceId.value = d.id
  deviceName.value = d.name
  deviceIPs.value = d.ips.join('\n')
}
async function mutate(path: string, data: unknown) {
  if (busy.value) return
  busy.value = true
  error.value = ''
  try {
    await verifyStatsSource()
    await statsRequest(path, data)
    busy.value = false
    await reload()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '保存失败'
  } finally {
    busy.value = false
  }
}
async function saveDevice() {
  await mutate('devices', {
    id: deviceId.value,
    name: deviceName.value,
    ips: deviceIPs.value.split(/[\s,，]+/).filter(Boolean),
  })
  if (!error.value) resetDevice()
}
function editNode(n: NodeMapping) {
  nodeName.value = n.node
  entryVps.value = n.entry_vps
  exitVps.value = n.exit_vps
}
async function saveNode() {
  await mutate('nodes', {
    node: nodeName.value,
    entry_vps: entryVps.value,
    exit_vps: exitVps.value,
  })
}
watch(
  () => activeBackend.value?.uuid,
  () => {
    generation++
    busy.value = false
    status.value = summary.value = null
    devices.value = []
    nodes.value = []
    resetDevice()
    clearFilters()
    nodeName.value = entryVps.value = exitVps.value = ''
    serviceUrl.value = statsConfig.value?.url ?? ''
    sourceId.value = statsConfig.value?.sourceId ?? ''
    token.value = statsToken.value
  },
)
let timer: ReturnType<typeof setInterval>
onMounted(() => {
  void ensureAutoStats()
    .then(() => reload())
    .catch(() => reload())
  timer = setInterval(() => {
    if (document.visibilityState === 'visible' && status.value && tab.value === 'stats')
      void reload()
  }, 15000)
})
onUnmounted(() => {
  generation++
  clearInterval(timer)
})
</script>
