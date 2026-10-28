import { useStorage } from '@/composables/use-storage'
import { activeBackend } from '@/store/setup'
import * as ipaddr from 'ipaddr.js'
import { computed, ref, watch } from 'vue'

export type StatsConfig = { url: string; sourceId: string }
export type Device = { id: string; name: string; ips: string[] }
export type NodeMapping = { node: string; entry_vps: string; exit_vps: string }
export type StatsStatus = {
  source_id: string
  auth_required?: boolean
  controller_label: string
  healthy: boolean
  last_sample: number | null
  last_error_at: number | null
  interval: number
  retention_days: number
}
export type StatsSummary = {
  rows: {
    key: string
    label: string
    upload: number
    download: number
    source_ip?: string
    current_name?: string
  }[]
  total: { upload: number; download: number }
  series: { at: number; upload: number; download: number }[]
  coverage: {
    upload: number
    download: number
    observed_upload: number
    observed_download: number
    samples: number
  }
  events: { kind: string; count: number }[]
  start: number
  end: number
  truncated: boolean
}

const configs = useStorage<Record<string, StatsConfig>>('stats/service-configs', {})
export const statsConfig = computed(() => configs.value[activeBackend.value?.uuid ?? ''])
const rememberedTokens = useStorage<Record<string, string>>('stats/remembered-tokens', {})
export const remembersStatsToken = computed(
  () => !!rememberedTokens.value[activeBackend.value?.uuid ?? ''],
)
export const statsToken = ref('')
export const statsAutoMode = ref(false)
let autoConnection: { id: string; promise: Promise<void> } | null = null
export const statsDevices = ref<Device[]>([])
const canonicalIP = (address: string) => {
  try {
    return ipaddr.process(address.split('%')[0]!).toString()
  } catch {
    return address
  }
}
export const statsDeviceLabels = computed(
  () =>
    new Map(
      statsDevices.value.flatMap((d) =>
        d.ips.map((address) => [canonicalIP(address), d.name] as const),
      ),
    ),
)
export const getStatsDeviceByIP = (address: string) =>
  statsDevices.value.find((device) =>
    device.ips.some((ip) => canonicalIP(ip) === canonicalIP(address)),
  )
export const getStatsDeviceLabel = (address: string) =>
  statsDeviceLabels.value.get(canonicalIP(address))

export function saveStatsConfig(config: StatsConfig, token: string) {
  const id = activeBackend.value?.uuid
  if (!id) throw new Error('请先选择 Nikki 后端')
  const url = config.url.trim().replace(/\/$/, '')
  if (url && !/^https?:\/\//.test(url)) throw new Error('服务地址必须使用 http:// 或 https://')
  if (!config.sourceId.trim()) throw new Error('请输入采集源 ID')
  configs.value = { ...configs.value, [id]: { url, sourceId: config.sourceId.trim() } }
  statsToken.value = token.trim()
  if (rememberedTokens.value[id])
    rememberedTokens.value = { ...rememberedTokens.value, [id]: statsToken.value }
  sessionStorage.setItem(`stats/token/${id}`, statsToken.value)
}

export async function ensureAutoStats() {
  const id = activeBackend.value?.uuid
  if (!id) return
  if (statsConfig.value?.sourceId && statsAutoMode.value) return
  if (autoConnection?.id === id) return autoConnection.promise
  const url = statsConfig.value?.url ?? ''
  const promise = (async () => {
    const response = await fetch(`${url}/api/stats/status`, {
      headers: statsToken.value ? { Authorization: `Bearer ${statsToken.value}` } : {},
      signal: AbortSignal.timeout(10000),
      cache: 'no-store',
      credentials: 'omit',
    })
    if (!response.ok) throw new Error('统计服务暂不可用')
    const status = (await response.json()) as StatsStatus
    if (activeBackend.value?.uuid !== id) throw new Error('后端已切换')
    if (status.auth_required !== false) return
    if (typeof status.source_id !== 'string' || !status.source_id)
      throw new Error('统计服务身份无效')
    statsAutoMode.value = true
    if (!statsConfig.value?.sourceId)
      configs.value = { ...configs.value, [id]: { url, sourceId: status.source_id } }
  })()
  autoConnection = { id, promise }
  try {
    await promise
  } finally {
    if (autoConnection?.promise === promise) autoConnection = null
  }
}

export async function statsRequest<T>(path: string, body?: unknown): Promise<T> {
  if (!statsConfig.value?.sourceId || (!statsToken.value && !statsAutoMode.value))
    await ensureAutoStats()
  const config = statsConfig.value
  const token = statsToken.value
  const backendId = activeBackend.value?.uuid
  if (!config?.sourceId || (!token && !statsAutoMode.value)) throw new Error('统计服务暂不可用')
  const response = await fetch(`${config.url}/api/stats/${path}`, {
    method: body === undefined ? 'GET' : 'PUT',
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(10000),
    cache: 'no-store',
    credentials: 'omit',
  })
  const data = await response.json().catch(() => {
    throw new Error('统计服务未返回 JSON，请检查服务地址')
  })
  if (
    backendId !== activeBackend.value?.uuid ||
    config !== statsConfig.value ||
    token !== statsToken.value
  )
    throw new Error('后端或统计配置已切换，请重新加载')
  if (!response.ok) throw new Error(data.error || `统计服务请求失败 (${response.status})`)
  return data as T
}

export async function verifyStatsSource() {
  const status = await statsRequest<StatsStatus>('status')
  if (status.source_id !== statsConfig.value?.sourceId)
    throw new Error('采集源 ID 不一致，已停止加载，避免混入其他 Nikki 的数据')
  return status
}

let labelGeneration = 0
export async function refreshStatsLabels() {
  const generation = ++labelGeneration
  const id = activeBackend.value?.uuid
  try {
    await verifyStatsSource()
    const devices = await statsRequest<Device[]>('devices')
    if (generation === labelGeneration && id === activeBackend.value?.uuid)
      statsDevices.value = devices
  } catch {
    if (generation === labelGeneration) statsDevices.value = []
  }
}

watch(
  () => activeBackend.value?.uuid,
  (id) => {
    statsDevices.value = []
    statsAutoMode.value = false
    autoConnection = null
    statsToken.value = id
      ? (sessionStorage.getItem(`stats/token/${id}`) ?? rememberedTokens.value[id] ?? '')
      : ''
    void refreshStatsLabels()
  },
  { immediate: true },
)

export const shanghaiMonth = () =>
  new Intl.DateTimeFormat('sv-SE', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
  }).format(new Date())
export type GroupTotals = {
  month?: string
  since: number | null
  last_sample: number | null
  healthy: boolean
  rows: { name: string; upload: number; download: number }[]
}
export const groupTotals = ref<GroupTotals | null>(null)
export const groupTotalsError = ref('')
export const deviceUsageOpen = ref(false)
export const statsSettingsOpen = ref(false)
export const deviceEditorIP = ref<string | null>(null)
export const trafficDetailsGroup = ref<string | null>(null)
export const groupTotalsMap = computed(
  () => new Map(groupTotals.value?.rows.map((row) => [row.name, row]) ?? []),
)

let groupGeneration = 0
let groupPending: number | null = null
export async function refreshGroupTotals() {
  if (groupPending !== null) return
  const generation = ++groupGeneration
  groupPending = generation
  try {
    await verifyStatsSource()
    const totals = await statsRequest<GroupTotals>('group-totals')
    if (generation !== groupGeneration) return
    groupTotals.value = totals
    groupTotalsError.value = ''
  } catch (e) {
    if (generation !== groupGeneration) return
    groupTotalsError.value = e instanceof Error ? e.message : '累计统计暂不可用'
  } finally {
    if (groupPending === generation) groupPending = null
  }
}
export function openDeviceEditor(address: string) {
  deviceEditorIP.value = address
}
export async function connectIntegratedStats(url: string, token: string, remember: boolean) {
  const normalized = url.trim().replace(/\/$/, '')
  if (normalized && !/^https?:\/\//.test(normalized))
    throw new Error('服务地址必须使用 http:// 或 https://')
  const id = activeBackend.value?.uuid
  if (!id) throw new Error('请先选择 Nikki 后端')
  const response = await fetch(`${normalized}/api/stats/status`, {
    headers: { Authorization: `Bearer ${token.trim()}` },
    signal: AbortSignal.timeout(10000),
    credentials: 'omit',
    cache: 'no-store',
  })
  const status = await response.json()
  if (!response.ok) throw new Error(status.error || '统计服务连接失败')
  if (id !== activeBackend.value?.uuid) throw new Error('后端已切换，请重试')
  if (typeof status.source_id !== 'string' || !status.source_id) throw new Error('统计服务身份无效')
  saveStatsConfig({ url: normalized, sourceId: status.source_id }, token)
  if (remember) rememberedTokens.value = { ...rememberedTokens.value, [id]: token.trim() }
  else {
    const next = { ...rememberedTokens.value }
    delete next[id]
    rememberedTokens.value = next
  }
  await Promise.all([refreshGroupTotals(), refreshStatsLabels()])
}
watch([() => activeBackend.value?.uuid, statsConfig, statsToken], () => {
  groupGeneration++
  groupPending = null
  groupTotals.value = null
  groupTotalsError.value = ''
  void refreshGroupTotals()
})
