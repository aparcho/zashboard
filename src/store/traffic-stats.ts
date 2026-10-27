import { useStorage } from '@/composables/use-storage'
import { activeBackend } from '@/store/setup'
import * as ipaddr from 'ipaddr.js'
import { computed, ref, watch } from 'vue'

export type StatsConfig = { url: string; sourceId: string }
export type Device = { id: string; name: string; ips: string[] }
export type NodeMapping = { node: string; entry_vps: string; exit_vps: string }
export type StatsStatus = {
  source_id: string
  controller_label: string
  healthy: boolean
  last_sample: number | null
  last_error_at: number | null
  interval: number
  retention_days: number
}
export type StatsSummary = {
  rows: { key: string; label: string; upload: number; download: number }[]
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
export const statsToken = ref('')
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
  sessionStorage.setItem(`stats/token/${id}`, statsToken.value)
}

export async function statsRequest<T>(path: string, body?: unknown): Promise<T> {
  const config = statsConfig.value
  const token = statsToken.value
  const backendId = activeBackend.value?.uuid
  if (!config?.sourceId || !token) throw new Error('请先配置统计服务并输入访问令牌')
  const response = await fetch(`${config.url}/api/stats/${path}`, {
    method: body === undefined ? 'GET' : 'PUT',
    headers: {
      Authorization: `Bearer ${token}`,
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
    statsToken.value = id ? (sessionStorage.getItem(`stats/token/${id}`) ?? '') : ''
    void refreshStatsLabels()
  },
  { immediate: true },
)
