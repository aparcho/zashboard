import { configs } from '@/assembly/config'
import {
  getLatencyByName,
  getProxyGroupChains,
  proxyGroupList,
  proxyMap,
  proxyProviederList,
} from '@/assembly/proxies'
import { GLOBAL, NOT_CONNECTED, PROXY_GROUP_SORT_TYPE, PROXY_TAB_TYPE } from '@/constant'
import { isHiddenGroup } from '@/helper'
import { proxiesTabShow } from '@/store/proxies'
import { groupsInActiveFolder, isProxyFolderModeActive } from '@/store/proxy-folders'
import { displayGlobalByMode, manageHiddenGroup, proxyGroupSortType } from '@/store/settings'
import { groupTotalsMap } from '@/store/traffic-stats'
import { isEmpty } from 'lodash'
import { computed, ref } from 'vue'
import {
  isProxyNodeSearchMode,
  matchProxySearchKeyword,
  proxyGroupContainsMatchingNode,
  proxyProviderContainsMatchingNode,
  proxySearchKeyword,
} from './proxy-search'

const filterProxyGroups = (groups: string[], respectHiddenGroups = true) => {
  if (!proxySearchKeyword.value) {
    if (!respectHiddenGroups || manageHiddenGroup.value) {
      return groups
    }

    return groups.filter((name) => !isHiddenGroup(name))
  }

  const matchesGroup = isProxyNodeSearchMode.value
    ? proxyGroupContainsMatchingNode
    : (name: string) => matchProxySearchKeyword(name)

  return groups.filter(matchesGroup)
}

const sortProxyGroups = (groups: string[]) => {
  const sortType = proxyGroupSortType.value
  if (sortType === PROXY_GROUP_SORT_TYPE.DEFAULT || groups.length <= 1) {
    return groups
  }

  const latencyOf = (name: string) => {
    const now = proxyMap.value[name]?.now
    if (!now) return NOT_CONNECTED
    return getLatencyByName(now, name)
  }

  const trafficOf = (name: string) => {
    const row = groupTotalsMap.value.get(name)
    return row ? row.upload + row.download : 0
  }

  return [...groups].sort((a, b) => {
    switch (sortType) {
      case PROXY_GROUP_SORT_TYPE.NAME_ASC:
        return a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' })
      case PROXY_GROUP_SORT_TYPE.NAME_DESC:
        return b.localeCompare(a, undefined, { numeric: true, sensitivity: 'base' })
      case PROXY_GROUP_SORT_TYPE.LATENCY_ASC: {
        const la = latencyOf(a)
        const lb = latencyOf(b)
        const va = la > NOT_CONNECTED ? la : Infinity
        const vb = lb > NOT_CONNECTED ? lb : Infinity
        return va - vb
      }
      case PROXY_GROUP_SORT_TYPE.LATENCY_DESC: {
        const la = latencyOf(a)
        const lb = latencyOf(b)
        const validA = la > NOT_CONNECTED
        const validB = lb > NOT_CONNECTED
        if (validA !== validB) return validA ? -1 : 1
        if (!validA) return 0
        return lb - la
      }
      case PROXY_GROUP_SORT_TYPE.TRAFFIC_DESC:
        return trafficOf(b) - trafficOf(a)
      case PROXY_GROUP_SORT_TYPE.TRAFFIC_ASC:
        return trafficOf(a) - trafficOf(b)
      default:
        return 0
    }
  })
}

const getRenderProxyGroups = () => {
  if (isEmpty(proxyMap.value)) {
    return []
  }

  if (displayGlobalByMode.value) {
    if (configs.value?.mode.toUpperCase() === GLOBAL) {
      return sortProxyGroups(filterProxyGroups(getProxyGroupChains(GLOBAL), false))
    }

    return sortProxyGroups(filterProxyGroups(proxyGroupList.value))
  }

  const globalGroups = proxyMap.value[GLOBAL] ? [GLOBAL] : []
  return sortProxyGroups(filterProxyGroups([...proxyGroupList.value, ...globalGroups]))
}

const getRenderProxyProviders = () => {
  const names = proxyProviederList.value.map((provider) => provider.name)

  if (!proxySearchKeyword.value) {
    return names
  }

  const matches = isProxyNodeSearchMode.value
    ? proxyProviderContainsMatchingNode
    : (name: string) => matchProxySearchKeyword(name)

  return names.filter(matches)
}

export const disableProxiesPageScroll = ref(false)

export const renderProxyGroups = computed(getRenderProxyGroups)

export const renderProxyProviders = computed(getRenderProxyProviders)

export const renderProxiesPageItems = computed(() => {
  if (proxiesTabShow.value === PROXY_TAB_TYPE.PROVIDER) {
    return renderProxyProviders.value
  }

  const groups = renderProxyGroups.value
  if (!isProxyFolderModeActive.value) return groups
  const filter = groupsInActiveFolder.value
  if (!filter) return groups
  return groups.filter((name) => filter.has(name))
})
