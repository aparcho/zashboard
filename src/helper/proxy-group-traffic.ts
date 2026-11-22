import { activeConnections } from '@/assembly/connections'
import { getConnectionChains } from '@/helper'
import { computed } from 'vue'

const speedByProxyGroup = (direction: 'downloadSpeed' | 'uploadSpeed') =>
  computed(() => {
    const speedMap = new Map<string, number>()

    for (const connection of activeConnections.value) {
      const speed = connection[direction]

      if (!speed) continue

      const chains = getConnectionChains(connection)

      for (let i = 0; i < chains.length; i++) {
        const name = chains[i]

        if (chains.indexOf(name) !== i) continue

        speedMap.set(name, (speedMap.get(name) ?? 0) + speed)
      }
    }

    return speedMap
  })

export const downloadSpeedByProxyGroup = speedByProxyGroup('downloadSpeed')
export const uploadSpeedByProxyGroup = speedByProxyGroup('uploadSpeed')

export const getUploadSpeedByProxyGroup = (name: string) =>
  uploadSpeedByProxyGroup.value.get(name) ?? 0

export const getDownloadSpeedByProxyGroup = (name: string) =>
  downloadSpeedByProxyGroup.value.get(name) ?? 0
