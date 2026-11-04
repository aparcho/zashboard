<template>
  <div class="relative flex h-18 shrink-0 flex-col justify-between">
    <div
      class="text-md truncate"
      :class="proxyGroup.icon && 'pr-10'"
    >
      {{ proxyGroup.name }}
    </div>
    <div
      class="text-base-content/40 flex min-w-0 items-center gap-1.5 text-[11px] tabular-nums"
      :class="proxyGroup.icon && 'pr-12'"
      data-group-metadata
    >
      <span
        v-if="displayContent"
        class="min-w-0 truncate tracking-wider uppercase"
        >{{ proxyGroup.type }} ·</span
      >
      <span class="shrink-0">{{ proxiesCount }}</span>
      <span
        class="text-base-content/25 shrink-0"
        aria-hidden="true"
        >·</span
      >
      <ProxyGroupTraffic
        :name="name"
        class="shrink-0"
      />
      <ProxyGroupFilter
        v-if="displayContent"
        :group-name="name"
      />
    </div>
    <div class="flex items-center">
      <div class="flex flex-1 items-center gap-1 truncate">
        <VisibilityToggle
          v-if="manageHiddenGroup"
          :hidden="hiddenGroup"
          class="z-10"
          @mouseenter="showVisibilityTip"
          @toggle="handlerGroupToggle"
        />
        <ProxyGroupNow
          :name="proxyGroup.name"
          :mobile="true"
        />
      </div>
      <ProxyGroupSpeed
        v-if="!twoColumnProxyGroup || displayContent"
        :name="name"
        class="mr-2"
      />
      <LatencyTag
        :class="twMerge('bg-base-200/40 hover:bg-base-200/70 z-10')"
        :loading="isLatencyTesting"
        :name="proxyGroup.now"
        :group-name="proxyGroup.name"
        @click.stop="emit('latency-test')"
      />
    </div>
    <ProxyIcon
      v-if="proxyGroup?.icon"
      :icon="proxyGroup.icon"
      :size="40"
      :margin="0"
      class="absolute top-0 right-0"
    />
  </div>
</template>

<script setup lang="ts">
import { hiddenGroupMap } from '@/store/proxies'
import { useKeyboardShortcuts } from '@/composables/use-keyboard'
import { KEYBOARD_SHORTCUT_ACTION } from '@/helper/keyboard'
import { isHiddenGroup } from '@/helper'
import { proxyMap } from '@/assembly/proxies'
import { useTooltip } from '@/composables/use-tooltip'
import { manageHiddenGroup, twoColumnProxyGroup } from '@/store/settings'
import { twMerge } from 'tailwind-merge'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import VisibilityToggle from '../common/VisibilityToggle.vue'
import LatencyTag from './LatencyTag.vue'
import ProxyGroupFilter from './ProxyGroupFilter.vue'
import ProxyGroupNow from './ProxyGroupNow.vue'
import ProxyIcon from './ProxyIcon.vue'
import ProxyGroupTraffic from './ProxyGroupTraffic.vue'
import ProxyGroupSpeed from './ProxyGroupSpeed.vue'

const props = defineProps<{
  name: string
  proxiesCount: string
  isLatencyTesting: boolean
  displayContent: boolean
}>()

const emit = defineEmits<{
  'latency-test': []
}>()

const { t } = useI18n()
const { getShortcutKey } = useKeyboardShortcuts()
const { showTip } = useTooltip()
const proxyGroup = computed(() => proxyMap.value[props.name])

const hiddenGroup = computed({
  get: () => Boolean(isHiddenGroup(props.name)),
  set: (value: boolean) => {
    hiddenGroupMap.value[props.name] = value
  },
})

const visibilityToggleTip = computed(() => {
  const title = t(hiddenGroup.value ? 'showProxyGroup' : 'hideProxyGroup')
  const shortcut = getShortcutKey(KEYBOARD_SHORTCUT_ACTION.TOGGLE_MANAGE_HIDDEN_GROUP)

  return shortcut ? `${title}\n${t('manageHiddenGroupShortcutTip', { shortcut })}` : title
})

const showVisibilityTip = (e: Event) => {
  showTip(e, visibilityToggleTip.value, {
    delay: [500, 0],
    trigger: 'mouseenter',
    touch: ['hold', 500],
  })
}

const handlerGroupToggle = () => {
  hiddenGroup.value = !hiddenGroup.value
}
</script>
