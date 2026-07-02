<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useClusterStore } from '../stores/cluster'
import PodList from '../components/PodList.vue'
import NodeList from '../components/NodeList.vue'
import PodDrawer from '../components/PodDrawer.vue'
import PortForwardPanel from '../components/PortForwardPanel.vue'
import ScanPanel from '../components/ScanPanel.vue'
import AgentPanel from '../components/AgentPanel.vue'
import PersistencePanel from '../components/PersistencePanel.vue'

const route = useRoute()
const cs = useClusterStore()

const clusterId = computed(() => route.params.id as string)
const info = computed(() => cs.connected[clusterId.value])
const tab = ref<'pods' | 'nodes' | 'pf' | 'scan' | 'agent' | 'persistence'>('pods')

const selectedPod = ref<{ namespace: string; name: string; containers: string[] } | null>(null)

watch(clusterId, async (id) => {
  if (id && !cs.connected[id]) {
    try { await cs.connect(id) } catch (e: any) {
      ;(window as any).ElMessage?.error?.(String(e))
    }
  }
}, { immediate: true })

onMounted(() => { tab.value = 'pods' })

function openPod(p: any) {
  selectedPod.value = { namespace: p.namespace, name: p.name, containers: p.containers || [] }
}
</script>

<template>
  <el-header class="layout-header">
    <span class="status-dot" :class="{ 'is-on': info }"></span>
    <b style="font-size:14px;font-weight:600">{{ info?.name || clusterId }}</b>
    <span v-if="info" style="color:var(--kg-text-muted);font-size:12px;font-family:var(--kg-font-mono)">
      {{ info.version }} · {{ info.apiServer }}
    </span>
    <span style="flex:1"></span>
    <el-segmented v-model="tab" :options="[
      { label: 'Pods', value: 'pods' },
      { label: 'Nodes', value: 'nodes' },
      { label: 'Port-Forward', value: 'pf' },
      { label: '扫描', value: 'scan' },
      { label: '智能攻击', value: 'agent' },
      { label: '持久化', value: 'persistence' },
    ]" />
  </el-header>
  <el-main class="layout-main">
    <PodList v-if="tab === 'pods'" :cluster-id="clusterId" @select="openPod" />
    <NodeList v-else-if="tab === 'nodes'" :cluster-id="clusterId" />
    <PortForwardPanel v-else-if="tab === 'pf'" :cluster-id="clusterId" />
    <ScanPanel v-else-if="tab === 'scan'" :cluster-id="clusterId" />
    <AgentPanel v-else-if="tab === 'agent'" :cluster-id="clusterId" />
    <PersistencePanel v-else-if="tab === 'persistence'" :cluster-id="clusterId" />
  </el-main>
  <PodDrawer
    v-if="selectedPod"
    :cluster-id="clusterId"
    :namespace="selectedPod.namespace"
    :pod="selectedPod.name"
    :containers="selectedPod.containers"
    @close="selectedPod = null"
  />
</template>

<style scoped>
.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--kg-text-dim);
  box-shadow: 0 0 0 3px rgba(90, 100, 120, 0.18);
  transition: background .2s, box-shadow .2s;
}
.status-dot.is-on {
  background: var(--kg-accent);
  box-shadow: 0 0 0 3px var(--kg-accent-soft);
}
</style>
