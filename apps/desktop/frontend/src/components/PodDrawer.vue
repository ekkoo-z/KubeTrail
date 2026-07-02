<script setup lang="ts">
import { ref, watch, computed } from 'vue'
import PodTerminal from './PodTerminal.vue'
import PodLogs from './PodLogs.vue'
import PodFiles from './PodFiles.vue'
import Redteam from './Redteam.vue'

const props = defineProps<{
  clusterId: string
  namespace: string
  pod: string
  containers: string[]
}>()
const emit = defineEmits<{ (e: 'close'): void }>()

const open = ref(true)
const tab = ref('overview')
const container = ref(props.containers[0] || '')

watch(() => props.containers, (cs) => {
  if (cs.length && !cs.includes(container.value)) container.value = cs[0]
})
watch(() => props.pod, () => { tab.value = 'overview' })

function onClose() {
  open.value = false
  emit('close')
}

const title = computed(() => `${props.namespace} / ${props.pod}`)
</script>

<template>
  <el-drawer v-model="open" :title="title" size="70%" @close="onClose" destroy-on-close>
    <div style="margin-bottom:8px;display:flex;align-items:center;gap:8px">
      <span>容器：</span>
      <el-select v-model="container" style="width:240px">
        <el-option v-for="c in containers" :key="c" :label="c" :value="c" />
      </el-select>
    </div>
    <el-tabs v-model="tab" type="border-card">
      <el-tab-pane label="概览" name="overview">
        <pre class="code-block">{{ {
          pod, namespace, containers,
        } }}</pre>
      </el-tab-pane>
      <el-tab-pane label="终端" name="term" lazy>
        <PodTerminal
          v-if="container"
          :cluster-id="clusterId"
          :namespace="namespace"
          :pod="pod"
          :container="container"
        />
      </el-tab-pane>
      <el-tab-pane label="日志" name="logs" lazy>
        <PodLogs
          v-if="container"
          :cluster-id="clusterId"
          :namespace="namespace"
          :pod="pod"
          :container="container"
        />
      </el-tab-pane>
      <el-tab-pane label="文件" name="files" lazy>
        <PodFiles
          v-if="container"
          :cluster-id="clusterId"
          :namespace="namespace"
          :pod="pod"
          :container="container"
        />
      </el-tab-pane>
      <el-tab-pane label="Redteam" name="redteam" lazy>
        <Redteam
          v-if="container"
          :cluster-id="clusterId"
          :namespace="namespace"
          :pod="pod"
          :container="container"
        />
      </el-tab-pane>
    </el-tabs>
  </el-drawer>
</template>
