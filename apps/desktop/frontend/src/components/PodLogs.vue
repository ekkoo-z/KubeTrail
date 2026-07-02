<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, watch, nextTick } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index'
import { api, on } from '../api/wails'

const props = defineProps<{ clusterId: string; namespace: string; pod: string; container: string }>()

const lines = ref<string[]>([])
const tail = ref(200)
const follow = ref(true)
const autoScroll = ref(true)
const sessionId = ref('')
const filterText = ref('')
const boxRef = ref<HTMLDivElement | null>(null)

let offLine: (() => void) | null = null
let offEnd: (() => void) | null = null

async function start() {
  await stop()
  lines.value = []
  try {
    const id = (await api.StartLogs({
      clusterID: props.clusterId,
      namespace: props.namespace,
      pod: props.pod,
      container: props.container,
      follow: follow.value,
      tailLines: tail.value,
      sinceSeconds: 0,
    })) as string
    sessionId.value = id
    offLine = on<string>(`logs:${id}:line`, (l) => {
      lines.value.push(l)
      if (lines.value.length > 5000) lines.value.splice(0, 1000)
      if (autoScroll.value) nextTick(scroll)
    })
    offEnd = on<string>(`logs:${id}:end`, (msg) => {
      lines.value.push(`[stream end] ${msg || ''}`)
      sessionId.value = ''
    })
  } catch (e: any) {
    ElMessage.error(`logs: ${e?.message || e}`)
  }
}

async function stop() {
  if (sessionId.value) {
    try { await api.StopLogs(sessionId.value) } catch {}
    sessionId.value = ''
  }
  offLine?.(); offLine = null
  offEnd?.(); offEnd = null
}

function scroll() {
  if (boxRef.value) boxRef.value.scrollTop = boxRef.value.scrollHeight
}

onMounted(start)
onBeforeUnmount(stop)
watch(() => `${props.pod}|${props.container}`, start)
</script>

<template>
  <div style="display:flex;gap:8px;margin-bottom:6px;align-items:center">
    <el-input-number v-model="tail" :min="10" :max="10000" size="small" />
    <el-switch v-model="follow" active-text="follow" />
    <el-switch v-model="autoScroll" active-text="自动滚动" />
    <el-input v-model="filterText" placeholder="过滤" size="small" style="width:200px" clearable />
    <el-button size="small" @click="start" :icon="'Refresh'">重连</el-button>
    <el-button size="small" @click="stop" :disabled="!sessionId">停止</el-button>
    <el-button size="small" @click="lines = []">清屏</el-button>
    <span style="color:#909399;font-size:12px;margin-left:auto">{{ lines.length }} 行</span>
  </div>
  <div ref="boxRef" class="code-block" style="height:500px;max-height:500px">
    <template v-for="(l, i) in lines" :key="i">
      <div v-if="!filterText || l.includes(filterText)">{{ l }}</div>
    </template>
  </div>
</template>
