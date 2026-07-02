<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, watch } from 'vue'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { ElMessage } from 'element-plus/es/components/message/index'
import { api, on, b64encode } from '../api/wails'
import { createTerminalResizeController } from './terminalResize'

const props = defineProps<{ clusterId: string; namespace: string; pod: string; container: string }>()

const elRef = ref<HTMLDivElement | null>(null)
const sessionId = ref('')
const shell = ref('auto')

let term: Terminal | null = null
let fit: FitAddon | null = null
let offData: (() => void) | null = null
let offExit: (() => void) | null = null
let resizeObserver: ResizeObserver | null = null
let writeQueue = Promise.resolve()
const resizeController = createTerminalResizeController({
  getTerminal: () => term,
  getFitAddon: () => fit,
  getSessionId: () => sessionId.value,
  sendResize: (id, cols, rows) => api.ResizeTerminal(id, cols, rows),
})

async function start() {
  if (!elRef.value) return
  await stop()
  term = new Terminal({
    cursorBlink: true,
    fontSize: 13,
    fontFamily: 'SF Mono, Menlo, Monaco, Courier New, monospace',
    theme: { background: '#000000', foreground: '#d4d4d4' },
    windowsMode: true,
  })
  term.attachCustomKeyEventHandler((event) => {
    if (event.key === 'Tab') event.preventDefault()
    return true
  })
  fit = new FitAddon()
  term.loadAddon(fit)
  term.open(elRef.value)
  await resizeController.fitNow(false)

  try {
    const id = (await api.StartTerminal({
      clusterID: props.clusterId,
      namespace: props.namespace,
      pod: props.pod,
      container: props.container,
      command: [shell.value],
    })) as string
    sessionId.value = id

    offData = on<string>(`terminal:${id}:data`, (b64) => {
      const bin = atob(b64)
      term?.write(bin)
    })
    offExit = on<string>(`terminal:${id}:exit`, (msg) => {
      term?.writeln('')
      term?.writeln(`\x1b[33m[session ended] ${msg || ''}\x1b[0m`)
      sessionId.value = ''
    })

    term.onData((data) => {
      const id = sessionId.value
      if (!id) return
      const payload = b64encode(data)
      writeQueue = writeQueue.then(async () => {
        if (sessionId.value !== id) return
        await resizeController.syncRemoteNow()
        if (sessionId.value === id) await api.WriteTerminal(id, payload)
      }).catch(() => {})
    })
    // first resize after backend connected
    await resizeController.fitNow(true)

    resizeObserver = new ResizeObserver(() => { resizeController.queueFit() })
    resizeObserver.observe(elRef.value)
  } catch (e: any) {
    ElMessage.error(`exec 失败: ${e?.message || e}`)
  }
}

async function stop() {
  resizeController.reset()
  writeQueue = Promise.resolve()
  resizeObserver?.disconnect()
  resizeObserver = null
  if (sessionId.value) {
    try { await api.StopTerminal(sessionId.value) } catch {}
    sessionId.value = ''
  }
  offData?.(); offData = null
  offExit?.(); offExit = null
  term?.dispose()
  term = null
}

onMounted(() => { start() })
onBeforeUnmount(() => { stop() })

watch(() => `${props.pod}|${props.container}`, () => { start() })
</script>

<template>
  <div style="display:flex;gap:8px;margin-bottom:6px;align-items:center">
    <el-select v-model="shell" size="small" style="width:140px">
      <el-option label="auto" value="auto" />
      <el-option label="bash" value="/bin/bash" />
      <el-option label="ash" value="/bin/ash" />
      <el-option label="sh" value="/bin/sh" />
    </el-select>
    <el-button size="small" @click="start" :icon="'Refresh'">重连</el-button>
    <el-button size="small" @click="stop" :icon="'CloseBold'" :disabled="!sessionId">断开</el-button>
    <span style="color:#909399;font-size:12px;margin-left:auto">{{ sessionId ? '已连接' : '未连接' }}</span>
  </div>
  <div ref="elRef" class="terminal-container"></div>
</template>
