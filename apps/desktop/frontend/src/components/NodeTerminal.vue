<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, watch } from 'vue'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { ElMessage } from 'element-plus/es/components/message/index'
import { ElMessageBox } from 'element-plus/es/components/message-box/index'
import { api, on, b64encode } from '../api/wails'
import { createTerminalResizeController } from './terminalResize'

const props = defineProps<{ clusterId: string; node: string }>()

const elRef = ref<HTMLDivElement | null>(null)
const sessionId = ref('')
const shell = ref('chroot')
const connecting = ref(false)
const status = ref('未连接')

type NodeShellAccess = {
  namespace: string
  helperPod: string
  image: string
  helperRunning: boolean
  requiresCreate: boolean
  getPodAllowed: boolean
  createPodAllowed: boolean
  execAllowed: boolean
  getPodReason?: string
  createPodReason?: string
  execReason?: string
}

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
  if (!elRef.value || connecting.value) return
  connecting.value = true
  await stop()
  status.value = '检查权限'

  try {
    const ok = await confirmNodeShell()
    if (!ok) return

    status.value = '连接中'
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
    term.writeln('\x1b[33m[kubetrail] 正在创建/复用 Node helper Pod，并打开 exec 会话...\x1b[0m')

    const id = (await api.StartNodeTerminal(props.clusterId, props.node, shell.value)) as string
    sessionId.value = id
    status.value = '已连接'

    offData = on<string>(`terminal:${id}:data`, (b64) => {
      const bin = atob(b64)
      term?.write(bin)
    })
    offExit = on<string>(`terminal:${id}:exit`, (msg) => {
      term?.writeln('')
      term?.writeln(`\x1b[33m[session ended] ${msg || ''}\x1b[0m`)
      sessionId.value = ''
      status.value = '未连接'
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
    await resizeController.fitNow(true)

    resizeObserver = new ResizeObserver(() => { resizeController.queueFit() })
    resizeObserver.observe(elRef.value)
  } catch (e: any) {
    status.value = '未连接'
    ElMessage.error(`Node exec 失败: ${e?.message || e}`)
  } finally {
    connecting.value = false
    if (!sessionId.value && status.value === '检查权限') status.value = '未连接'
  }
}

async function confirmNodeShell(): Promise<boolean> {
  let access: NodeShellAccess
  try {
    access = (await api.CheckNodeShellAccess(props.clusterId, props.node)) as NodeShellAccess
  } catch (e: any) {
    ElMessage.error(`Node Shell 权限检查失败: ${e?.message || e}`)
    return false
  }

  if (!access.getPodAllowed) {
    await ElMessageBox.alert(
      `当前 Kubernetes 身份缺少 get pods 权限，无法检查或复用 Node helper Pod。\n\nNamespace: ${access.namespace}\nHelper Pod: ${access.helperPod}${reasonLine(access.getPodReason)}`,
      '无法进入 Node Shell',
      { type: 'warning', confirmButtonText: '知道了' },
    )
    return false
  }
  if (!access.execAllowed) {
    await ElMessageBox.alert(
      `当前 Kubernetes 身份缺少 create pods/exec 权限，无法进入 helper Pod 执行命令。\n\nNamespace: ${access.namespace}\nHelper Pod: ${access.helperPod}${reasonLine(access.execReason)}`,
      '无法进入 Node Shell',
      { type: 'warning', confirmButtonText: '知道了' },
    )
    return false
  }
  if (access.requiresCreate && !access.createPodAllowed) {
    await ElMessageBox.alert(
      `当前 Kubernetes 身份缺少 create pods 权限，无法创建 Node helper Pod。\n\nNode Shell 需要创建 privileged + hostPath(/) 的 helper Pod 后才能进入节点。\n\nNamespace: ${access.namespace}\nHelper Pod: ${access.helperPod}${reasonLine(access.createPodReason)}`,
      '无法创建 Node helper Pod',
      { type: 'warning', confirmButtonText: '知道了' },
    )
    return false
  }

  const helperAction = access.requiresCreate
    ? `创建 helper Pod ${access.namespace}/${access.helperPod}`
    : `复用 helper Pod ${access.namespace}/${access.helperPod}`
  const createWarning = access.createPodAllowed
    ? ''
    : '\n\n注意：当前身份没有 create pods 权限；本次仅因 helper Pod 已存在才可尝试连接，清理后将无法重建。'
  const modeNotice = shell.value === 'helper'
    ? '\nMode: helper tools（使用 helper 镜像内工具，宿主机根目录挂载在 /host）'
    : '\nMode: host shell（chroot/nsenter 到宿主机环境，使用宿主机文件系统内工具）'

  try {
    await ElMessageBox.confirm(
      `即将进入 Node Shell。\n\nKubeTrail 会${helperAction}。\nImage: ${access.image || 'unknown'}${modeNotice}\n\n该 Pod 使用 privileged、hostPID、hostNetwork，并将宿主机 / 挂载到 /host。进入后具备高权限节点调试能力。\n\n请确认这是授权范围内的节点操作。${createWarning}`,
      '确认进入 Node Shell',
      {
        type: 'warning',
        confirmButtonText: '确认进入',
        cancelButtonText: '取消',
        distinguishCancelAndClose: true,
      },
    )
    return true
  } catch {
    status.value = '未连接'
    return false
  }
}

function reasonLine(reason?: string): string {
  return reason ? `\nReason: ${reason}` : ''
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
  status.value = '未连接'
  offData?.(); offData = null
  offExit?.(); offExit = null
  term?.dispose()
  term = null
}

async function cleanup() {
  await stop()
  try {
    await api.DeleteNodeShellPod(props.clusterId, props.node)
    ElMessage.success('Debug pod 已清理')
  } catch (e: any) {
    ElMessage.error(`清理失败: ${e?.message || e}`)
  }
}

onMounted(() => { start() })
onBeforeUnmount(() => { stop() })

watch(() => props.node, () => { start() })
</script>

<template>
  <div style="display:flex;gap:8px;margin-bottom:6px;align-items:center">
    <el-select v-model="shell" size="small" style="width:140px">
      <el-option label="chroot auto" value="chroot" />
      <el-option label="chroot bash" value="bash" />
      <el-option label="nsenter" value="nsenter" />
      <el-option label="helper tools" value="helper" />
    </el-select>
    <el-button size="small" @click="start" :icon="'Refresh'" :loading="connecting">连接</el-button>
    <el-button size="small" @click="stop" :icon="'CloseBold'" :disabled="!sessionId">断开</el-button>
    <el-button size="small" @click="cleanup" type="danger" plain :disabled="connecting">清理 debug pod</el-button>
    <span style="color:#909399;font-size:12px;margin-left:auto">{{ status }}</span>
  </div>
  <div ref="elRef" class="terminal-container"></div>
</template>
