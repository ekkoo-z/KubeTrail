<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index'
import { api, on } from '../api/wails'

const props = defineProps<{ clusterId: string }>()

const list = ref<any[]>([])
const form = ref({ namespace: 'default', pod: '', localPort: 0, podPort: 0 })
const offHandles: Array<() => void> = []

async function refresh() {
  list.value = ((await api.ListPortForwards()) as any[]) || []
}

async function start() {
  if (!form.value.pod || !form.value.podPort) {
    ElMessage.warning('pod 和远端端口必填')
    return
  }
  try {
    const id = (await api.StartPortForward(
      props.clusterId,
      form.value.namespace,
      form.value.pod,
      form.value.localPort | 0,
      form.value.podPort | 0,
    )) as string
    offHandles.push(on<any>(`pf:${id}:status`, (d) => {
      ElMessage.success(`PF 就绪：本机 :${d.localPort}`)
      refresh()
    }))
    offHandles.push(on<string>(`pf:${id}:error`, (msg) => {
      ElMessage.error(`PF 错误：${msg}`)
      refresh()
    }))
    await refresh()
  } catch (e: any) {
    ElMessage.error(String(e?.message || e))
  }
}

async function stop(id: string) {
  await api.StopPortForward(id)
  await refresh()
}

onMounted(refresh)
onBeforeUnmount(() => { offHandles.forEach((f) => f()) })
</script>

<template>
  <el-card style="margin-bottom:12px">
    <div class="pf-help">
      <div class="pf-help__title">使用方式</div>
      <div class="pf-help__body">
        在当前机器监听 <code>127.0.0.1:&lt;本地端口&gt;</code>，通过 kube-apiserver 转发到目标
        <code>Pod:&lt;Pod 端口&gt;</code>，不需要额外部署内网穿透服务端。即使目标 Pod 没有
        Ingress、NodePort 或 LoadBalancer，也可以通过 API Server 通道访问它的端口。本地端口填
        <code>0</code> 会自动分配，就绪后访问列表里的本地地址；当前仅支持 Pod 名，需要当前身份具备
        <code>create pods/portforward</code> 权限。
      </div>
    </div>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <el-input v-model="form.namespace" placeholder="namespace" style="width:160px" size="small" />
      <el-input v-model="form.pod" placeholder="pod 名" style="width:240px" size="small" />
      <el-input-number v-model="form.localPort" placeholder="本地端口（0=随机）" :min="0" size="small" />
      <span>→</span>
      <el-input-number v-model="form.podPort" placeholder="Pod 端口" :min="1" size="small" />
      <el-button type="primary" @click="start" size="small">启动</el-button>
      <el-button @click="refresh" size="small" :icon="'Refresh'">刷新</el-button>
    </div>
  </el-card>

  <el-table :data="list" stripe>
    <el-table-column prop="namespace" label="ns" width="140" />
    <el-table-column prop="pod" label="pod" min-width="240" show-overflow-tooltip />
    <el-table-column label="本地" width="100">
      <template #default="{ row }">127.0.0.1:{{ row.localPort }}</template>
    </el-table-column>
    <el-table-column prop="podPort" label="Pod 端口" width="100" />
    <el-table-column label="状态" width="100">
      <template #default="{ row }">
        <el-tag :type="row.ready ? 'success' : 'info'" size="small">{{ row.ready ? '就绪' : '建立中' }}</el-tag>
      </template>
    </el-table-column>
    <el-table-column label="操作" width="120">
      <template #default="{ row }">
        <el-button size="small" type="danger" @click="stop(row.sessionID)">停止</el-button>
      </template>
    </el-table-column>
  </el-table>
</template>

<style scoped>
.pf-help {
  border: 1px solid var(--kg-border-soft);
  border-radius: 6px;
  background: var(--kg-surface-2);
  padding: 10px 12px;
  margin-bottom: 12px;
}

.pf-help__title {
  color: var(--kg-text);
  font-size: 13px;
  font-weight: 600;
  line-height: 20px;
  margin-bottom: 2px;
}

.pf-help__body {
  color: var(--kg-text-muted);
  font-size: 12px;
  line-height: 20px;
}

.pf-help code {
  font-family: var(--kg-font-mono);
  font-size: 12px;
  color: var(--kg-accent);
  background: var(--kg-bg);
  border: 1px solid var(--kg-border-soft);
  border-radius: 4px;
  padding: 1px 4px;
}
</style>
