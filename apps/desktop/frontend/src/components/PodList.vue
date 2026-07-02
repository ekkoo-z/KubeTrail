<script setup lang="ts">
import { ref, computed, onMounted, watch, h } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index'
import { ElTag } from 'element-plus/es/components/tag/index'
import { api } from '../api/wails'
import { useClusterStore } from '../stores/cluster'

const props = defineProps<{ clusterId: string }>()
const emit = defineEmits<{ (e: 'select', pod: any): void }>()

const cs = useClusterStore()

const namespaces = ref<string[]>([])
const namespace = ref<string>('(all)')
const pods = ref<any[]>([])
const loading = ref(false)
const filterInput = ref('')
const filterText = ref('')
// SA 只能看自己 ns 时把横幅亮出来
const restricted = ref(false)

// debounce 250ms — 5k+ rows 全量过滤每次按键太烫
let filterTimer: any
watch(filterInput, (v) => {
  clearTimeout(filterTimer)
  filterTimer = setTimeout(() => { filterText.value = v }, 250)
})

const filtered = computed(() => {
  if (!filterText.value) return pods.value
  const f = filterText.value.toLowerCase()
  return pods.value.filter((p) =>
    p.name.toLowerCase().includes(f) ||
    (p.node || '').toLowerCase().includes(f) ||
    (p.namespace || '').toLowerCase().includes(f),
  )
})

function statusTag(s: string) {
  switch (s) {
    case 'Running': return 'success'
    case 'Pending':
    case 'ContainerCreating': return 'warning'
    case 'Succeeded': return 'info'
    case 'Failed':
    case 'CrashLoopBackOff':
    case 'Error':
    case 'ImagePullBackOff': return 'danger'
    default: return 'info'
  }
}

const columns = computed(() => {
  const cols: any[] = [
    { key: 'name', dataKey: 'name', title: '名称', width: 260 },
    { key: 'namespace', dataKey: 'namespace', title: 'ns', width: 160 },
    {
      key: 'status', dataKey: 'status', title: '状态', width: 130,
      cellRenderer: ({ cellData }: any) =>
        h(ElTag, { type: statusTag(cellData), size: 'small' }, () => cellData),
    },
    { key: 'ready', dataKey: 'ready', title: '就绪', width: 70 },
    { key: 'restarts', dataKey: 'restarts', title: '重启', width: 60 },
    { key: 'age', dataKey: 'age', title: '年龄', width: 80 },
    { key: 'podIP', dataKey: 'podIP', title: 'Pod IP', width: 130 },
    { key: 'node', dataKey: 'node', title: '节点', width: 200 },
    {
      key: 'marks', dataKey: 'privileged', title: '标记', width: 100,
      cellRenderer: ({ rowData }: any) => {
        if (rowData.privileged) return h(ElTag, { type: 'danger', size: 'small' }, () => 'privileged')
        return null
      },
    },
  ]
  if (namespace.value !== '(all)') return cols.filter((c) => c.key !== 'namespace')
  return cols
})

const rowEventHandlers = {
  onClick: ({ rowData }: any) => emit('select', rowData),
}

const rowKey = (row: any) => `${row.namespace}/${row.name}`

async function loadNamespaces() {
  try {
    const list = (await api.ListNamespaces(props.clusterId)) as any[]
    const names = list.map((n) => n.name)
    // 后端在 forbidden 时只会回一个 ns —— 此时禁用 "(all)" 路径，
    // 避免再触发一次 cluster-scope list 的 403
    if (names.length <= 1) {
      restricted.value = true
      namespaces.value = names.length ? names : [defaultNs()]
      namespace.value = namespaces.value[0]
    } else {
      restricted.value = false
      namespaces.value = ['(all)', ...names]
      // 默认选 SA 的 ns（若它在列表里），否则 (all)
      const bound = defaultNs()
      if (bound && names.includes(bound)) namespace.value = bound
      else if (!namespaces.value.includes(namespace.value)) namespace.value = '(all)'
    }
  } catch (e: any) {
    ElMessage.error(`list namespaces: ${e?.message || e}`)
  }
}

function defaultNs(): string {
  return cs.connected[props.clusterId]?.namespace || ''
}

async function loadPods() {
  loading.value = true
  try {
    const ns = namespace.value === '(all)' ? '' : namespace.value
    pods.value = ((await api.ListPods(props.clusterId, ns)) as any[]) || []
  } catch (e: any) {
    const msg = String(e?.message || e)
    // ns-scoped SA 在 (all) 模式下后端会自动 fallback；
    // 这里只是 belt-and-braces：若依然报 forbidden，提示用户切到自己的 ns
    if (/forbidden|Not Allowed/i.test(msg) && namespace.value === '(all)') {
      restricted.value = true
      const bound = defaultNs()
      if (bound) {
        namespace.value = bound
        ElMessage.warning(`无 cluster-scope list 权限，已切到 ${bound}`)
        return
      }
    }
    ElMessage.error(`list pods: ${msg}`)
  } finally {
    loading.value = false
  }
}

watch(namespace, loadPods)
watch(() => props.clusterId, async () => {
  await loadNamespaces()
  await loadPods()
})

onMounted(async () => {
  await loadNamespaces()
  await loadPods()
})
</script>

<template>
  <div v-if="restricted" class="rbac-banner">
    <span class="rbac-banner__dot" />
    <div class="rbac-banner__text">
      <b>受限身份</b> · 当前 SA 没有 cluster-scope list 权限，已限定在
      <code>{{ namespace }}</code>。想看其它 ns 的资源？
      <router-link :to="{ name: 'cheatsheet' }" class="rbac-banner__link">命令速查 → 权限自查</router-link>
      里有 <code>auth can-i --list</code> 一把过模板。
    </div>
  </div>

  <div style="display:flex;gap:8px;margin-bottom:8px;align-items:center">
    <el-select v-model="namespace" filterable style="width:240px" :disabled="restricted && namespaces.length <= 1">
      <el-option v-for="n in namespaces" :key="n" :label="n" :value="n" />
    </el-select>
    <el-input v-model="filterInput" placeholder="过滤 名字/节点/ns" clearable style="width:280px" />
    <el-button @click="loadPods" :loading="loading">
      <el-icon style="margin-right:4px"><Refresh /></el-icon>刷新
    </el-button>
    <span style="color:var(--kg-text-muted);font-size:12px;margin-left:auto">
      {{ filtered.length }} / {{ pods.length }} pods
      <span v-if="pods.length > 500" style="color:var(--kg-accent);margin-left:4px">virtualized</span>
    </span>
  </div>

  <div v-loading="loading" :style="{ height: restricted ? 'calc(100vh - 230px)' : 'calc(100vh - 180px)', background: 'var(--kg-surface)', border: '1px solid var(--kg-border-soft)', borderRadius: '8px' }">
    <el-auto-resizer>
      <template #default="{ height, width }">
        <el-table-v2
          :columns="columns"
          :data="filtered"
          :width="width"
          :height="height"
          :row-key="rowKey"
          :row-event-handlers="rowEventHandlers"
          :estimated-row-height="40"
        />
      </template>
    </el-auto-resizer>
  </div>
</template>

<style scoped>
:deep(.el-table-v2__row) { cursor: pointer; }
:deep(.el-table-v2__row:hover) { background: var(--kg-surface-2); }

.rbac-banner {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 14px;
  margin-bottom: 10px;
  background: rgba(245, 158, 11, 0.06);
  border: 1px solid rgba(245, 158, 11, 0.25);
  border-radius: 8px;
}
.rbac-banner__dot {
  width: 6px;
  height: 6px;
  margin-top: 7px;
  border-radius: 50%;
  background: var(--kg-warn);
  flex-shrink: 0;
}
.rbac-banner__text {
  font-size: 12.5px;
  line-height: 1.6;
  color: var(--kg-text);
}
.rbac-banner__text code {
  font-family: var(--kg-font-mono);
  font-size: 11.5px;
  background: var(--kg-surface-2);
  border: 1px solid var(--kg-border-soft);
  border-radius: 3px;
  padding: 1px 5px;
  color: var(--kg-warn);
}
.rbac-banner__link {
  color: var(--kg-accent);
  text-decoration: none;
  font-weight: 500;
}
.rbac-banner__link:hover { text-decoration: underline; }
</style>
