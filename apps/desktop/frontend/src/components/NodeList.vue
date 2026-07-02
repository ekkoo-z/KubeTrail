<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index'
import { api } from '../api/wails'
import NodeDrawer from './NodeDrawer.vue'

const props = defineProps<{ clusterId: string }>()
const nodes = ref<any[]>([])
const loading = ref(false)
const restricted = ref(false)
const selectedNode = ref('')
const drawerVisible = ref(false)

async function load() {
  loading.value = true
  try {
    const list = ((await api.ListNodes(props.clusterId)) as any[]) || []
    nodes.value = list
    restricted.value = list.length === 0
  } catch (e: any) {
    const msg = String(e?.message || e)
    if (/forbidden|Not Allowed/i.test(msg)) {
      restricted.value = true
      nodes.value = []
    } else {
      ElMessage.error(`list nodes: ${msg}`)
    }
  } finally {
    loading.value = false
  }
}

function openNode(row: any) {
  selectedNode.value = row.name
  drawerVisible.value = true
}

watch(() => props.clusterId, load)
onMounted(load)
</script>

<template>
  <div v-if="restricted && !loading" class="rbac-banner">
    <span class="rbac-banner__dot" />
    <div class="rbac-banner__text">
      <b>无 nodes 权限</b> · 列 Node 是 cluster-scope 操作，当前 SA 拿不到。
      <router-link :to="{ name: 'cheatsheet' }" class="rbac-banner__link">命令速查 → 权限自查</router-link>
      看你具体能干什么。
    </div>
  </div>

  <div style="display:flex;gap:8px;margin-bottom:8px;align-items:center">
    <el-button @click="load" :loading="loading">
      <el-icon style="margin-right:4px"><Refresh /></el-icon>刷新
    </el-button>
    <span style="color:var(--kg-text-muted);font-size:12px;margin-left:auto">{{ nodes.length }} 个 node</span>
  </div>
  <el-table :data="nodes" v-loading="loading" :height="restricted ? 'calc(100vh - 230px)' : 'calc(100vh - 180px)'">
    <el-table-column prop="name" label="名称" min-width="200" show-overflow-tooltip />
    <el-table-column label="状态" width="100">
      <template #default="{ row }">
        <el-tag :type="row.status === 'Ready' ? 'success' : 'danger'" size="small">{{ row.status }}</el-tag>
      </template>
    </el-table-column>
    <el-table-column prop="roles" label="角色" width="140" />
    <el-table-column prop="version" label="版本" width="120" />
    <el-table-column prop="internalIP" label="内网 IP" width="130" />
    <el-table-column prop="age" label="年龄" width="80" />
    <el-table-column prop="runtime" label="运行时" min-width="160" show-overflow-tooltip />
    <el-table-column label="操作" width="100" align="center">
      <template #default="{ row }">
        <el-button size="small" link @click="openNode(row)">Shell</el-button>
      </template>
    </el-table-column>
  </el-table>

  <NodeDrawer
    v-if="drawerVisible"
    :cluster-id="clusterId"
    :node="selectedNode"
    @close="drawerVisible = false"
  />
</template>

<style scoped>
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
.rbac-banner__link {
  color: var(--kg-accent);
  text-decoration: none;
  font-weight: 500;
}
.rbac-banner__link:hover { text-decoration: underline; }
</style>
