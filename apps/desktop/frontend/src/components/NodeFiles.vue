<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index'
import { ElMessageBox } from 'element-plus/es/components/message-box/index'
import { api, b64decodeToText } from '../api/wails'

const props = defineProps<{ clusterId: string; node: string }>()

const cwd = ref('/')
const entries = ref<any[]>([])
const loading = ref(false)
const cwdInput = ref('/')
const preview = ref<{ path: string; text: string } | null>(null)

async function list(path?: string) {
  const p = path ?? cwd.value
  loading.value = true
  try {
    entries.value = ((await api.ListNodeFiles(props.clusterId, props.node, p)) as any[]) || []
    cwd.value = p
    cwdInput.value = p
  } catch (e: any) {
    ElMessage.error(String(e?.message || e))
  } finally {
    loading.value = false
  }
}

function parentOf(p: string): string {
  if (p === '/' || p === '') return '/'
  const idx = p.lastIndexOf('/')
  if (idx <= 0) return '/'
  return p.slice(0, idx)
}

async function open(row: any) {
  if (row.isDir || (row.isLink && row.target && row.target.endsWith('/'))) {
    // Strip /host prefix from the path returned by backend.
    let dir = row.path
    if (dir.startsWith('/host')) dir = dir.slice(5) || '/'
    await list(dir)
  } else {
    let filePath = row.path
    if (filePath.startsWith('/host')) filePath = filePath.slice(5)
    await readPreview(filePath)
  }
}

async function readPreview(path: string) {
  try {
    const b64 = (await api.ReadNodeFile(props.clusterId, props.node, path, 256 * 1024)) as string
    preview.value = { path, text: b64decodeToText(b64) }
  } catch (e: any) {
    ElMessage.error(String(e?.message || e))
  }
}

async function downloadFile(row: any) {
  try {
    const dir = await api.PickDirectory()
    if (!dir) return
    let remotePath = row.path
    if (remotePath.startsWith('/host')) remotePath = remotePath.slice(5)
    await api.DownloadNodeFile(props.clusterId, props.node, remotePath, dir)
    ElMessage.success(`已下载到 ${dir}`)
  } catch (e: any) {
    ElMessage.error(String(e?.message || e))
  }
}

async function uploadHere() {
  try {
    const file = await api.PickOpenFile()
    if (!file) return
    await api.UploadNodeFile(props.clusterId, props.node, file, cwd.value)
    ElMessage.success(`已上传到 ${cwd.value}`)
    await list()
  } catch (e: any) {
    ElMessage.error(String(e?.message || e))
  }
}

async function remove(row: any) {
  try {
    await ElMessageBox.confirm(`删除 ${row.path}？`, '确认', { type: 'warning' })
    let target = row.path
    if (target.startsWith('/host')) target = target.slice(5)
    await api.DeleteNodeFile(props.clusterId, props.node, target)
    ElMessage.success('已删除')
    await list()
  } catch (e: any) {
    if (e === 'cancel') return
    ElMessage.error(String(e?.message || e))
  }
}

function displayName(row: any): string {
  // Show actual node path, strip /host prefix.
  let p = row.name
  return p
}

onMounted(() => list('/'))
watch(() => props.node, () => list('/'))
</script>

<template>
  <div style="display:flex;gap:6px;align-items:center;margin-bottom:6px">
    <el-button :icon="'Back'" @click="list(parentOf(cwd))" size="small">上级</el-button>
    <el-input v-model="cwdInput" size="small" @keyup.enter="list(cwdInput)" style="flex:1" />
    <el-button :icon="'Right'" size="small" @click="list(cwdInput)">Go</el-button>
    <el-button :icon="'Refresh'" size="small" @click="list()" :loading="loading">刷新</el-button>
    <el-button :icon="'Upload'" size="small" type="primary" @click="uploadHere">上传到此</el-button>
  </div>
  <el-table :data="entries" v-loading="loading" height="420" @row-dblclick="open">
    <el-table-column label="名" min-width="220" show-overflow-tooltip>
      <template #default="{ row }">
        <el-icon v-if="row.isDir"><Folder /></el-icon>
        <el-icon v-else-if="row.isLink"><Link /></el-icon>
        <el-icon v-else><Document /></el-icon>
        <span style="margin-left:4px">{{ displayName(row) }}</span>
        <span v-if="row.target" style="color:#909399;font-size:12px;margin-left:4px">→ {{ row.target }}</span>
      </template>
    </el-table-column>
    <el-table-column prop="mode" label="模式" width="110" />
    <el-table-column prop="size" label="大小" width="100" />
    <el-table-column prop="mtime" label="mtime" width="120" />
    <el-table-column label="操作" width="220" align="right">
      <template #default="{ row }">
        <el-button size="small" link @click="open(row)">{{ row.isDir ? '进入' : '查看' }}</el-button>
        <el-button size="small" link @click="downloadFile(row)" v-if="!row.isDir">下载</el-button>
        <el-button size="small" link type="danger" @click="remove(row)">删除</el-button>
      </template>
    </el-table-column>
  </el-table>

  <el-dialog v-model="preview" v-if="preview" :title="preview.path" width="80%">
    <pre class="code-block" style="max-height:60vh">{{ preview.text }}</pre>
    <template #footer>
      <el-button @click="preview = null">关闭</el-button>
    </template>
  </el-dialog>
</template>
