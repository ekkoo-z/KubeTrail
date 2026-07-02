<script setup lang="ts">
import { reactive, ref } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index'
import { api } from '../api/wails'

const emit = defineEmits<{ (e: 'saved'): void; (e: 'cancel'): void }>()

const tab = ref<'kubeconfig' | 'token'>('kubeconfig')

const form = reactive({
  name: '',
  namespace: '',
  // kubeconfig branch
  kubeconfigPath: '',
  kubeconfigContent: '',
  // token branch
  apiServer: '',
  token: '',
  caData: '',
  insecure: false,
  // hub-proxy / aggregated apiserver
  apiPathPrefix: '',
})

const testing = ref(false)
const saving = ref(false)
const scanning = ref(false)
const importing = ref(false)
const extensions = ref<any[]>([])

async function importFromScan() {
  importing.value = true
  try {
    const r = await api.ImportScanResult() as any
    if (!r?.document) {
      ElMessage.warning('未解析到有效文档')
      return
    }
    const facts: any[] = []
    for (const col of (r.document.collectors || [])) {
      if (col.facts) facts.push(...col.facts)
    }
    let apiServer = ''
    let token = ''
    let ns = ''
    let caData = ''
    for (const f of facts) {
      if (f.id?.startsWith('k8s_context') && f.value?.apiServer) {
        apiServer = f.value.apiServer
      }
      if (f.id === 'serviceaccount.mounted' && f.value) {
        if (f.value.token?.content) token = f.value.token.content
        if (f.value.namespace?.content) ns = f.value.namespace.content
        if (f.value['ca.crt']?.content) caData = f.value['ca.crt'].content
      }
    }
    if (!apiServer && !token) {
      ElMessage.warning('扫描结果中未找到 apiServer / token 字段')
      return
    }
    tab.value = 'token'
    if (apiServer) form.apiServer = apiServer
    if (token) form.token = token
    if (ns) form.namespace = ns
    if (caData) form.caData = caData
    form.insecure = !caData
    if (!form.name) form.name = r.source || 'scan-import'
    ElMessage.success('已从扫描结果提取连接信息')
  } catch (e: any) {
    if (e?.message?.includes('cancel')) return
    ElMessage.error(`导入失败: ${e?.message || e}`)
  } finally {
    importing.value = false
  }
}

async function pickKubeconfig() {
  try {
    const r = (await api.OpenKubeconfigDialog()) as { path?: string; content?: string }
    if (r?.path) {
      form.kubeconfigPath = r.path
      form.kubeconfigContent = r.content || ''
      if (!form.name) {
        const base = r.path.split('/').pop() || 'kubeconfig'
        form.name = base
      }
    }
  } catch (e: any) {
    ElMessage.error(`选取文件失败: ${e?.message || e}`)
  }
}

function buildDTO(opts: { withPrefix?: boolean } = { withPrefix: true }) {
  const dto: any = {
    name: form.name || 'unnamed',
    type: tab.value,
    namespace: form.namespace,
  }
  if (tab.value === 'kubeconfig') {
    dto.kubeconfigContent = form.kubeconfigContent
  } else {
    dto.apiServer = form.apiServer
    dto.token = form.token
    dto.caData = form.caData
    dto.insecure = form.insecure
  }
  if (opts.withPrefix) dto.apiPathPrefix = form.apiPathPrefix
  return dto
}

async function scanExtensions() {
  scanning.value = true
  extensions.value = []
  try {
    extensions.value = ((await api.ListClusterExtensions(buildDTO({ withPrefix: false }))) as any[]) || []
    if (extensions.value.length === 0) {
      ElMessage.warning('未发现 ClusterExtension（hub 可能未启用兼容代理 CRD）')
    } else {
      ElMessage.success(`发现 ${extensions.value.length} 个 ClusterExtension`)
    }
  } catch (e: any) {
    ElMessage.error(`扫描失败: ${e?.message || e}`)
  } finally {
    scanning.value = false
  }
}

function applyExtension(ext: any) {
  form.apiPathPrefix = ext.proxyPath
  if (!form.name || form.name === 'unnamed') form.name = ext.name
}

async function test() {
  testing.value = true
  try {
    const v = (await api.TestConnection(buildDTO())) as string
    ElMessage.success(`连接成功，apiserver 版本 ${v}`)
  } catch (e: any) {
    ElMessage.error(`连接失败: ${e?.message || e}`)
  } finally {
    testing.value = false
  }
}

async function save() {
  saving.value = true
  try {
    await api.SaveCluster(buildDTO())
    ElMessage.success('已保存')
    emit('saved')
  } catch (e: any) {
    ElMessage.error(`保存失败: ${e?.message || e}`)
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <el-tabs v-model="tab" type="card">
    <!-- ============================ kubeconfig ============================ -->
    <el-tab-pane label="kubeconfig 文件" name="kubeconfig">
      <el-form label-width="130px" size="default">
        <el-form-item label="显示名">
          <el-input v-model="form.name" placeholder="kind-test" />
        </el-form-item>
        <el-form-item label="kubeconfig">
          <el-button @click="pickKubeconfig">
            <el-icon style="margin-right:4px"><FolderOpened /></el-icon>选择文件
          </el-button>
          <span v-if="form.kubeconfigPath" class="kg-inline-hint">
            {{ form.kubeconfigPath }} · {{ form.kubeconfigContent.length }} B
          </span>
        </el-form-item>
        <el-form-item label="默认 namespace">
          <el-input v-model="form.namespace" placeholder="留空则用 kubeconfig 当前 context 的 ns" />
        </el-form-item>
      </el-form>
    </el-tab-pane>

    <!-- ============================ SA Token ============================ -->
    <el-tab-pane label="SA Token + apiserver" name="token">
      <el-form label-width="130px" size="default">
        <el-form-item label="从扫描结果导入">
          <el-button :loading="importing" size="small" @click="importFromScan">
            <el-icon style="margin-right:4px"><Upload /></el-icon>选择扫描结果 JSON
          </el-button>
          <span class="kg-inline-hint">自动提取 token / apiserver / namespace</span>
        </el-form-item>
        <el-form-item label="显示名">
          <el-input v-model="form.name" placeholder="prod-pwn" />
        </el-form-item>
        <el-form-item label="apiserver URL">
          <el-input v-model="form.apiServer" placeholder="https://10.0.0.1:6443" />
        </el-form-item>
        <el-form-item label="Bearer Token">
          <el-input v-model="form.token" type="textarea" :rows="3" placeholder="eyJhbGciOi..." />
        </el-form-item>
        <el-form-item label="CA 数据">
          <el-input
            v-model="form.caData"
            type="textarea"
            :rows="3"
            placeholder="PEM 或 base64；留空且勾选 insecure 则跳过校验"
          />
        </el-form-item>
        <el-form-item label="insecure-tls">
          <el-switch v-model="form.insecure" />
          <span class="kg-inline-hint">跳过证书校验（红队场景常用）</span>
        </el-form-item>
        <el-form-item label="默认 namespace">
          <el-input v-model="form.namespace" placeholder="default" />
        </el-form-item>
      </el-form>
    </el-tab-pane>
  </el-tabs>

  <el-divider>聚合网关 / Hub Proxy（可选）</el-divider>
  <el-form label-width="130px" size="default">
    <el-form-item label="API 路径前缀">
      <el-input
        v-model="form.apiPathPrefix"
        type="textarea"
        :rows="2"
        placeholder="留空 = 直连。示例：/apis/cluster.example.io/v1/clusterextensions/example-cluster/proxy"
      />
    </el-form-item>
    <el-form-item label=" ">
      <el-button :loading="scanning" size="small" @click="scanExtensions">
        <el-icon style="margin-right:4px"><Search /></el-icon>扫描 ClusterExtension
      </el-button>
      <span class="kg-inline-hint">先填好 hub 的 kubeconfig / token+URL，再点扫描</span>
    </el-form-item>
  </el-form>

  <el-table
    v-if="extensions.length"
    :data="extensions"
    size="small"
    stripe
    max-height="200"
    style="margin-bottom:12px"
  >
    <el-table-column prop="name" label="名称" min-width="180" />
    <el-table-column prop="endpoint" label="endpoint" min-width="240" show-overflow-tooltip />
    <el-table-column prop="status" label="状态" width="100" />
    <el-table-column label="操作" width="100" align="right">
      <template #default="{ row }">
        <el-button size="small" type="primary" link @click="applyExtension(row)">选用</el-button>
      </template>
    </el-table-column>
  </el-table>

  <div class="kg-actions">
    <el-button @click="emit('cancel')">取消</el-button>
    <el-button :loading="testing" @click="test">测试连接</el-button>
    <el-button type="primary" :loading="saving" @click="save">保存</el-button>
  </div>
</template>

<style scoped>
.kg-inline-hint {
  margin-left: 10px;
  color: var(--kg-text-dim);
  font-size: 12px;
}
</style>
