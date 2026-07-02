<script setup lang="ts">
import { ref, reactive, computed, watch, onMounted } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index'
import { ElMessageBox } from 'element-plus/es/components/message-box/index'
import { Coin, Timer, Key, Brush, Delete, DocumentCopy, Download } from '@element-plus/icons-vue'
import { api } from '../api/wails'
import {
  persistenceCatalog,
  persistenceSearchText,
  riskVariant,
  riskLabel,
  categoryLabel,
  type PersistenceTechniqueCard,
} from '../data/persistenceCatalog'

const props = defineProps<{ clusterId: string }>()

// --- State ---
const filter = ref('')
const selectedTechnique = ref<PersistenceTechniqueCard | null>(null)
const createdResources = ref<any[]>([])
const operationResult = ref<Record<string, any> | null>(null)
const loading = ref(false)
const formValues = reactive<Record<string, any>>({})
const viewingResource = ref<any | null>(null)
const credentialLoading = ref(false)
const credentialResult = ref<Record<string, any> | null>(null)

// --- Derived ---
const filteredCatalog = computed(() => {
  const kw = filter.value.trim().toLowerCase()
  return persistenceCatalog.filter((c) => !kw || persistenceSearchText(c).includes(kw))
})

const matchingResources = computed(() => {
  if (!selectedTechnique.value) return []
  return createdResources.value.filter(
    (r) => r.technique === selectedTechnique.value!.technique,
  )
})

// --- Lifecycle ---
onMounted(() => {
  loadResources()
})

// --- Catalog from backend (for runtime technique list) ---
async function loadResources() {
  try {
    const resources = await api.ListPersistenceResources(props.clusterId)
    createdResources.value = resources || []
  } catch (e: any) {
    // Silently fail on load - resources list just stays empty.
    createdResources.value = []
  }
}

// --- Selection ---
function selectTechnique(card: PersistenceTechniqueCard) {
  selectedTechnique.value = card
  operationResult.value = null
  viewingResource.value = null
  credentialResult.value = null
  // Reset form to defaults.
  for (const p of card.parameters) {
    formValues[p.key] = p.defaultValue
  }
}

// --- Execution ---
async function executeTechnique() {
  const card = selectedTechnique.value
  if (!card) return

  // Confirmation for medium/high risk.
  if (card.requiresConfirm) {
    try {
      await ElMessageBox.confirm(
        buildRiskConfirmMessage(card),
        `确认执行${riskLabel(card.riskLevel)}操作 - ${card.label}`,
        {
          confirmButtonText: '我已理解，执行',
          cancelButtonText: '取消',
          type: card.riskLevel === 'high' ? 'error' : 'warning',
        },
      )
    } catch {
      return // User cancelled.
    }
  }

  loading.value = true
  operationResult.value = null

  try {
    const result = await dispatchTechnique(card, formValues)
    operationResult.value = result
    if (result?.success || result?.token || result?.kubeconfig) {
      ElMessage.success(`${card.label} 执行成功`)
    } else if (result?.error) {
      ElMessage.warning(result.error)
    }
    await loadResources()
  } catch (e: any) {
    operationResult.value = { technique: card.technique, success: false, error: String(e) }
    ElMessage.error(String(e))
  } finally {
    loading.value = false
  }
}

function buildRiskConfirmMessage(card: PersistenceTechniqueCard): string {
  const lines = [
    `即将执行「${card.label}」。`,
    '',
    '该操作会在当前集群中创建或修改资源，可能影响工作负载调度、凭据继承、审计告警或后续清理。',
    '如果你不清楚这个功能的用途、会改动哪些资源，或不确定如何回滚，请先取消并查看说明。',
  ]
  if (card.riskNotes?.length) {
    lines.push('', '风险提示：', ...card.riskNotes.map((note) => `- ${note}`))
  }
  lines.push('', '确认已理解影响后再继续执行。')
  return lines.join('\n')
}

async function dispatchTechnique(card: PersistenceTechniqueCard, params: Record<string, any>): Promise<Record<string, any>> {
  switch (card.technique) {
    case 'serviceaccount':
      return await api.CreatePersistenceSA(props.clusterId, {
        name: String(params.name || 'kubetrail-admin'),
        namespace: String(params.namespace || 'default'),
        clusterAdmin: Boolean(params.clusterAdmin ?? true),
      })
    case 'shadow-kubeconfig':
      return await api.GenerateShadowKubeconfig(props.clusterId, {
        name: String(params.name || 'kubetrail-shadow'),
        namespace: String(params.namespace || 'default'),
        clusterAdmin: true,
      })
    case 'token-request':
      return await api.RequestSAToken(props.clusterId, {
        saName: String(params.saName || 'default'),
        namespace: String(params.namespace || 'default'),
        durationSeconds: Number(params.durationSeconds || 3600),
      })
    case 'cronjob':
      return await api.CreatePersistenceCronJob(props.clusterId, {
        name: String(params.name || 'kubetrail-persist'),
        namespace: String(params.namespace || 'default'),
        schedule: String(params.schedule || '*/30 * * * *'),
        image: String(params.image || 'busybox:stable'),
        command: shellCommand(String(params.command || '/bin/sh -c echo persistence-ok')),
      })
    case 'deployment':
      return await api.CreatePersistenceDeployment(props.clusterId, {
        name: String(params.name || 'kubetrail-backdoor'),
        namespace: String(params.namespace || 'default'),
        image: String(params.image || 'busybox:stable'),
        command: shellCommand(String(params.command || '/bin/sh -c while true; do sleep 3600; done')),
      })
    case 'daemonset':
      return await api.CreatePersistenceDaemonSet(props.clusterId, {
        name: String(params.name || 'kubetrail-node-agent'),
        namespace: String(params.namespace || 'default'),
        image: String(params.image || 'busybox:stable'),
        command: shellCommand(String(params.command || '/bin/sh -c while true; do sleep 3600; done')),
      })
    case 'pull-secret':
      return await api.InjectPullSecret(props.clusterId, String(params.namespace || 'default'))
    default:
      throw new Error(`Unknown technique: ${card.technique}`)
  }
}

function shellCommand(value: string): string[] {
  const trimmed = value.trim()
  if (!trimmed) return []
  const shellPrefix = /^\/bin\/sh\s+-c\s+/
  const command = trimmed.replace(shellPrefix, '')
  return ['/bin/sh', '-c', command]
}

// --- Delete ---
async function deleteResource(resource: any) {
  const label = resource.detail || `${resource.technique}/${resource.resourceName}`
  try {
    await ElMessageBox.confirm(`确认删除 ${label}？此操作不可撤销。`, '确认删除', {
      confirmButtonText: '删除',
      cancelButtonText: '取消',
      type: 'warning',
    })
  } catch {
    return
  }

  try {
    await api.DeletePersistenceResource(
      props.clusterId,
      resource.technique,
      resource.namespace || '',
      resource.resourceName,
    )
    ElMessage.success(`已删除 ${label}`)
    // If selected technique matches, clear result.
    if (selectedTechnique.value?.technique === resource.technique) {
      operationResult.value = null
    }
    await loadResources()
  } catch (e: any) {
    ElMessage.error(`删除失败: ${e}`)
  }
}

// --- View Resource Credential ---
async function viewResource(res: any) {
  viewingResource.value = res
  credentialResult.value = null
  selectedTechnique.value = null
  operationResult.value = null

  // For SA and shadow-kubeconfig types, fetch the token/kubeconfig.
  if (res.technique === 'serviceaccount' || res.technique === 'shadow-kubeconfig') {
    credentialLoading.value = true
    try {
      const kc = await api.GetSAKubeconfig(props.clusterId, res.namespace || 'default', res.resourceName)
      credentialResult.value = kc
    } catch (e: any) {
      credentialResult.value = { error: String(e) }
    } finally {
      credentialLoading.value = false
    }
  }
}

// --- Copy & Save ---
async function copyText(value: string, msg = '已复制') {
  try {
    await navigator.clipboard.writeText(value)
    ElMessage.success(msg)
  } catch {
    ElMessage.error('复制失败，请手动选取')
  }
}

async function saveKubeconfigFile() {
  if (!operationResult.value) return
  try {
    await api.SaveKubeconfigFile(operationResult.value as any)
    ElMessage.success('Kubeconfig 已保存')
  } catch (e: any) {
    ElMessage.error(String(e))
  }
}

function formatExpiresAt(ts: string): string {
  if (!ts) return ''
  return new Date(ts).toLocaleString()
}

// --- Icon ---
function techIcon(technique: string) {
  switch (technique) {
    case 'serviceaccount':
    case 'shadow-kubeconfig':
      return Key
    case 'cronjob':
    case 'token-request':
      return Timer
    case 'deployment':
    case 'daemonset':
      return Coin
    case 'pull-secret':
      return Download
    default:
      return Brush
  }
}
</script>

<template>
  <div class="persist">
    <!-- LEFT RAIL -->
    <aside class="persist-rail">
      <div class="persist-search">
        <input v-model="filter" placeholder="搜索持久化手法..." />
        <span v-if="filter" class="persist-search__count">{{ filteredCatalog.length }}</span>
      </div>

      <div class="persist-rail__body">
        <!-- Technique Catalog -->
        <div class="persist-group">
          <div
            v-for="card in filteredCatalog"
            :key="card.id"
            class="persist-item"
            :class="{
              'is-active': selectedTechnique?.id === card.id,
              [`is-${riskVariant(card.riskLevel)}`]: true,
            }"
            @click="selectTechnique(card)"
          >
            <div class="persist-item__head">
              <component :is="techIcon(card.technique)" class="persist-item__icon" />
              <span class="persist-item__label">{{ card.label }}</span>
            </div>
            <div class="persist-item__meta">
              <span class="persist-item__tag" :class="`is-${riskVariant(card.riskLevel)}`">
                {{ riskLabel(card.riskLevel) }}
              </span>
              <span class="persist-item__cat">{{ categoryLabel(card.category) }}</span>
            </div>
          </div>
          <div v-if="!filteredCatalog.length" class="persist-rail__empty">无匹配手法</div>
        </div>

        <!-- Created Resources -->
        <div v-if="createdResources.length" class="persist-resources">
          <div class="persist-resources__head">
            <span>已创建资源</span>
            <span class="persist-resources__count">{{ createdResources.length }}</span>
          </div>
          <button
            v-for="res in createdResources"
            :key="res.id"
            class="persist-resource"
            :class="{ 'is-active': viewingResource?.id === res.id }"
            @click="viewResource(res)"
          >
            <component :is="techIcon(res.technique)" class="persist-resource__icon" />
            <div class="persist-resource__body">
              <span class="persist-resource__name">{{ res.resourceName }}</span>
              <span class="persist-resource__detail">{{ res.technique }}</span>
            </div>
            <button class="persist-resource__del" title="删除" @click.stop="deleteResource(res)">
              <Delete />
            </button>
          </button>
        </div>
      </div>
    </aside>

    <!-- RIGHT PANE -->
    <section class="persist-pane">
      <!-- Viewing Created Resource -->
      <template v-if="viewingResource">
        <header class="persist-pane__head">
          <component :is="techIcon(viewingResource.technique)" class="persist-pane__icon" />
          <div class="persist-pane__title">
            <div class="persist-pane__name">{{ viewingResource.resourceName }}</div>
            <div class="persist-pane__desc">{{ viewingResource.detail }}</div>
          </div>
          <span class="persist-badge is-safe">{{ viewingResource.technique }}</span>
        </header>

        <!-- SA / Shadow Kubeconfig: show token + kubeconfig -->
        <template v-if="viewingResource.technique === 'serviceaccount' || viewingResource.technique === 'shadow-kubeconfig'">
          <div v-if="credentialLoading" class="persist-result__title" style="color: var(--kg-text-muted)">
            加载凭据中...
          </div>
          <template v-else-if="credentialResult?.kubeconfig">
            <div class="persist-result">
              <div class="persist-result__title">🔑 访问凭据</div>
              <div class="persist-result__row">
                <span class="persist-result__label">Token</span>
                <code class="persist-result__token">{{ credentialResult.token?.substring(0, 60) }}...</code>
                <button class="persist-mini-btn" @click="copyText(credentialResult.token, 'Token 已复制')">
                  <DocumentCopy /> 复制 Token
                </button>
              </div>
              <div class="persist-result__row">
                <span class="persist-result__label">Kubeconfig</span>
                <pre class="persist-result__pre">{{ credentialResult.kubeconfig }}</pre>
              </div>
              <div class="persist-result__actions">
                <button class="persist-mini-btn" @click="copyText(credentialResult.kubeconfig, 'Kubeconfig 已复制')">
                  <DocumentCopy /> 复制 Kubeconfig
                </button>
                <button class="persist-mini-btn" @click="api.SaveKubeconfigFile(credentialResult as any)">
                  <Download /> 保存文件
                </button>
              </div>
            </div>
          </template>
          <template v-else-if="credentialResult?.error">
            <div class="persist-result">
              <div class="persist-result__title is-error">❌ 获取凭据失败</div>
              <div class="persist-result__row">
                <span class="persist-result__value is-error">{{ credentialResult.error }}</span>
              </div>
            </div>
          </template>
        </template>

        <!-- Workload types: show info -->
        <template v-else>
          <div class="persist-section">
            <div class="persist-section__title">资源详情</div>
            <div class="persist-form">
              <div class="persist-form__row">
                <span class="persist-form__label">类型</span>
                <span style="font-size:12px;color:var(--kg-text)">{{ viewingResource.technique }}</span>
              </div>
              <div class="persist-form__row">
                <span class="persist-form__label">名称</span>
                <span style="font-size:12px;color:var(--kg-text);font-family:var(--kg-font-mono)">{{ viewingResource.resourceName }}</span>
              </div>
              <div class="persist-form__row" v-if="viewingResource.namespace">
                <span class="persist-form__label">命名空间</span>
                <span style="font-size:12px;color:var(--kg-text);font-family:var(--kg-font-mono)">{{ viewingResource.namespace }}</span>
              </div>
              <div class="persist-form__row" v-if="viewingResource.createdAt">
                <span class="persist-form__label">创建时间</span>
                <span style="font-size:12px;color:var(--kg-text-muted)">{{ new Date(viewingResource.createdAt).toLocaleString() }}</span>
              </div>
              <div class="persist-form__row" v-if="viewingResource.status">
                <span class="persist-form__label">状态</span>
                <span class="persist-perm is-safe">{{ viewingResource.status }}</span>
              </div>
            </div>
          </div>
        </template>

        <div style="display:flex;gap:8px;padding-top:4px">
          <button class="persist-mini-btn is-danger" @click="deleteResource(viewingResource); viewingResource = null; credentialResult = null">
            <Delete /> 删除此资源
          </button>
        </div>
      </template>

      <template v-if="selectedTechnique">
        <!-- Header -->
        <header class="persist-pane__head">
          <span class="persist-badge" :class="`is-${riskVariant(selectedTechnique.riskLevel)}`">
            {{ riskLabel(selectedTechnique.riskLevel) }}
          </span>
          <span class="persist-cat-tag">{{ categoryLabel(selectedTechnique.category) }}</span>
          <div class="persist-pane__title">
            <div class="persist-pane__name">{{ selectedTechnique.label }}</div>
            <div class="persist-pane__desc">{{ selectedTechnique.description }}</div>
          </div>
        </header>

        <!-- Permission Checks -->
        <div class="persist-section">
          <div class="persist-section__title">所需权限</div>
          <div class="persist-perms">
            <span v-for="p in selectedTechnique.permissions" :key="p" class="persist-perm">
              {{ p }}
            </span>
          </div>
        </div>

        <!-- Parameters Form -->
        <div class="persist-section">
          <div class="persist-section__title">参数</div>
          <div class="persist-form">
            <div
              v-for="param in selectedTechnique.parameters"
              :key="param.key"
              class="persist-form__row"
            >
              <label class="persist-form__label">{{ param.label }}</label>
              <template v-if="param.type === 'boolean'">
                <el-switch v-model="formValues[param.key]" size="small" />
              </template>
              <template v-else>
                <input
                  v-model="formValues[param.key]"
                  class="persist-form__input"
                  :placeholder="param.placeholder || ''"
                  :type="param.type === 'number' ? 'number' : 'text'"
                />
              </template>
            </div>
          </div>
        </div>

        <!-- Risk Notes -->
        <div v-if="selectedTechnique.riskNotes?.length" class="persist-section">
          <div class="persist-section__title">注意事项</div>
          <ul class="persist-notes">
            <li v-for="note in selectedTechnique.riskNotes" :key="note">{{ note }}</li>
          </ul>
        </div>

        <!-- Execute Button -->
        <div class="persist-actions">
          <button
            class="persist-btn"
            :class="`is-${riskVariant(selectedTechnique.riskLevel)}`"
            :disabled="loading"
            @click="executeTechnique"
          >
            {{ loading ? '执行中...' : `执行 - ${selectedTechnique.label}` }}
          </button>
        </div>

        <!-- Result -->
        <div v-if="operationResult" class="persist-result">
          <!-- Shadow Kubeconfig Result -->
          <template v-if="operationResult.kubeconfig">
            <div class="persist-result__title">✅ 影子 Kubeconfig 已生成</div>
            <div class="persist-result__row">
              <span class="persist-result__label">SA</span>
              <span class="persist-result__value">
                {{ operationResult.sa }} / {{ operationResult.namespace }}
              </span>
            </div>
            <div class="persist-result__row">
              <span class="persist-result__label">Token</span>
              <code class="persist-result__token">{{ operationResult.token?.substring(0, 40) }}...</code>
              <button class="persist-mini-btn" @click="copyText(operationResult.token, 'Token 已复制')">
                复制
              </button>
            </div>
            <pre class="persist-result__pre">{{ operationResult.kubeconfig }}</pre>
            <div class="persist-result__actions">
              <button class="persist-mini-btn" @click="copyText(operationResult.kubeconfig, 'Kubeconfig 已复制')">
                <DocumentCopy /> 复制
              </button>
              <button class="persist-mini-btn" @click="saveKubeconfigFile">
                <Download /> 保存文件
              </button>
            </div>
          </template>

          <!-- Token Request Result -->
          <template v-else-if="operationResult.token && !operationResult.kubeconfig">
            <div class="persist-result__title">✅ Token 已生成</div>
            <div class="persist-result__row">
              <span class="persist-result__label">过期时间</span>
              <span class="persist-result__value">{{ formatExpiresAt(operationResult.expiresAt) }}</span>
            </div>
            <pre class="persist-result__pre">{{ operationResult.token }}</pre>
            <button class="persist-mini-btn" @click="copyText(operationResult.token, 'Token 已复制')">
              复制 Token
            </button>
          </template>

          <!-- PersistenceResult -->
          <template v-else>
            <div
              class="persist-result__title"
              :class="operationResult.success ? '' : 'is-error'"
            >
              {{ operationResult.success ? '✅ 执行成功' : '❌ 执行失败' }}
            </div>
            <div v-if="operationResult.detail" class="persist-result__row">
              <span class="persist-result__label">详情</span>
              <span class="persist-result__value">{{ operationResult.detail }}</span>
            </div>
            <div v-if="operationResult.resourceName" class="persist-result__row">
              <span class="persist-result__label">资源名称</span>
              <span class="persist-result__value">{{ operationResult.resourceName }}</span>
            </div>
            <div v-if="operationResult.namespace" class="persist-result__row">
              <span class="persist-result__label">命名空间</span>
              <span class="persist-result__value">{{ operationResult.namespace }}</span>
            </div>
            <div v-if="operationResult.error" class="persist-result__row">
              <span class="persist-result__label">错误</span>
              <span class="persist-result__value is-error">{{ operationResult.error }}</span>
            </div>
            <div
              v-if="operationResult.permissions && Object.keys(operationResult.permissions).length"
              class="persist-result__row"
            >
              <span class="persist-result__label">权限检查</span>
              <div class="persist-perms">
                <span
                  v-for="(allowed, perm) in operationResult.permissions"
                  :key="perm"
                  class="persist-perm"
                  :class="allowed ? '' : 'is-denied'"
                >
                  {{ allowed ? '✓' : '✗' }} {{ perm }}
                </span>
              </div>
            </div>
          </template>
        </div>

        <!-- Matching Created Resources -->
        <div
          v-if="matchingResources.length && !operationResult?.kubeconfig"
          class="persist-result"
        >
          <div class="persist-result__title">已创建的同类型资源</div>
          <div v-for="res in matchingResources" :key="res.id" class="persist-result__row">
            <span class="persist-result__value">{{ res.detail }}</span>
            <button class="persist-mini-btn is-danger" @click="deleteResource(res)">删除</button>
          </div>
        </div>
      </template>

      <!-- Placeholder -->
      <template v-else>
        <div class="persist-pane__placeholder">从左侧选择持久化手法</div>
      </template>
    </section>
  </div>
</template>

<style scoped>
.persist {
  display: flex;
  height: 100%;
  min-height: 0;
  gap: 1px;
  background: var(--kg-border);
  border: 1px solid var(--kg-border);
  border-radius: 8px;
  overflow: hidden;
}

/* Rail */
.persist-rail {
  width: 280px;
  min-width: 220px;
  display: flex;
  flex-direction: column;
  background: color-mix(in srgb, var(--kg-surface) 80%, var(--kg-bg));
}
.persist-search {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 10px;
  border-bottom: 1px solid var(--kg-border);
  background: var(--kg-surface);
}
.persist-search input {
  flex: 1;
  min-width: 0;
  background: var(--kg-bg);
  border: 1px solid var(--kg-border);
  border-radius: 6px;
  padding: 7px 9px;
  color: var(--kg-text);
  font-size: 12px;
  outline: none;
}
.persist-search input:focus {
  border-color: var(--kg-accent);
  box-shadow: 0 0 0 3px var(--kg-accent-ring);
}
.persist-search__count {
  font-size: 10px;
  color: var(--kg-text-muted);
  min-width: 18px;
  text-align: center;
}
.persist-rail__body {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  padding: 6px;
}
.persist-rail__empty {
  padding: 20px;
  text-align: center;
  color: var(--kg-text-dim);
  font-size: 12px;
}

/* Catalog Items */
.persist-item {
  position: relative;
  display: flex;
  flex-direction: column;
  width: 100%;
  text-align: left;
  padding: 10px 9px 10px 11px;
  margin-bottom: 2px;
  border: 1px solid transparent;
  border-radius: 7px;
  background: transparent;
  cursor: pointer;
  transition: background 0.15s ease, border-color 0.15s ease;
}
.persist-item:hover {
  background: var(--kg-surface);
  border-color: var(--kg-border);
}
.persist-item.is-active {
  border-color: color-mix(in srgb, var(--kg-accent) 58%, var(--kg-border));
  box-shadow: inset 2px 0 0 var(--kg-accent);
}
.persist-item.is-active.is-full {
  border-color: color-mix(in srgb, var(--kg-warn) 58%, var(--kg-border));
  box-shadow: inset 2px 0 0 var(--kg-warn);
}
.persist-item.is-active.is-dangerous {
  border-color: color-mix(in srgb, var(--kg-danger) 58%, var(--kg-border));
  box-shadow: inset 2px 0 0 var(--kg-danger);
}
.persist-item__head {
  display: flex;
  align-items: center;
  gap: 6px;
}
.persist-item__icon {
  width: 16px;
  height: 16px;
  color: var(--kg-text-muted);
  flex-shrink: 0;
}
.persist-item.is-active .persist-item__icon,
.persist-item:hover .persist-item__icon {
  color: var(--kg-text);
}
.persist-item__label {
  font-size: 12px;
  color: var(--kg-text);
  line-height: 1.3;
}
.persist-item__meta {
  display: flex;
  gap: 6px;
  margin-top: 4px;
  margin-left: 22px;
}
.persist-item__tag {
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 9px;
  font-weight: 700;
  text-transform: uppercase;
}
.persist-item__tag.is-safe {
  background: var(--kg-accent);
  color: #fff;
}
.persist-item__tag.is-full {
  background: var(--kg-warn);
  color: #fff;
}
.persist-item__tag.is-dangerous {
  background: var(--kg-danger);
  color: #fff;
}
.persist-item__cat {
  font-size: 9px;
  color: var(--kg-text-dim);
}

/* Resources */
.persist-resources {
  margin-top: 12px;
  padding-top: 10px;
  border-top: 1px solid var(--kg-border);
}
.persist-resources__head {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 8px;
  font-size: 10px;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--kg-text-muted);
}
.persist-resources__count {
  margin-left: auto;
  background: var(--kg-surface-2);
  border-radius: 4px;
  padding: 1px 5px;
  font-size: 9px;
}
.persist-resource {
  position: relative;
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  text-align: left;
  padding: 7px 9px;
  border: 1px solid transparent;
  border-radius: 6px;
  background: transparent;
  cursor: pointer;
}
.persist-resource:hover {
  background: var(--kg-surface);
  border-color: var(--kg-border);
}
.persist-resource.is-active {
  background: var(--kg-surface-2);
  border-color: color-mix(in srgb, var(--kg-accent) 58%, var(--kg-border));
  box-shadow: inset 2px 0 0 var(--kg-accent);
}
.persist-resource__icon {
  width: 14px;
  height: 14px;
  color: var(--kg-text-dim);
  flex-shrink: 0;
}
.persist-resource__body {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}
.persist-resource__name {
  font-size: 11px;
  color: var(--kg-text);
  font-family: var(--kg-font-mono);
}
.persist-resource__detail {
  font-size: 9px;
  color: var(--kg-text-dim);
}
.persist-resource__del {
  flex-shrink: 0;
  width: 22px;
  height: 22px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: none;
  border-radius: 4px;
  background: transparent;
  color: var(--kg-text-dim);
  cursor: pointer;
  opacity: 0;
  transition: opacity 0.15s;
}
.persist-resource:hover .persist-resource__del {
  opacity: 1;
}
.persist-resource__del:hover {
  background: color-mix(in srgb, var(--kg-danger) 18%, transparent);
  color: var(--kg-danger);
}
.persist-resource__del svg {
  width: 12px;
  height: 12px;
}

/* Pane */
.persist-pane {
  flex: 1;
  min-width: 0;
  min-height: 0;
  display: flex;
  flex-direction: column;
  background: var(--kg-bg);
  overflow-y: auto;
  padding: 16px;
  gap: 14px;
}
.persist-pane__placeholder {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: var(--kg-text-dim);
  font-size: 14px;
}
.persist-pane__icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
  color: var(--kg-accent);
}
.persist-pane__head {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding-bottom: 2px;
}
.persist-pane__title {
  flex: 1;
  min-width: 0;
}
.persist-pane__name {
  font-size: 15px;
  font-weight: 600;
  color: var(--kg-text);
}
.persist-pane__desc {
  font-size: 12px;
  color: var(--kg-text-muted);
  margin-top: 3px;
  line-height: 1.45;
}
.persist-badge {
  font-size: 10px;
  font-weight: 700;
  padding: 2px 6px;
  border-radius: 3px;
  text-transform: uppercase;
}
.persist-badge.is-safe {
  background: var(--kg-accent);
  color: #fff;
}
.persist-badge.is-full {
  background: var(--kg-warn);
  color: #fff;
}
.persist-badge.is-dangerous {
  background: var(--kg-danger);
  color: #fff;
}
.persist-cat-tag {
  font-size: 10px;
  padding: 2px 6px;
  border-radius: 3px;
  background: var(--kg-surface-2);
  color: var(--kg-text-muted);
}

/* Sections */
.persist-section {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 12px;
  border: 1px solid var(--kg-border);
  border-radius: 8px;
  background: color-mix(in srgb, var(--kg-surface) 78%, var(--kg-bg));
}
.persist-section__title {
  font-size: 13px;
  font-weight: 600;
  color: var(--kg-text);
}
.persist-perms {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.persist-perm {
  padding: 3px 8px;
  border-radius: 4px;
  background: color-mix(in srgb, var(--kg-accent) 14%, var(--kg-surface-2));
  color: var(--kg-accent);
  font-size: 11px;
  font-family: var(--kg-font-mono);
}
.persist-perm.is-denied {
  background: color-mix(in srgb, var(--kg-danger) 14%, var(--kg-surface-2));
  color: var(--kg-danger);
}

/* Form */
.persist-form {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.persist-form__row {
  display: grid;
  grid-template-columns: 140px minmax(0, 1fr);
  align-items: center;
  gap: 10px;
}
.persist-form__label {
  font-size: 12px;
  color: var(--kg-text-muted);
}
.persist-form__input {
  background: var(--kg-bg);
  border: 1px solid var(--kg-border);
  border-radius: 6px;
  padding: 7px 9px;
  color: var(--kg-text);
  font-size: 12px;
  font-family: var(--kg-font-mono);
  outline: none;
}
.persist-form__input:focus {
  border-color: var(--kg-accent);
  box-shadow: 0 0 0 3px var(--kg-accent-ring);
}

/* Notes */
.persist-notes {
  margin: 0;
  padding-left: 18px;
  font-size: 12px;
  color: var(--kg-text-muted);
  line-height: 1.55;
}
.persist-notes li {
  margin-bottom: 3px;
}

/* Actions */
.persist-actions {
  display: flex;
  gap: 8px;
}
.persist-btn {
  padding: 8px 20px;
  border: none;
  border-radius: 6px;
  color: #fff;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.15s;
}
.persist-btn:hover {
  opacity: 0.9;
}
.persist-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.persist-btn.is-safe {
  background: var(--kg-accent);
}
.persist-btn.is-full {
  background: var(--kg-warn);
}
.persist-btn.is-dangerous {
  background: var(--kg-danger);
}

/* Result */
.persist-result {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 12px;
  border-radius: 8px;
  background: var(--kg-surface);
  border: 1px solid var(--kg-accent);
}
.persist-result__title {
  font-size: 13px;
  font-weight: 600;
  color: var(--kg-accent);
}
.persist-result__title.is-error {
  color: var(--kg-danger);
}
.persist-result__row {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 12px;
}
.persist-result__label {
  font-weight: 600;
  color: var(--kg-text-muted);
}
.persist-result__value {
  font-family: var(--kg-font-mono);
  font-size: 11px;
  color: var(--kg-text);
  word-break: break-all;
}
.persist-result__value.is-error {
  color: var(--kg-danger);
}
.persist-result__token {
  font-family: var(--kg-font-mono);
  font-size: 11px;
  color: var(--kg-text);
  word-break: break-all;
  background: var(--kg-surface-2);
  padding: 6px 8px;
  border-radius: 4px;
}
.persist-result__pre {
  margin: 0;
  padding: 8px;
  border-radius: 4px;
  background: var(--kg-surface-2);
  font-family: var(--kg-font-mono);
  font-size: 11px;
  color: var(--kg-text);
  white-space: pre-wrap;
  word-break: break-all;
  overflow-x: auto;
  max-height: 320px;
  overflow-y: auto;
}
.persist-result__actions {
  display: flex;
  gap: 8px;
}
.persist-mini-btn {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  flex-shrink: 0;
  padding: 4px 10px;
  border: 1px solid var(--kg-border);
  border-radius: 5px;
  background: var(--kg-bg);
  color: var(--kg-text);
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
  width: fit-content;
}
.persist-mini-btn:hover {
  border-color: var(--kg-accent);
  color: var(--kg-accent);
}
.persist-mini-btn.is-danger:hover {
  border-color: var(--kg-danger);
  color: var(--kg-danger);
  background: color-mix(in srgb, var(--kg-danger) 10%, var(--kg-bg));
}
.persist-mini-btn svg {
  width: 12px;
  height: 12px;
}

@media (max-width: 900px) {
  .persist {
    flex-direction: column;
  }
  .persist-rail {
    width: auto;
    max-height: 280px;
  }
  .persist-form__row {
    grid-template-columns: 1fr;
    align-items: stretch;
  }
}
</style>
