<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { api } from '../api/wails'
import { useAgentStore } from '../stores/agent'
import { currentLocale, setLocale, t, type Locale } from '../i18n'

const agentStore = useAgentStore()

const provider = ref<'claude' | 'codex'>('claude')
const language = ref<Locale>(currentLocale.value)
const apiKey = ref('')
const baseUrl = ref('')
const model = ref('')
const proxy = ref('')
const claudePath = ref('')
const codexPath = ref('')
const allowMaterialize = ref(false)
const customEnvText = ref('')
const saving = ref(false)
const testing = ref(false)
const runtimeLoading = ref(false)
const testResult = ref<{ ok: boolean; msg: string } | null>(null)
const logs = ref<string[]>([])
const runtimeInfo = ref<any>(null)
const mcpServers = ref<McpServerForm[]>([])
const editingMcpIndex = ref(-1)
const mcpDraft = ref<McpServerForm>(emptyMcpDraft())
const activeTab = ref('agent')

type McpServerForm = {
  name: string
  type: 'stdio' | 'http' | 'sse'
  command: string
  argsText: string
  url: string
  envText: string
  headersText: string
  timeout: number
  alwaysLoad: boolean
}

onMounted(async () => {
  try {
    const status = await api.GetAgentStatus()
    agentStore.setStatus(status as any)
    const cfg = await api.GetAgentDisplayConfig()
    if (cfg) {
      provider.value = ((cfg as any).provider === 'codex' ? 'codex' : 'claude')
      apiKey.value = (cfg as any).apiKey || ''
      baseUrl.value = (cfg as any).baseUrl || ''
      model.value = (cfg as any).model || ''
      proxy.value = (cfg as any).proxy || ''
      claudePath.value = (cfg as any).claudePath || ''
      codexPath.value = (cfg as any).codexPath || ''
      allowMaterialize.value = (cfg as any).allowMaterialize || false
      const envMap = (cfg as any).customEnv
      customEnvText.value = envMap && typeof envMap === 'object' && Object.keys(envMap).length ? JSON.stringify(envMap, null, 2) : ''
      mcpServers.value = Array.isArray((cfg as any).mcpServers) ? (cfg as any).mcpServers.map(mcpServerToForm).filter(Boolean) : []
    }
  } catch {}
  refreshRuntimeInfo()
  refreshLogs()
})

watch(language, (value) => {
  setLocale(value)
})

function buildConfig(): any {
  return {
    provider: provider.value,
    apiKey: apiKey.value,
    baseUrl: baseUrl.value,
    model: model.value,
    proxy: proxy.value,
    claudePath: claudePath.value,
    codexPath: codexPath.value,
    allowMaterialize: allowMaterialize.value,
    customEnv: parseObjectText(customEnvText.value.trim(), t('自定义环境变量')),
    mcpServers: mcpServersForSave(),
  }
}

function defaultModelForProvider(value: 'claude' | 'codex'): string {
  return value === 'codex' ? t('留空使用 Codex 默认模型') : t('留空使用 Claude Code 默认模型')
}

function onProviderChange(value: 'claude' | 'codex') {
  const oldDefaults = new Set([
    'claude-sonnet-4-6',
    'gpt-5.4',
    '留空使用 Codex 默认模型',
    '留空使用 Claude Code 默认模型',
    'Leave empty to use the Codex default model',
    'Leave empty to use the Claude Code default model',
  ])
  if (!model.value.trim() || oldDefaults.has(model.value.trim())) {
    model.value = ''
  }
  void value
}

function emptyMcpDraft(): McpServerForm {
  return {
    name: '',
    type: 'stdio',
    command: '',
    argsText: '',
    url: '',
    envText: '',
    headersText: '',
    timeout: 0,
    alwaysLoad: false,
  }
}

function mcpServerToForm(server: any): McpServerForm | null {
  if (!server || typeof server !== 'object') return null
  return {
    name: String(server.name || ''),
    type: ['stdio', 'http', 'sse'].includes(String(server.type)) ? String(server.type) as McpServerForm['type'] : 'stdio',
    command: String(server.command || ''),
    argsText: Array.isArray(server.args) ? server.args.join('\n') : '',
    url: String(server.url || ''),
    envText: server.env ? JSON.stringify(server.env, null, 2) : '',
    headersText: server.headers ? JSON.stringify(server.headers, null, 2) : '',
    timeout: Number(server.timeout) || 0,
    alwaysLoad: Boolean(server.alwaysLoad),
  }
}

function formToMcpServer(form: McpServerForm): any | null {
  const name = form.name.trim()
  if (!name) return null
  const base: any = {
    name,
    type: form.type,
    timeout: Number(form.timeout) || 0,
    alwaysLoad: form.alwaysLoad,
  }
  if (form.type === 'stdio') {
    base.command = form.command.trim()
    base.args = splitLines(form.argsText)
    base.env = parseObjectText(form.envText, 'Env JSON')
    if (!base.command) return null
  } else {
    base.url = form.url.trim()
    base.headers = parseObjectText(form.headersText, 'Headers JSON')
    if (!base.url) return null
  }
  return base
}

function hasMcpDraftContent(form: McpServerForm): boolean {
  return Boolean(
    form.name.trim() ||
    form.command.trim() ||
    form.argsText.trim() ||
    form.url.trim() ||
    form.envText.trim() ||
    form.headersText.trim() ||
    form.timeout ||
    form.alwaysLoad,
  )
}

function mcpServersForSave(): any[] {
  const forms = mcpServers.value.map(item => ({ ...item }))
  if (hasMcpDraftContent(mcpDraft.value)) {
    const server = formToMcpServer(mcpDraft.value)
    if (!server) {
      throw new Error(t('请先补全当前 MCP 草稿，或点击清空后再保存'))
    }
    if (!/^[A-Za-z0-9_-]{1,80}$/.test(server.name)) {
      throw new Error(t('MCP 名称只能包含字母、数字、-、_'))
    }
    const form = mcpServerToForm(server)!
    const index = editingMcpIndex.value >= 0
      ? editingMcpIndex.value
      : forms.findIndex(item => item.name === form.name)
    if (index >= 0) {
      forms.splice(index, 1, form)
    } else {
      forms.push(form)
    }
  }
  return forms.map(formToMcpServer).filter(Boolean)
}

function parseObjectText(text: string, label: string): Record<string, string> {
  const trimmed = text.trim()
  if (!trimmed) return {}
  const value = JSON.parse(trimmed)
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} ${t('必须是对象')}`)
  }
  const out: Record<string, string> = {}
  for (const [key, raw] of Object.entries(value)) {
    if (String(key).trim() && String(raw).trim()) out[String(key).trim()] = String(raw).trim()
  }
  return out
}

function splitLines(text: string): string[] {
  return text.split('\n').map(item => item.trim()).filter(Boolean)
}

function editMcp(index: number) {
  editingMcpIndex.value = index
  mcpDraft.value = { ...mcpServers.value[index] }
}

function resetMcpDraft() {
  editingMcpIndex.value = -1
  mcpDraft.value = emptyMcpDraft()
}

function upsertMcp() {
  try {
    const server = formToMcpServer(mcpDraft.value)
    if (!server) {
      ;(window as any).ElMessage?.warning?.(t('请完整填写 MCP 名称和连接信息'))
      return
    }
    if (!/^[A-Za-z0-9_-]{1,80}$/.test(server.name)) {
      ;(window as any).ElMessage?.warning?.(t('MCP 名称只能包含字母、数字、-、_'))
      return
    }
    const form = mcpServerToForm(server)!
    const duplicate = mcpServers.value.findIndex((item, index) => item.name === form.name && index !== editingMcpIndex.value)
    if (duplicate >= 0) {
      ;(window as any).ElMessage?.warning?.(t('MCP 名称已存在'))
      return
    }
    if (editingMcpIndex.value >= 0) {
      mcpServers.value.splice(editingMcpIndex.value, 1, form)
    } else {
      mcpServers.value.push(form)
    }
    resetMcpDraft()
  } catch (e: any) {
    ;(window as any).ElMessage?.error?.(String(e?.message || e))
  }
}

function removeMcp(index: number) {
  mcpServers.value.splice(index, 1)
  if (editingMcpIndex.value === index) resetMcpDraft()
}

async function save() {
  saving.value = true
  try {
    const config = buildConfig()
    await api.ConfigureAgent(config)
    const s = await api.GetAgentStatus()
    agentStore.setStatus(s as any)
    await refreshRuntimeInfo()
    ;(window as any).ElMessage?.success?.(t('配置已保存，Agent 已应用新配置'))
  } catch (e: any) {
    ;(window as any).ElMessage?.error?.(String(e))
  } finally {
    saving.value = false
  }
}

async function testConnection() {
  testing.value = true
  testResult.value = null
  try {
    const msg = await api.TestAgentConnection(buildConfig())
    testResult.value = { ok: true, msg: String(msg) }
    ;(window as any).ElMessage?.success?.(String(msg))
  } catch (e: any) {
    testResult.value = { ok: false, msg: String(e) }
    ;(window as any).ElMessage?.error?.(String(e))
  } finally {
    testing.value = false
  }
}

async function refreshRuntimeInfo() {
  runtimeLoading.value = true
  try {
    runtimeInfo.value = await api.CheckAgentRuntime(buildConfig())
  } catch (e: any) {
    runtimeInfo.value = { claudeAvailable: false, codexAvailable: false, claudeError: String(e), codexError: String(e) }
  } finally {
    runtimeLoading.value = false
  }
}

async function stopAgent() {
  try {
    await api.StopAgent()
    const s = await api.GetAgentStatus()
    agentStore.setStatus(s as any)
    ;(window as any).ElMessage?.info?.(t('Agent 已停止'))
  } catch (e: any) {
    ;(window as any).ElMessage?.error?.(String(e))
  }
}

async function restartAgent() {
  try {
    await api.RestartAgent()
    ;(window as any).ElMessage?.success?.(t('Agent 正在重启...'))
    setTimeout(async () => {
      const s = await api.GetAgentStatus()
      agentStore.setStatus(s as any)
    }, 3000)
  } catch (e: any) {
    ;(window as any).ElMessage?.error?.(String(e))
  }
}

async function refreshLogs() {
  try {
    const l = await api.AgentLogs()
    logs.value = l || []
  } catch {}
}
</script>

<template>
  <div class="settings-page">
    <div class="page-title">设置</div>

    <el-tabs v-model="activeTab" class="settings-tabs">
      <el-tab-pane label="Agent 配置" name="agent">
        <div class="tab-body">
          <el-form label-width="160px" size="default">
            <el-form-item label="Provider">
              <el-segmented
                v-model="provider"
                :options="[
                  { label: 'Claude Code', value: 'claude' },
                  { label: 'Codex', value: 'codex' },
                ]"
                @change="onProviderChange"
              />
            </el-form-item>
            <el-form-item label="API Key">
              <div class="field-stack">
                <el-input v-model="apiKey" type="password" show-password :placeholder="provider === 'codex' ? 'sk-...' : 'sk-ant-...'" style="max-width:400px" />
                <div class="field-hint">{{ provider === 'codex' ? '使用官方 Codex 时留空，使用本机 codex 登录态；自定义网关/API Key 才填写' : '使用官方 Claude Code 时留空，使用本机 claude 登录态；自定义网关/API Key 才填写' }}</div>
              </div>
            </el-form-item>
            <el-form-item label="Base URL">
              <div class="field-stack">
                <el-input v-model="baseUrl" :placeholder="provider === 'codex' ? 'https://api.openai.com (留空使用默认)' : 'https://api.anthropic.com (留空使用默认)'" style="max-width:400px" />
                <div class="field-hint">{{ provider === 'codex' ? '使用官方 Codex 时留空；只有接入自定义 OpenAI-compatible 网关时填写。' : '使用官方 Claude Code 时留空；只有接入自定义 Anthropic-compatible 网关时填写。' }}</div>
              </div>
            </el-form-item>
            <el-form-item label="Model">
              <el-input v-model="model" :placeholder="defaultModelForProvider(provider)" style="max-width:400px" />
            </el-form-item>
            <el-form-item label="Proxy">
              <el-input v-model="proxy" placeholder="http://proxy:8080 (可选)" style="max-width:400px" />
            </el-form-item>
            <el-form-item label="自定义环境变量">
              <div class="field-stack">
                <textarea
                  v-model="customEnvText"
                  class="custom-env-textarea"
                  rows="4"
                  spellcheck="false"
                  placeholder='{"MY_VAR":"value","ANOTHER":"value2"}'
                ></textarea>
                <div class="field-hint">JSON 格式，这些环境变量会透传给 Agent 子进程</div>
              </div>
            </el-form-item>
            <el-form-item label="Claude CLI">
              <div class="runtime-input">
                <el-input
                  v-model="claudePath"
                  placeholder="留空则自动从 PATH 发现 claude"
                  style="max-width:520px"
                />
                <el-button @click="refreshRuntimeInfo" :loading="runtimeLoading">检测</el-button>
              </div>
              <div class="runtime-hint">
                {{ runtimeInfo?.claudeAvailable ? `已发现 (${runtimeInfo.claudeSource || 'auto'}): ${runtimeInfo.claudePath}` : (runtimeInfo?.claudeError || '未检测') }}
              </div>
            </el-form-item>
            <el-form-item label="Codex CLI">
              <div class="runtime-input">
                <el-input
                  v-model="codexPath"
                  placeholder="留空自动从登录 Shell/PATH 发现；可填 /Users/ekkoo/.local/bin/codex"
                  style="max-width:520px"
                />
                <el-button @click="refreshRuntimeInfo" :loading="runtimeLoading">检测</el-button>
              </div>
              <div class="field-hint">官方 Codex 模式默认使用本机 ~/.codex；显式路径会优先于自动发现</div>
              <div class="runtime-hint">
                {{ runtimeInfo?.codexAvailable ? `可用 (${runtimeInfo.codexSource || 'sdk'}): ${runtimeInfo.codexPath}` : (runtimeInfo?.codexError || '未检测') }}
              </div>
            </el-form-item>
            <el-form-item label="允许 Materialize 敏感值">
              <el-switch v-model="allowMaterialize" />
              <span style="font-size:11px;color:var(--kg-text-muted);margin-left:8px">
                启用后 Agent 可解密显示 sensitive:// 引用的原始值
              </span>
            </el-form-item>
          </el-form>
        </div>
      </el-tab-pane>

      <el-tab-pane :label="t('界面语言')" name="language">
        <div class="tab-body">
          <el-form label-width="160px" size="default">
            <el-form-item :label="t('语言')">
              <div class="field-stack">
                <el-segmented
                  v-model="language"
                  :options="[
                    { label: t('中文'), value: 'zh-CN' },
                    { label: t('英文'), value: 'en-US' },
                  ]"
                />
                <div class="field-hint">{{ t('语言偏好会立即生效，并保存在当前浏览器本地。') }}</div>
                <div class="field-hint">{{ t('使用英文界面，并让 Agent 默认输出英文') }}</div>
              </div>
            </el-form-item>
          </el-form>
        </div>
      </el-tab-pane>

      <el-tab-pane label="MCP 配置" name="mcp">
        <div class="tab-body">
          <div class="mcp-layout">
            <div class="mcp-list">
              <div v-if="!mcpServers.length" class="mcp-empty">暂无 MCP 服务</div>
              <button
                v-for="(server, index) in mcpServers"
                :key="server.name"
                type="button"
                class="mcp-item"
                :class="{ active: editingMcpIndex === index }"
                @click="editMcp(index)"
              >
                <span class="mcp-item__name">{{ server.name }}</span>
                <span class="mcp-item__meta">{{ server.type === 'stdio' ? server.command : server.url }}</span>
                <span class="mcp-item__type">{{ server.type }}</span>
              </button>
            </div>

            <div class="mcp-form">
              <div class="mcp-form-grid">
                <label>
                  <span>名称</span>
                  <input v-model="mcpDraft.name" class="mcp-input" placeholder="filesystem" />
                </label>
                <label>
                  <span>类型</span>
                  <select v-model="mcpDraft.type" class="mcp-input">
                    <option value="stdio">stdio</option>
                    <option value="http">http</option>
                    <option value="sse">sse</option>
                  </select>
                </label>
                <label v-if="mcpDraft.type === 'stdio'" class="span-2">
                  <span>Command</span>
                  <input v-model="mcpDraft.command" class="mcp-input mono" placeholder="npx" />
                </label>
                <label v-else class="span-2">
                  <span>URL</span>
                  <input v-model="mcpDraft.url" class="mcp-input mono" placeholder="https://example.com/mcp" />
                </label>
                <label v-if="mcpDraft.type === 'stdio'" class="span-2">
                  <span>Args，每行一个</span>
                  <textarea v-model="mcpDraft.argsText" class="mcp-textarea mono" rows="4" placeholder="-y&#10;@modelcontextprotocol/server-filesystem&#10;/tmp"></textarea>
                </label>
                <label v-if="mcpDraft.type === 'stdio'" class="span-2">
                  <span>Env JSON</span>
                  <textarea v-model="mcpDraft.envText" class="mcp-textarea mono" rows="4" placeholder='{"TOKEN":"value"}'></textarea>
                </label>
                <label v-else class="span-2">
                  <span>Headers JSON</span>
                  <textarea v-model="mcpDraft.headersText" class="mcp-textarea mono" rows="4" placeholder='{"Authorization":"Bearer token"}'></textarea>
                </label>
                <label>
                  <span>Timeout ms</span>
                  <input v-model.number="mcpDraft.timeout" class="mcp-input mono" type="number" min="0" placeholder="0" />
                </label>
                <label class="mcp-switch">
                  <span>Always Load</span>
                  <el-switch v-model="mcpDraft.alwaysLoad" />
                </label>
              </div>
              <div class="mcp-actions">
                <el-button size="small" type="primary" @click="upsertMcp">
                  {{ editingMcpIndex >= 0 ? '更新 MCP' : '添加 MCP' }}
                </el-button>
                <el-button size="small" plain @click="resetMcpDraft">清空</el-button>
                <el-button
                  v-if="editingMcpIndex >= 0"
                  size="small"
                  type="danger"
                  plain
                  @click="removeMcp(editingMcpIndex)"
                >删除</el-button>
                <span class="mcp-hint">保存配置并重启 Agent 后生效。</span>
              </div>
            </div>
          </div>
        </div>
      </el-tab-pane>

      <el-tab-pane name="logs">
        <template #label>
          <span class="tab-label-with-dot">
            Agent 日志
            <span class="tab-dot" :class="{ on: agentStore.status.ready }"></span>
          </span>
        </template>
        <div class="tab-body">
          <div class="status-bar">
            <div class="status-items">
              <span class="status-chip">
                <span class="dot" :class="{ on: agentStore.status.ready }"></span>
                {{ agentStore.status.ready ? '运行中' : agentStore.status.running ? '启动中...' : '已停止' }}
              </span>
              <span class="status-chip mono" v-if="agentStore.status.pid">PID {{ agentStore.status.pid }}</span>
              <span class="status-chip" v-if="provider === 'claude' && runtimeInfo?.claudeAvailable">
                <span class="dot on"></span>
                Claude CLI ({{ runtimeInfo.claudeSource || 'auto' }})
              </span>
              <span class="status-chip" v-else-if="provider === 'claude'">
                <span class="dot"></span>
                Claude CLI 未找到
              </span>
              <span class="status-chip" v-else-if="runtimeInfo?.codexAvailable">
                <span class="dot on"></span>
                Codex ({{ runtimeInfo.codexSource || 'sdk' }})
              </span>
              <span class="status-chip" v-else>
                <span class="dot"></span>
                Codex 不可用
              </span>
            </div>
            <div class="status-actions">
              <el-button size="small" @click="restartAgent" :disabled="!agentStore.status.running">重启</el-button>
              <el-button size="small" type="danger" plain @click="stopAgent" :disabled="!agentStore.status.running">停止</el-button>
              <el-button size="small" text @click="refreshRuntimeInfo" :loading="runtimeLoading">检测运行时</el-button>
              <el-button size="small" text @click="refreshLogs">刷新日志</el-button>
            </div>
          </div>
          <div class="log-output">
            <div v-if="!logs.length" class="log-empty">暂无日志</div>
            <div v-for="(line, i) in logs.slice(-50)" :key="i" class="log-line">{{ line }}</div>
          </div>
        </div>
      </el-tab-pane>
    </el-tabs>

    <div v-if="activeTab === 'agent' || activeTab === 'mcp'" class="save-bar">
      <el-button type="primary" @click="save" :loading="saving">保存并应用</el-button>
      <el-button @click="testConnection" :loading="testing">测试连接</el-button>
      <span v-if="testResult" :style="{ fontSize: '12px', color: testResult.ok ? 'var(--kg-accent)' : 'var(--kg-warn)' }">
        {{ testResult.msg }}
      </span>
    </div>
  </div>
</template>

<style scoped>
.settings-page { padding: 24px; max-width: 980px; }
.page-title { font-size: 18px; font-weight: 700; margin-bottom: 16px; }

.settings-tabs :deep(.el-tabs__header) { margin-bottom: 0; }
.settings-tabs :deep(.el-tabs__nav-wrap::after) { height: 1px; background: var(--kg-border); }
.settings-tabs :deep(.el-tabs__item) { font-size: 13px; font-weight: 600; color: var(--kg-text-muted); }
.settings-tabs :deep(.el-tabs__item.is-active) { color: var(--kg-text); }
.settings-tabs :deep(.el-tabs__active-bar) { background: var(--kg-accent); }
.settings-tabs :deep(.el-tab-pane) { min-height: 0; }

.tab-body { padding: 20px 0 0; }

.save-bar { display: flex; align-items: center; gap: 8px; margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--kg-border); }

.tab-label-with-dot { display: inline-flex; align-items: center; gap: 6px; }
.tab-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--kg-text-dim); flex-shrink: 0; }
.tab-dot.on { background: var(--kg-accent); }

.mcp-layout { display: grid; grid-template-columns: minmax(220px, 280px) minmax(0, 1fr); gap: 12px; align-items: start; }
.mcp-list { min-height: 0; max-height: 480px; overflow-y: auto; padding: 6px; border: 1px solid var(--kg-border); border-radius: 8px; background: var(--kg-bg); }
.mcp-empty { padding: 28px 8px; text-align: center; color: var(--kg-text-muted); font-size: 12px; }
.mcp-item { position: relative; width: 100%; min-height: 58px; display: flex; flex-direction: column; gap: 4px; padding: 8px 58px 8px 9px; border: 1px solid transparent; border-radius: 7px; background: transparent; color: var(--kg-text); text-align: left; cursor: pointer; }
.mcp-item:hover { background: var(--kg-surface-2); }
.mcp-item.active { background: var(--kg-accent-soft); border-color: color-mix(in srgb, var(--kg-accent) 64%, var(--kg-border)); }
.mcp-item__name { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px; font-weight: 800; font-family: var(--kg-font-mono); }
.mcp-item__meta { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--kg-text-muted); font-size: 11px; font-family: var(--kg-font-mono); }
.mcp-item__type { position: absolute; right: 8px; top: 8px; padding: 1px 5px; border-radius: 4px; background: var(--kg-surface-2); color: var(--kg-text-muted); font-size: 10px; font-weight: 700; }
.mcp-form { min-width: 0; padding: 10px; border: 1px solid var(--kg-border); border-radius: 8px; background: color-mix(in srgb, var(--kg-surface) 72%, var(--kg-bg)); }
.mcp-form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
.mcp-form label { min-width: 0; display: flex; flex-direction: column; gap: 5px; color: var(--kg-text-muted); font-size: 11px; font-weight: 700; }
.mcp-form .span-2 { grid-column: span 2; }
.mcp-input, .mcp-textarea { width: 100%; min-width: 0; box-sizing: border-box; border: 1px solid var(--kg-border); border-radius: 6px; background: var(--kg-bg); color: var(--kg-text); font-size: 12px; outline: none; }
.mcp-input { height: 32px; padding: 0 8px; }
.mcp-textarea { resize: vertical; padding: 8px; line-height: 1.45; }
.mcp-input:focus, .mcp-textarea:focus { border-color: var(--kg-accent); box-shadow: 0 0 0 3px var(--kg-accent-ring); }
.mcp-form .mono { font-family: var(--kg-font-mono); }
.mcp-switch { justify-content: end; }
.mcp-actions { margin-top: 10px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.mcp-hint { color: var(--kg-text-muted); font-size: 11px; }

.status-bar { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; padding: 10px 12px; border: 1px solid var(--kg-border); border-radius: 8px; background: var(--kg-bg); }
.status-items { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.status-chip { display: inline-flex; align-items: center; gap: 5px; font-size: 12px; font-weight: 600; color: var(--kg-text-muted); }
.status-actions { display: flex; gap: 6px; flex-shrink: 0; }

.runtime-input { display: flex; gap: 8px; align-items: center; width: 100%; }
.runtime-hint { margin-top: 6px; max-width: 620px; color: var(--kg-text-muted); font-size: 11px; font-family: var(--kg-font-mono); word-break: break-all; }
.field-stack { display: flex; flex-direction: column; align-items: flex-start; width: 100%; }
.field-hint { margin-top: 6px; color: var(--kg-text-muted); font-size: 11px; font-family: var(--kg-font-mono); }
.custom-env-textarea { width: 100%; max-width: 520px; min-width: 0; box-sizing: border-box; resize: vertical; padding: 8px 11px; border: 1px solid var(--kg-border); border-radius: 6px; background: var(--kg-bg); color: var(--kg-text); font-family: var(--kg-font-mono); font-size: 12px; line-height: 1.5; outline: none; }
.custom-env-textarea:focus { border-color: var(--kg-accent); box-shadow: 0 0 0 3px var(--kg-accent-ring); }
.dot { width: 6px; height: 6px; border-radius: 50%; background: var(--kg-text-dim); flex-shrink: 0; }
.dot.on { background: var(--kg-accent); }
.mono { font-family: var(--kg-font-mono); }
.log-output { max-height: calc(100vh - 320px); overflow-y: auto; font-family: var(--kg-font-mono); font-size: 11px; background: var(--kg-bg); padding: 10px; border-radius: 6px; border: 1px solid var(--kg-border); }
.log-empty { color: var(--kg-text-muted); text-align: center; padding: 32px 16px; }
.log-line { padding: 1px 0; color: var(--kg-text-muted); white-space: pre-wrap; word-break: break-all; }

@media (max-width: 860px) {
  .mcp-layout { grid-template-columns: 1fr; }
  .mcp-list { min-height: 120px; max-height: 220px; }
  .mcp-form-grid { grid-template-columns: 1fr; }
  .mcp-form .span-2 { grid-column: span 1; }
  .status-bar { flex-direction: column; align-items: flex-start; }
}
</style>
