<script setup lang="ts">
import { ref, computed, onUnmounted } from 'vue'
import { api, on } from '../api/wails'
import { useScanStore, type ScanResult } from '../stores/scan'

const props = defineProps<{ clusterId: string }>()
const scanStore = useScanStore()

const mode = ref('safe')
const rbacMode = ref('focused')
const timeout = ref(60)
const credentialSweep = ref(false)
const sensitive = ref('redact')
const scanning = ref(false)
const showFacts = ref(false)
const factFilter = ref('')
const unsubs: (() => void)[] = []

const activeResult = computed(() => {
  if (!scanStore.activeResultId) return null
  return scanStore.results.find(r => r.id === scanStore.activeResultId) ?? null
})

const filteredFacts = computed(() => {
  const doc = activeResult.value?.document
  if (!doc?.facts) return []
  const q = factFilter.value.toLowerCase()
  if (!q) return doc.facts
  return doc.facts.filter((f: any) =>
    (f.id || '').toLowerCase().includes(q) ||
    (f.collector || '').toLowerCase().includes(q) ||
    JSON.stringify(f.value || '').toLowerCase().includes(q)
  )
})

const factsByCollector = computed(() => {
  const groups: Record<string, any[]> = {}
  for (const f of filteredFacts.value) {
    const c = f.collector || 'unknown'
    if (!groups[c]) groups[c] = []
    groups[c].push(f)
  }
  return groups
})

async function startScan() {
  scanning.value = true
  try {
    await api.StartClusterScan(props.clusterId, {
      mode: mode.value,
      timeout: timeout.value,
      sensitive: sensitive.value,
      rbacMode: rbacMode.value,
      credentialSweep: credentialSweep.value,
      maxItems: 100,
    })
  } catch (e: any) {
    ;(window as any).ElMessage?.error?.(String(e))
    scanning.value = false
  }
}

unsubs.push(on('scan:complete', (result: any) => {
  scanning.value = false
  if (result) scanStore.addResult(result)
  ;(window as any).ElMessage?.success?.('扫描完成，请前往「智能攻击」标签页的「攻击面」查看结果')
}))

unsubs.push(on('scan:error', (err: string) => {
  scanning.value = false
  ;(window as any).ElMessage?.error?.(`扫描失败: ${err}`)
}))

onUnmounted(() => {
  unsubs.forEach(fn => fn())
})

async function exportResult() {
  if (!scanStore.activeResultId) return
  try {
    await api.ExportScanResult(scanStore.activeResultId)
  } catch (e: any) {
    ;(window as any).ElMessage?.error?.(String(e))
  }
}
</script>

<template>
  <div class="scan-panel">
    <!-- Action bar -->
    <div class="scan-actions">
      <el-button type="success" plain @click="startScan" :loading="scanning" :disabled="scanning">
        <el-icon><Search /></el-icon> 扫描当前集群
      </el-button>
    </div>

    <!-- Scan config -->
    <el-card shadow="never" class="config-card">
      <template #header><span style="font-size:13px;font-weight:600">扫描配置</span></template>
      <el-form label-width="120px" size="small">
        <el-form-item label="Mode">
          <el-select v-model="mode" style="width:120px">
            <el-option label="Safe" value="safe" />
            <el-option label="Full" value="full" />
          </el-select>
        </el-form-item>
        <el-form-item label="RBAC Mode">
          <el-select v-model="rbacMode" style="width:120px">
            <el-option label="Focused" value="focused" />
            <el-option label="Full" value="full" />
          </el-select>
        </el-form-item>
        <el-form-item label="Timeout (s)">
          <el-input-number v-model="timeout" :min="10" :max="300" style="width:120px" />
        </el-form-item>
        <el-form-item label="Sensitive">
          <el-select v-model="sensitive" style="width:120px">
            <el-option label="Redact" value="redact" />
            <el-option label="Raw" value="raw" />
            <el-option label="Metadata" value="metadata" />
          </el-select>
        </el-form-item>
        <el-form-item label="Credential Sweep">
          <el-switch v-model="credentialSweep" />
        </el-form-item>
      </el-form>
    </el-card>

    <!-- Results -->
    <div v-if="scanStore.results.length" class="results-section">
      <div class="section-title">扫描结果</div>
      <div class="result-list">
        <div
          v-for="r in scanStore.results" :key="r.id"
          class="result-item"
          :class="{ active: r.id === scanStore.activeResultId }"
          @click="scanStore.setActive(r.id)"
        >
          <span class="result-badge" :class="r.source">{{ r.source === 'import' ? '导入' : '实时' }}</span>
          <span class="result-meta">{{ r.factCount }} facts · {{ r.errorCount }} errors</span>
          <el-button size="small" text type="danger" @click.stop="scanStore.removeResult(r.id)">
            <el-icon><Delete /></el-icon>
          </el-button>
        </div>
      </div>
    </div>

    <!-- Active result summary -->
    <el-card v-if="activeResult" shadow="never" class="summary-card">
      <template #header>
        <div style="display:flex;align-items:center;gap:8px">
          <span style="font-size:13px;font-weight:600">结果摘要</span>
          <span style="flex:1"></span>
          <el-button size="small" plain @click="showFacts = !showFacts">
            {{ showFacts ? '隐藏 Facts' : '查看 Facts' }}
          </el-button>
          <el-button size="small" plain @click="exportResult">导出 JSON</el-button>
        </div>
      </template>
      <div class="summary-grid">
        <div><span class="label">Schema</span><span class="value mono">{{ activeResult.document?.schemaVersion }}</span></div>
        <div><span class="label">Mode</span><span class="value">{{ activeResult.document?.mode }}</span></div>
        <div><span class="label">Facts</span><span class="value accent">{{ activeResult.factCount }}</span></div>
        <div><span class="label">Collectors</span><span class="value">{{ activeResult.document?.collectors?.length || 0 }}</span></div>
        <div><span class="label">Errors</span><span class="value" :class="{ warn: activeResult.errorCount > 0 }">{{ activeResult.errorCount }}</span></div>
        <div><span class="label">Target</span><span class="value mono">{{ activeResult.document?.target?.namespace }} / {{ activeResult.document?.target?.podName }}</span></div>
      </div>
    </el-card>

    <!-- Fact browser -->
    <div v-if="showFacts && activeResult" class="fact-browser">
      <el-input v-model="factFilter" placeholder="搜索 facts..." clearable size="small" style="margin-bottom:8px" />
      <div class="fact-count">{{ filteredFacts.length }} / {{ activeResult.factCount }} facts</div>
      <el-collapse>
        <el-collapse-item v-for="(facts, collector) in factsByCollector" :key="collector" :title="`${collector} (${facts.length})`">
          <div v-for="(fact, i) in facts" :key="i" class="fact-item">
            <div class="fact-id">{{ fact.id }}</div>
            <div v-if="fact.sensitive" class="fact-sensitive">sensitive</div>
            <pre class="fact-value">{{ typeof fact.value === 'string' ? fact.value : JSON.stringify(fact.value, null, 2) }}</pre>
          </div>
        </el-collapse-item>
      </el-collapse>
    </div>
  </div>
</template>

<style scoped>
.scan-panel { padding: 16px; display: flex; flex-direction: column; gap: 12px; }
.scan-actions { display: flex; gap: 8px; }
.config-card { background: var(--kg-surface); border-color: var(--kg-border); }
.section-title { font-size: 13px; font-weight: 600; margin-bottom: 6px; }
.result-list { display: flex; flex-direction: column; gap: 4px; }
.result-item {
  display: flex; align-items: center; gap: 8px;
  padding: 6px 10px; border-radius: 6px; cursor: pointer;
  background: var(--kg-surface); border: 1px solid var(--kg-border);
  transition: border-color .15s;
}
.result-item.active { border-color: var(--kg-accent); }
.result-badge {
  font-size: 11px; padding: 1px 6px; border-radius: 3px;
  font-weight: 600; text-transform: uppercase;
}
.result-badge.import { background: var(--kg-info); color: #fff; }
.result-badge.live { background: var(--kg-accent); color: #fff; }
.result-meta { font-size: 12px; color: var(--kg-text-muted); flex: 1; }
.summary-card { background: var(--kg-surface); border-color: var(--kg-border); }
.summary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
.summary-grid .label { font-size: 11px; color: var(--kg-text-muted); display: block; }
.summary-grid .value { font-size: 13px; font-weight: 600; }
.summary-grid .mono { font-family: var(--kg-font-mono); font-size: 12px; }
.summary-grid .accent { color: var(--kg-accent); }
.summary-grid .warn { color: var(--kg-warn); }
.fact-browser { max-height: 500px; overflow-y: auto; }
.fact-count { font-size: 11px; color: var(--kg-text-muted); margin-bottom: 4px; }
.fact-item { padding: 6px 0; border-bottom: 1px solid var(--kg-border); }
.fact-id { font-size: 12px; font-weight: 600; font-family: var(--kg-font-mono); }
.fact-sensitive { font-size: 10px; color: var(--kg-warn); font-weight: 600; }
.fact-value { font-size: 11px; font-family: var(--kg-font-mono); white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow-y: auto; color: var(--kg-text-muted); margin: 4px 0 0; }
</style>
