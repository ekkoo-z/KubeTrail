<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index'
import { api } from '../api/wails'

interface Preset {
  key: string
  label: string
  category: 'k8s' | 'host' | 'cloud' | string
  description: string
}

const props = defineProps<{
  clusterId: string
  namespace: string
  pod: string
  container: string
}>()

const catalog = ref<Preset[]>([])
const output = ref('')
const current = ref<Preset | null>(null)
const loading = ref(false)
const copied = ref(false)
const filter = ref('')
const lastRun = ref<number | null>(null)

async function load() {
  catalog.value = ((await api.ReconCatalog()) as Preset[]) || []
}

const groups = computed(() => {
  const kw = filter.value.trim().toLowerCase()
  const match = (p: Preset) =>
    !kw ||
    p.label.toLowerCase().includes(kw) ||
    p.key.toLowerCase().includes(kw) ||
    p.description.toLowerCase().includes(kw)
  const order: Array<{ id: string; title: string; hint: string }> = [
    { id: 'k8s',   title: 'K8s',   hint: 'SA / Kube env' },
    { id: 'host',  title: 'Host',  hint: '容器内本地' },
    { id: 'cloud', title: 'Cloud', hint: '云元数据' },
  ]
  return order
    .map(g => ({ ...g, items: catalog.value.filter(p => p.category === g.id && match(p)) }))
    .filter(g => g.items.length > 0)
})

const totalMatched = computed(() => groups.value.reduce((n, g) => n + g.items.length, 0))

async function run(preset: Preset) {
  loading.value = true
  current.value = preset
  output.value = ''
  try {
    output.value = (await api.ReconRead(
      props.clusterId,
      props.namespace,
      props.pod,
      props.container,
      preset.key,
    )) as string
    lastRun.value = Date.now()
  } catch (e: any) {
    output.value = String(e?.message || e)
  } finally {
    loading.value = false
  }
}

async function copy() {
  if (!output.value) return
  try {
    await navigator.clipboard.writeText(output.value)
    copied.value = true
    setTimeout(() => { copied.value = false }, 1400)
  } catch {
    ElMessage.warning('复制失败')
  }
}

function relativeTime(ts: number | null): string {
  if (!ts) return ''
  const s = Math.floor((Date.now() - ts) / 1000)
  if (s < 5) return 'just now'
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  return `${Math.floor(s / 3600)}h ago`
}

const tickedRel = ref(relativeTime(lastRun.value))
setInterval(() => { tickedRel.value = relativeTime(lastRun.value) }, 5000)

const outputBytes = computed(() => new Blob([output.value]).size)

onMounted(load)
</script>

<template>
  <div class="rt">
    <!-- ============== LEFT RAIL ============== -->
    <aside class="rt-rail">
      <div class="rt-search">
        <svg class="rt-search__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="11" cy="11" r="8"/>
          <line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
        <input v-model="filter" placeholder="过滤 preset..." />
        <span v-if="filter" class="rt-search__count">{{ totalMatched }}</span>
      </div>

      <div class="rt-rail__body">
        <div v-for="g in groups" :key="g.id" class="rt-group">
          <div class="rt-group__head" :class="`is-${g.id}`">
            <span class="rt-group__title">{{ g.title }}</span>
            <span class="rt-group__hint">{{ g.hint }}</span>
            <span class="rt-group__count">{{ g.items.length }}</span>
          </div>
          <button
            v-for="p in g.items"
            :key="p.key"
            class="rt-preset"
            :class="{ 'is-active': current?.key === p.key, 'is-loading': loading && current?.key === p.key }"
            @click="run(p)"
          >
            <span class="rt-preset__label">{{ p.label }}</span>
            <span class="rt-preset__desc">{{ p.description }}</span>
          </button>
        </div>

        <div v-if="!groups.length" class="rt-rail__empty">
          <div class="rt-rail__empty-text">无匹配 preset</div>
        </div>
      </div>
    </aside>

    <!-- ============== RIGHT PANE ============== -->
    <section class="rt-pane">
      <!-- header strip -->
      <header class="rt-pane__head">
        <template v-if="current">
          <span class="rt-cat-tag" :class="`is-${current.category}`">{{ current.category }}</span>
          <div class="rt-pane__title">
            <div class="rt-pane__name">{{ current.label }}</div>
            <div class="rt-pane__key">{{ current.key }} · {{ current.description }}</div>
          </div>
          <div class="rt-pane__meta">
            <span v-if="output && !loading" class="rt-pane__bytes">{{ outputBytes }} B</span>
            <span v-if="lastRun && !loading" class="rt-pane__time">{{ tickedRel }}</span>
            <span v-if="loading" class="rt-pane__time">running…</span>
          </div>
          <button class="rt-btn" :disabled="loading" @click="run(current)" title="重新运行">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="23 4 23 10 17 10"/>
              <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
            </svg>
            <span>重跑</span>
          </button>
          <button class="rt-btn" :class="{ 'is-copied': copied }" :disabled="!output" @click="copy">
            <svg v-if="!copied" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
            </svg>
            <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="20 6 9 17 4 12"/>
            </svg>
            <span>{{ copied ? '已复制' : '复制' }}</span>
          </button>
        </template>
        <template v-else>
          <div class="rt-pane__placeholder">从左侧选一个 preset 开跑</div>
        </template>
      </header>

      <!-- body -->
      <div class="rt-output" :class="{ 'is-empty': !output && !loading }" v-loading="loading">
        <template v-if="output">
          <pre class="rt-output__code">{{ output }}</pre>
        </template>
        <div v-else-if="!loading" class="rt-output__hint">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="6 7 10 12 6 17"/>
            <line x1="12" y1="17" x2="18" y2="17"/>
          </svg>
          <div class="rt-output__hint-title">等待执行</div>
          <div class="rt-output__hint-sub">选一个 preset，结果会在这里显示</div>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
/* ============== layout ============== */
.rt {
  display: flex;
  gap: 0;
  height: 540px;
  background: var(--kg-bg);
  border: 1px solid var(--kg-border-soft);
  border-radius: 10px;
  overflow: hidden;
}

/* ============== left rail ============== */
.rt-rail {
  width: 280px;
  display: flex;
  flex-direction: column;
  background: var(--kg-surface);
  border-right: 1px solid var(--kg-border-soft);
  min-width: 0;
}

.rt-search {
  position: relative;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 12px;
  border-bottom: 1px solid var(--kg-border-soft);
}
.rt-search__icon {
  width: 13px;
  height: 13px;
  color: var(--kg-text-dim);
  flex-shrink: 0;
}
.rt-search input {
  flex: 1;
  min-width: 0;
  background: transparent;
  border: none;
  outline: none;
  color: var(--kg-text);
  font: 13px var(--kg-font-sans);
}
.rt-search input::placeholder { color: var(--kg-text-dim); }
.rt-search__count {
  font: 600 10.5px var(--kg-font-mono);
  padding: 1px 6px;
  border-radius: 8px;
  background: var(--kg-accent-soft);
  color: var(--kg-accent);
}

.rt-rail__body {
  flex: 1;
  overflow-y: auto;
  padding: 6px;
}

/* group */
.rt-group { margin-top: 8px; }
.rt-group:first-child { margin-top: 4px; }
.rt-group__head {
  display: flex;
  align-items: baseline;
  gap: 8px;
  padding: 6px 10px 6px 12px;
  position: relative;
}
.rt-group__head::before {
  content: '';
  position: absolute;
  left: 4px;
  top: 50%;
  transform: translateY(-50%);
  width: 3px;
  height: 12px;
  border-radius: 2px;
  background: var(--kg-text-dim);
}
.rt-group__head.is-k8s::before   { background: var(--kg-accent); }
.rt-group__head.is-host::before  { background: var(--kg-info); }
.rt-group__head.is-cloud::before { background: var(--kg-warn); }
.rt-group__title {
  font: 600 11px var(--kg-font-mono);
  letter-spacing: 1.2px;
  text-transform: uppercase;
  color: var(--kg-text);
}
.rt-group__hint {
  flex: 1;
  font-size: 10.5px;
  color: var(--kg-text-dim);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.rt-group__count {
  font: 500 10px var(--kg-font-mono);
  color: var(--kg-text-dim);
  padding: 0 5px;
  border-radius: 6px;
  border: 1px solid var(--kg-border-soft);
}

/* preset */
.rt-preset {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 2px;
  width: 100%;
  padding: 7px 10px 7px 12px;
  background: transparent;
  border: none;
  border-radius: 6px;
  color: var(--kg-text);
  font-family: inherit;
  cursor: pointer;
  text-align: left;
  transition: background .15s var(--kg-ease);
}
.rt-preset:hover { background: var(--kg-surface-2); }
.rt-preset.is-active {
  background: var(--kg-accent-soft);
}
.rt-preset.is-active::before {
  content: '';
  position: absolute;
  left: 3px;
  top: 8px;
  bottom: 8px;
  width: 2px;
  border-radius: 1px;
  background: var(--kg-accent);
}
.rt-preset.is-loading::after {
  content: '';
  position: absolute;
  right: 8px;
  top: 50%;
  transform: translateY(-50%);
  width: 10px;
  height: 10px;
  border: 1.5px solid var(--kg-accent);
  border-top-color: transparent;
  border-radius: 50%;
  animation: rt-spin .8s linear infinite;
}
@keyframes rt-spin { to { transform: translateY(-50%) rotate(360deg); } }

.rt-preset__label {
  font-size: 12.5px;
  font-weight: 500;
  color: var(--kg-text);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 100%;
}
.rt-preset.is-active .rt-preset__label { color: var(--kg-accent); }
.rt-preset__desc {
  font-size: 11px;
  color: var(--kg-text-dim);
  line-height: 1.4;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 100%;
}

.rt-rail__empty {
  padding: 28px 14px;
  text-align: center;
}
.rt-rail__empty-text {
  font-family: var(--kg-font-mono);
  font-size: 11px;
  color: var(--kg-text-dim);
  letter-spacing: 1px;
  text-transform: uppercase;
}

/* ============== right pane ============== */
.rt-pane {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.rt-pane__head {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--kg-border-soft);
  background: var(--kg-surface);
  min-height: 48px;
}
.rt-pane__placeholder {
  flex: 1;
  font-size: 12.5px;
  color: var(--kg-text-dim);
  text-align: center;
}

.rt-cat-tag {
  font: 600 10px var(--kg-font-mono);
  letter-spacing: 1px;
  text-transform: uppercase;
  padding: 2px 7px;
  border-radius: 4px;
  flex-shrink: 0;
}
.rt-cat-tag.is-k8s   { background: var(--kg-accent-soft); color: var(--kg-accent); }
.rt-cat-tag.is-host  { background: var(--kg-info-soft);   color: var(--kg-info); }
.rt-cat-tag.is-cloud { background: var(--kg-warn-soft);   color: var(--kg-warn); }

.rt-pane__title {
  flex: 1;
  min-width: 0;
  line-height: 1.2;
}
.rt-pane__name {
  font-size: 13.5px;
  font-weight: 600;
  color: var(--kg-text);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.rt-pane__key {
  margin-top: 2px;
  font: 11px var(--kg-font-mono);
  color: var(--kg-text-dim);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.rt-pane__meta {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 1px;
  font: 10.5px var(--kg-font-mono);
  color: var(--kg-text-dim);
  flex-shrink: 0;
}
.rt-pane__bytes { color: var(--kg-text-muted); }
.rt-pane__time { letter-spacing: 0.3px; }

/* button */
.rt-btn {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 5px 10px;
  border: 1px solid var(--kg-border);
  background: transparent;
  color: var(--kg-text-muted);
  font: 500 11.5px var(--kg-font-sans);
  letter-spacing: 0.3px;
  border-radius: 5px;
  cursor: pointer;
  transition: color .15s, border-color .15s, background .15s;
  flex-shrink: 0;
}
.rt-btn:hover:not(:disabled) {
  color: var(--kg-accent);
  border-color: var(--kg-accent);
  background: var(--kg-accent-soft);
}
.rt-btn:disabled { opacity: 0.4; cursor: not-allowed; }
.rt-btn.is-copied {
  color: var(--kg-accent);
  border-color: var(--kg-accent);
  background: var(--kg-accent-soft);
}
.rt-btn svg { width: 12px; height: 12px; }

/* output */
.rt-output {
  flex: 1;
  background: #07090D;
  min-height: 0;
  position: relative;
  overflow: hidden;
}
.rt-output.is-empty {
  display: flex;
  align-items: center;
  justify-content: center;
}
.rt-output__code {
  margin: 0;
  height: 100%;
  padding: 14px 16px;
  font: 12.5px / 1.65 var(--kg-font-mono);
  color: #C9D1D9;
  white-space: pre;
  overflow: auto;
  word-break: normal;
}
.rt-output__hint {
  text-align: center;
  color: var(--kg-text-dim);
}
.rt-output__hint svg {
  width: 28px;
  height: 28px;
  margin: 0 auto 10px;
  display: block;
  color: var(--kg-text-dim);
  opacity: 0.5;
}
.rt-output__hint-title {
  font: 600 13px var(--kg-font-sans);
  color: var(--kg-text-muted);
  margin-bottom: 4px;
}
.rt-output__hint-sub {
  font-size: 11.5px;
  color: var(--kg-text-dim);
}
</style>
