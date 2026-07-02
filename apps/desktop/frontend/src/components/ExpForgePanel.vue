<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index'
import { Brush, Check, Memo, Operation, SetUp } from '@element-plus/icons-vue'
import { useScanStore } from '../stores/scan'
import {
  lpeExploitCatalog,
  lpeExploitSearchText,
  matchLpeExploit,
  type LpeExploitCard,
  type LpeExploitMatch,
} from '../data/lpeExpCatalog'

const props = defineProps<{
  scanId?: string
  initialTemplateIds?: string[]
  initialFindingIds?: string[]
  initialFactIds?: string[]
  initialParams?: Record<string, string | number | boolean>
}>()
const scanStore = useScanStore()

const selectedExploit = ref<LpeExploitCard | null>(null)
const filter = ref('')
const selectionContext = ref<{ findingIds: string[]; factIds: string[] }>({ findingIds: [], factIds: [] })

const activeResult = computed(() => {
  if (!scanStore.activeResultId) return null
  return scanStore.results.find(r => r.id === scanStore.activeResultId) ?? null
})

const activeExploitMatches = computed(() => {
  const out = new Map<string, LpeExploitMatch>()
  const doc = activeResult.value?.document
  if (!doc) return out
  for (const card of lpeExploitCatalog) {
    const match = matchLpeExploit(card, doc)
    if (match.matched) out.set(card.id, match)
  }
  return out
})

const filteredExploitCards = computed(() => {
  const kw = filter.value.trim().toLowerCase()
  return lpeExploitCatalog.filter(card => !kw || lpeExploitSearchText(card).includes(kw))
})

const totalCatalogMatched = computed(() => filteredExploitCards.value.length)

const selectedExploitMatch = computed(() => {
  const card = selectedExploit.value
  return card ? activeExploitMatches.value.get(card.id) ?? null : null
})

const methodSections = computed(() => {
  const method = selectedExploit.value?.method
  if (!method) return []
  return [
    { key: 'verify', label: '确认信号', hint: '用于判断目标是否满足触发条件', icon: Check, tone: 'verify', lines: method.verify },
    { key: 'build', label: '编译 / 准备', hint: '依赖、构建和目标侧准备步骤', icon: SetUp, tone: 'build', lines: method.build },
    { key: 'run', label: '运行入口', hint: '授权环境中的执行入口', icon: Operation, tone: 'run', lines: method.run },
    { key: 'cleanup', label: '清理', hint: '删除临时文件或恢复验证痕迹', icon: Brush, tone: 'cleanup', lines: method.cleanup },
  ].filter(section => section.lines.length)
})

function selectExploit(card: LpeExploitCard) {
  selectedExploit.value = card
  selectionContext.value = { findingIds: [], factIds: [] }
}

function selectExploitFromContext(card: LpeExploitCard, context: { findingIds: string[]; factIds: string[]; params?: Record<string, string | number | boolean> }) {
  selectExploit(card)
  selectionContext.value = {
    findingIds: [...context.findingIds],
    factIds: [...context.factIds],
  }
}

function categoryLabel(category: string): string {
  const labels: Record<string, string> = {
    'userland-suid': '用户态 SUID',
    'userland-package-manager': '用户态包管理',
    'kernel-page-cache': '内核页缓存',
    'kernel-filesystem': '内核文件系统',
    'kernel-netfilter': '内核网络过滤',
    'kernel-ebpf': '内核 eBPF',
    'kernel-namespace': '内核命名空间',
  }
  return labels[category] ?? category.replaceAll('-', ' ')
}

function sourceRoleLabel(role: string): string {
  if (role === 'primary') return '主'
  if (role === 'secondary') return '备'
  return '参考'
}

function confidenceLabel(confidence: string): string {
  const labels: Record<string, string> = {
    stable: '稳定',
    'version-sensitive': '版本敏感',
    research: '研究型',
    none: '未命中',
    signal: '线索',
    probable: '疑似可用',
  }
  return labels[confidence] ?? confidence
}

function applyInitialSelection() {
  const ids = props.initialTemplateIds ?? []
  if (!ids.length) return
  const params = props.initialParams ?? {}
  const pocId = typeof params.pocId === 'string' ? params.pocId : ''
  const exploitCard = lpeExploitCatalog.find(card => {
    if (pocId && card.id === pocId) return true
    const cardTemplateId = card.templateId || 'external-cve-poc'
    return ids.includes(cardTemplateId)
  })
  if (exploitCard) {
    if (
      selectedExploit.value?.id === exploitCard.id &&
      selectionContext.value.findingIds.join(',') === (props.initialFindingIds ?? []).join(',')
    ) {
      return
    }
    selectExploitFromContext(exploitCard, {
      findingIds: props.initialFindingIds ?? [],
      factIds: props.initialFactIds ?? [],
      params,
    })
    return
  }
  selectedExploit.value = null
  selectionContext.value = { findingIds: [], factIds: [] }
}

async function copyText(value: string, label = '已复制') {
  try {
    await navigator.clipboard.writeText(value)
    ElMessage.success(label)
  } catch {
    ElMessage.error('复制失败，请手动选取')
  }
}

watch(() => [props.initialTemplateIds, props.initialFindingIds, props.initialFactIds, props.initialParams], applyInitialSelection, { deep: true, immediate: true })
</script>

<template>
  <div class="exp">
    <!-- LEFT RAIL -->
    <aside class="exp-rail">
      <div class="exp-search">
        <input v-model="filter" placeholder="搜索 Linux 提权 EXP..." />
        <span v-if="filter" class="exp-search__count">{{ totalCatalogMatched }}</span>
      </div>

      <div class="exp-rail__body">
        <div class="exp-library">
          <div class="exp-group__head is-dangerous">
            <span class="exp-group__title">Linux 漏洞库</span>
            <span class="exp-group__hint">GitHub / PoC</span>
            <span class="exp-group__count">{{ totalCatalogMatched }}</span>
          </div>
          <button
            v-for="card in filteredExploitCards"
            :key="card.id"
            class="exp-item exp-item--poc"
            :class="{ 'is-active': selectedExploit?.id === card.id, 'is-matched': activeExploitMatches.has(card.id) }"
            @click="selectExploit(card)"
          >
            <span class="exp-item__label">{{ card.title }}</span>
            <span class="exp-item__id">{{ card.cves.join(', ') }}</span>
            <span v-if="activeExploitMatches.has(card.id)" class="exp-item__match">已命中</span>
          </button>
          <div v-if="!filteredExploitCards.length" class="exp-rail__empty">无匹配 EXP</div>
        </div>
      </div>
    </aside>

    <!-- RIGHT PANE -->
    <section class="exp-pane">
      <template v-if="selectedExploit">
        <header class="exp-pane__head">
          <span class="exp-mode-tag is-dangerous">{{ confidenceLabel(selectedExploit.confidence) }}</span>
          <span class="exp-kind-tag">{{ categoryLabel(selectedExploit.category) }}</span>
          <div class="exp-pane__title">
            <div class="exp-pane__name">{{ selectedExploit.title }}</div>
            <div class="exp-pane__summary">{{ selectedExploit.cves.join(' / ') }}</div>
          </div>
        </header>

        <div class="exp-meta">
          <div v-if="activeExploitMatches.has(selectedExploit.id)" class="exp-meta__row">
            <span class="exp-meta__label">扫描命中</span>
            <span class="exp-meta__value accent">{{ confidenceLabel(selectedExploitMatch?.confidence || '') }} · {{ selectedExploitMatch?.reason }}</span>
          </div>
          <div v-if="selectedExploitMatch?.evidenceFactIds.length" class="exp-meta__row">
            <span class="exp-meta__label">证据</span>
            <span class="exp-meta__value mono">{{ selectedExploitMatch.evidenceFactIds.join(', ') }}</span>
          </div>
          <div v-if="selectedExploitMatch?.missingPrerequisites.length" class="exp-meta__row">
            <span class="exp-meta__label">缺口</span>
            <ul class="exp-meta__list">
              <li v-for="item in selectedExploitMatch.missingPrerequisites" :key="item">{{ item }}</li>
            </ul>
          </div>
          <div v-if="selectedExploit.target.distro" class="exp-meta__row">
            <span class="exp-meta__label">发行版</span>
            <span class="exp-meta__value">{{ selectedExploit.target.distro }}</span>
          </div>
          <div v-if="selectedExploit.target.package" class="exp-meta__row">
            <span class="exp-meta__label">组件</span>
            <span class="exp-meta__value">{{ selectedExploit.target.package }}</span>
          </div>
          <div v-if="selectedExploit.target.kernel" class="exp-meta__row">
            <span class="exp-meta__label">内核</span>
            <span class="exp-meta__value">{{ selectedExploit.target.kernel }}</span>
          </div>
          <div v-if="selectedExploit.target.arch" class="exp-meta__row">
            <span class="exp-meta__label">架构</span>
            <span class="exp-meta__value">{{ selectedExploit.target.arch }}</span>
          </div>
        </div>

        <div class="exp-usage">
          <div class="exp-params__title">使用方法</div>

          <div v-if="selectedExploit.usage?.officialOnline" class="exp-usage__block">
            <div class="exp-usage__head">
              <span>目标可出网：一键 payload</span>
              <button class="exp-mini-btn" @click="copyText(selectedExploit.usage.officialOnline.command)">复制</button>
            </div>
            <div class="exp-usage__note">来源：{{ selectedExploit.usage.officialOnline.project }}</div>
            <pre class="exp-result__pre">{{ selectedExploit.usage.officialOnline.command }}</pre>
            <div class="exp-usage__note">{{ selectedExploit.usage.officialOnline.note }}</div>
          </div>

          <div v-else class="exp-usage__block">
            <div class="exp-usage__head">
              <span>未确认公开一键 payload</span>
            </div>
            <div class="exp-usage__note">直接查看下方 GitHub 链接，根据 README 在授权实验环境中自行编译或选择目标版本参数。</div>
          </div>

        </div>

        <div v-if="selectedExploit.method" class="exp-method">
          <div
            v-for="section in methodSections"
            :key="section.key"
            class="exp-method__section"
            :class="`is-${section.tone}`"
          >
            <div class="exp-method__head">
              <span class="exp-method__icon" aria-hidden="true">
                <component :is="section.icon" />
              </span>
              <span class="exp-method__title">{{ section.label }}</span>
              <span class="exp-method__hint">{{ section.hint }}</span>
            </div>
            <pre class="exp-method__pre">{{ section.lines.join('\n') }}</pre>
          </div>
          <div v-if="selectedExploit.method.notes.length" class="exp-method__section">
            <div class="exp-method__head">
              <span class="exp-method__icon" aria-hidden="true">
                <Memo />
              </span>
              <span class="exp-method__title">备注</span>
              <span class="exp-method__hint">版本差异、限制和人工复核点</span>
            </div>
            <ul class="exp-method__notes">
              <li v-for="item in selectedExploit.method.notes" :key="item">{{ item }}</li>
            </ul>
          </div>
        </div>

        <div class="exp-sources">
          <div class="exp-params__title">来源</div>
          <a
            v-for="source in selectedExploit.sources"
            :key="source.url"
            class="exp-source"
            :href="source.url"
            target="_blank"
            rel="noreferrer"
          >
            <span class="exp-source__role">{{ sourceRoleLabel(source.role) }}</span>
            <span class="exp-source__body">
              <span class="exp-source__name">{{ source.name }}</span>
              <span v-if="source.note" class="exp-source__note">{{ source.note }}</span>
            </span>
            <span v-if="source.language" class="exp-source__lang">{{ source.language }}</span>
          </a>
        </div>

      </template>

      <template v-else>
        <div class="exp-pane__placeholder">从左侧选择 Linux 漏洞条目</div>
      </template>
    </section>
  </div>
</template>

<style scoped>
.exp { display: flex; height: 100%; min-height: 0; gap: 1px; background: var(--kg-border); border: 1px solid var(--kg-border); border-radius: 8px; overflow: hidden; }

/* Rail */
.exp-rail { width: 280px; min-width: 220px; display: flex; flex-direction: column; background: color-mix(in srgb, var(--kg-surface) 80%, var(--kg-bg)); }
.exp-search { display: flex; align-items: center; gap: 6px; padding: 10px; border-bottom: 1px solid var(--kg-border); background: var(--kg-surface); }
.exp-search input { flex: 1; min-width: 0; background: var(--kg-bg); border: 1px solid var(--kg-border); border-radius: 6px; padding: 7px 9px; color: var(--kg-text); font-size: 12px; outline: none; }
.exp-search input:focus { border-color: var(--kg-accent); box-shadow: 0 0 0 3px var(--kg-accent-ring); }
.exp-search__count { font-size: 10px; color: var(--kg-text-muted); min-width: 18px; text-align: center; }
.exp-rail__loading { padding: 20px; text-align: center; color: var(--kg-text-muted); font-size: 12px; }
.exp-rail__body { flex: 1; min-height: 0; overflow-y: auto; padding: 6px; }
.exp-rail__empty { padding: 20px; text-align: center; color: var(--kg-text-dim); font-size: 12px; }

/* Groups */
.exp-group { margin-bottom: 8px; }
.exp-group__head { display: flex; align-items: center; gap: 6px; padding: 6px 8px; font-size: 10px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; }
.exp-group__head.is-safe { color: var(--kg-accent); }
.exp-group__head.is-full { color: var(--kg-warn); }
.exp-group__head.is-dangerous { color: var(--kg-danger); }
.exp-group__hint { color: var(--kg-text-dim); font-weight: 400; }
.exp-group__count { margin-left: auto; background: var(--kg-surface-2); border-radius: 4px; padding: 1px 5px; font-size: 9px; }

/* Items */
.exp-item { position: relative; display: flex; flex-direction: column; width: 100%; text-align: left; padding: 8px 9px 8px 11px; border: 1px solid transparent; border-radius: 7px; background: transparent; cursor: pointer; transition: background var(--kg-dur) var(--kg-ease), border-color var(--kg-dur) var(--kg-ease); }
.exp-item:hover { background: var(--kg-surface); border-color: var(--kg-border); }
.exp-item.is-active { background: var(--kg-surface-2); border-color: color-mix(in srgb, var(--kg-accent) 58%, var(--kg-border)); box-shadow: inset 2px 0 0 var(--kg-accent); }
.exp-item--poc.is-active { border-color: color-mix(in srgb, var(--kg-danger) 58%, var(--kg-border)); box-shadow: inset 2px 0 0 var(--kg-danger); }
.exp-item--poc.is-matched { background: color-mix(in srgb, var(--kg-danger) 12%, var(--kg-bg)); }
.exp-item__label { font-size: 12px; color: var(--kg-text); line-height: 1.3; }
.exp-item__id { margin-top: 2px; font-size: 10px; color: var(--kg-text-dim); font-family: var(--kg-font-mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.exp-item__match { width: fit-content; margin-top: 3px; padding: 1px 5px; border-radius: 3px; background: var(--kg-danger); color: #fff; font-size: 9px; font-weight: 700; text-transform: uppercase; }
.exp-library { margin-top: 8px; padding-top: 8px; border-top: 1px solid var(--kg-border); }

/* Pane */
.exp-pane { flex: 1; min-width: 0; min-height: 0; display: flex; flex-direction: column; background: var(--kg-bg); overflow-y: auto; padding: 16px; gap: 14px; }
.exp-pane__placeholder { display: flex; align-items: center; justify-content: center; height: 100%; color: var(--kg-text-dim); font-size: 14px; }
.exp-pane__head { display: flex; align-items: flex-start; gap: 8px; padding-bottom: 2px; }
.exp-pane__title { flex: 1; min-width: 0; }
.exp-pane__name { font-size: 15px; font-weight: 600; color: var(--kg-text); }
.exp-pane__summary { font-size: 12px; color: var(--kg-text-muted); margin-top: 3px; line-height: 1.45; }

/* Tags */
.exp-mode-tag { font-size: 10px; font-weight: 700; padding: 2px 6px; border-radius: 3px; text-transform: uppercase; }
.exp-mode-tag.is-safe { background: var(--kg-accent); color: #fff; }
.exp-mode-tag.is-full { background: var(--kg-warn); color: #fff; }
.exp-mode-tag.is-dangerous { background: var(--kg-danger); color: #fff; }
.exp-kind-tag { font-size: 10px; padding: 2px 6px; border-radius: 3px; background: var(--kg-surface-2); color: var(--kg-text-muted); }

/* Meta */
.exp-meta { display: flex; flex-direction: column; gap: 9px; padding: 12px; border-radius: 8px; background: var(--kg-surface); border: 1px solid var(--kg-border); }
.exp-meta__row { display: flex; gap: 10px; font-size: 12px; min-width: 0; }
.exp-meta__label { min-width: 100px; font-weight: 600; color: var(--kg-text-muted); flex-shrink: 0; }
.exp-meta__value { color: var(--kg-text); }
.exp-meta__value.mono { font-family: var(--kg-font-mono); font-size: 11px; word-break: break-all; }
.exp-meta__value.accent { color: var(--kg-accent); font-weight: 600; }
.exp-meta__list { margin: 0; padding-left: 16px; color: var(--kg-text); }
.exp-meta__list li { margin-bottom: 2px; }

/* Params */
.exp-params { display: flex; flex-direction: column; gap: 8px; padding: 12px; border: 1px solid var(--kg-border); border-radius: 8px; background: color-mix(in srgb, var(--kg-surface) 78%, var(--kg-bg)); }
.exp-params__title { font-size: 13px; font-weight: 600; color: var(--kg-text); }
.exp-param-row { display: grid; grid-template-columns: minmax(120px, 160px) minmax(0, 1fr) minmax(120px, 220px); align-items: center; gap: 8px; }
.exp-param-row__label { min-width: 140px; font-size: 12px; font-family: var(--kg-font-mono); color: var(--kg-text-muted); }
.exp-param-row__input { min-width: 0; background: var(--kg-bg); border: 1px solid var(--kg-border); border-radius: 6px; padding: 7px 8px; color: var(--kg-text); font-size: 12px; font-family: var(--kg-font-mono); outline: none; }
.exp-param-row__input:focus { border-color: var(--kg-accent); box-shadow: 0 0 0 3px var(--kg-accent-ring); }
.exp-param-row__doc { font-size: 10px; color: var(--kg-text-dim); max-width: 200px; }

/* Actions */
.exp-actions { display: flex; gap: 8px; }
.exp-btn-generate { padding: 8px 20px; border: none; border-radius: 6px; background: var(--kg-accent); color: #fff; font-size: 13px; font-weight: 600; cursor: pointer; transition: opacity 0.15s; }
.exp-btn-generate:hover { opacity: 0.9; }
.exp-btn-generate:disabled { opacity: 0.5; cursor: not-allowed; }
.exp-btn-generate.is-danger { background: var(--kg-danger); }
.exp-btn-secondary { padding: 7px 14px; border: 1px solid var(--kg-border); border-radius: 6px; background: var(--kg-surface-2); color: var(--kg-text); font-size: 12px; font-weight: 600; cursor: pointer; }
.exp-btn-secondary:hover { border-color: var(--kg-accent); }

/* Result */
.exp-result { display: flex; flex-direction: column; gap: 10px; padding: 12px; border-radius: 8px; background: var(--kg-surface); border: 1px solid var(--kg-accent); }
.exp-result__title { font-size: 13px; font-weight: 600; color: var(--kg-accent); }
.exp-result__row { display: flex; flex-direction: column; gap: 4px; font-size: 12px; }
.exp-result__label { font-weight: 600; color: var(--kg-text-muted); }
.exp-result__value { font-family: var(--kg-font-mono); font-size: 11px; color: var(--kg-text); word-break: break-all; }
.exp-result__files { margin: 0; padding-left: 16px; }
.exp-result__files li { margin-bottom: 2px; }
.exp-result__files code { font-size: 11px; }
.exp-result__pre { margin: 0; padding: 8px; border-radius: 4px; background: var(--kg-surface-2); font-family: var(--kg-font-mono); font-size: 11px; color: var(--kg-text); white-space: pre-wrap; word-break: break-all; overflow-x: auto; }
.exp-binary-file { display: flex; align-items: center; gap: 8px; min-width: 0; padding: 8px; border-radius: 6px; background: var(--kg-surface-2); }
.exp-binary-file code { flex: 1; min-width: 0; }
.exp-mini-btn { flex-shrink: 0; padding: 4px 8px; border: 1px solid var(--kg-border); border-radius: 5px; background: var(--kg-bg); color: var(--kg-text); font-size: 11px; font-weight: 600; cursor: pointer; }
.exp-mini-btn:hover { border-color: var(--kg-accent); color: var(--kg-accent); }

.exp-usage { display: flex; flex-direction: column; gap: 10px; padding: 12px; border: 1px solid color-mix(in srgb, var(--kg-danger) 42%, var(--kg-border)); border-radius: 8px; background: color-mix(in srgb, var(--kg-danger) 7%, var(--kg-surface)); }
.exp-usage__block { display: flex; flex-direction: column; gap: 7px; min-width: 0; }
.exp-usage__head { display: flex; align-items: center; justify-content: space-between; gap: 8px; font-size: 12px; font-weight: 700; color: var(--kg-text); }
.exp-usage__note { font-size: 11px; color: var(--kg-text-muted); line-height: 1.45; }

.exp-method { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
.exp-method__section { position: relative; min-width: 0; overflow: hidden; border: 1px solid var(--kg-border); border-radius: 8px; background: color-mix(in srgb, var(--kg-surface) 88%, var(--kg-bg)); }
.exp-method__section::before { content: ""; position: absolute; inset: 0 auto 0 0; width: 3px; background: var(--kg-text-dim); }
.exp-method__section.is-verify::before { background: var(--kg-accent); }
.exp-method__section.is-build::before { background: var(--kg-warn); }
.exp-method__section.is-run::before { background: var(--kg-danger); }
.exp-method__section.is-cleanup::before { background: color-mix(in srgb, var(--kg-accent) 55%, var(--kg-text-muted)); }
.exp-method__head { display: grid; grid-template-columns: 24px minmax(max-content, auto) minmax(0, 1fr); align-items: center; gap: 8px; padding: 10px 11px 9px 13px; border-bottom: 1px solid color-mix(in srgb, var(--kg-border) 78%, transparent); }
.exp-method__icon { display: inline-flex; align-items: center; justify-content: center; width: 24px; height: 24px; border-radius: 6px; background: var(--kg-surface-2); color: var(--kg-text-muted); }
.exp-method__icon svg { width: 14px; height: 14px; }
.exp-method__section.is-verify .exp-method__icon { color: var(--kg-accent); background: color-mix(in srgb, var(--kg-accent) 12%, var(--kg-surface-2)); }
.exp-method__section.is-build .exp-method__icon { color: var(--kg-warn); background: color-mix(in srgb, var(--kg-warn) 14%, var(--kg-surface-2)); }
.exp-method__section.is-run .exp-method__icon { color: var(--kg-danger); background: color-mix(in srgb, var(--kg-danger) 12%, var(--kg-surface-2)); }
.exp-method__section.is-cleanup .exp-method__icon { color: color-mix(in srgb, var(--kg-accent) 65%, var(--kg-text-muted)); background: color-mix(in srgb, var(--kg-accent) 9%, var(--kg-surface-2)); }
.exp-method__title { width: fit-content; white-space: nowrap; padding: 3px 7px; border: 1px solid var(--kg-border); border-radius: 999px; background: var(--kg-bg); color: var(--kg-text); font-size: 12px; font-weight: 700; line-height: 1.1; }
.exp-method__hint { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--kg-text-dim); font-size: 11px; }
.exp-method__pre { margin: 0; min-height: 54px; padding: 10px 11px 11px 13px; background: color-mix(in srgb, var(--kg-bg) 76%, var(--kg-surface-2)); color: var(--kg-text); font-family: var(--kg-font-mono); font-size: 11px; line-height: 1.55; white-space: pre-wrap; word-break: break-word; overflow-x: auto; }
.exp-method__notes { margin: 0; padding: 10px 12px 11px 30px; color: var(--kg-text); font-size: 12px; line-height: 1.55; background: color-mix(in srgb, var(--kg-bg) 76%, var(--kg-surface-2)); }
.exp-method__notes li { margin-bottom: 4px; }
.exp-method__notes li:last-child { margin-bottom: 0; }

.exp-sources { display: flex; flex-direction: column; gap: 8px; }
.exp-source { display: flex; align-items: center; gap: 8px; padding: 8px 10px; border: 1px solid var(--kg-border); border-radius: 6px; background: var(--kg-surface); color: var(--kg-text); text-decoration: none; }
.exp-source:hover { border-color: var(--kg-accent); }
.exp-source__role { min-width: 48px; padding: 1px 5px; border-radius: 3px; background: var(--kg-surface-2); color: var(--kg-text-muted); font-size: 10px; font-weight: 700; text-transform: uppercase; }
.exp-source__body { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.exp-source__name { font-size: 12px; }
.exp-source__note { font-size: 10px; color: var(--kg-text-dim); line-height: 1.35; }
.exp-source__lang { font-size: 10px; color: var(--kg-text-dim); font-family: var(--kg-font-mono); }
@media (max-width: 900px) {
  .exp { flex-direction: column; }
  .exp-rail { width: auto; max-height: 260px; }
  .exp-method { grid-template-columns: 1fr; }
  .exp-method__head { grid-template-columns: 24px minmax(max-content, auto); }
  .exp-method__hint { grid-column: 2; white-space: normal; }
  .exp-param-row { grid-template-columns: 1fr; align-items: stretch; }
  .exp-param-row__label { min-width: 0; }
}
</style>
