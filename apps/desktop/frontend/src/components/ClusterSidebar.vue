<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage } from 'element-plus/es/components/message/index'
import { ElMessageBox } from 'element-plus/es/components/message-box/index'
import { useClusterStore } from '../stores/cluster'
import { t } from '../i18n'
import ConnectionForm from './ConnectionForm.vue'
import avatarUrl from '../assets/brand/kubetrail-avatar.png'

const cs = useClusterStore()
const router = useRouter()
const route = useRoute()
const showForm = ref(false)

const activeId = computed(() => route.params.id as string | undefined)
const activeName = computed(() => route.name as string | undefined)

async function open(id: string) {
  try {
    if (!cs.connected[id]) await cs.connect(id)
    router.push({ name: 'cluster', params: { id } })
  } catch (e: any) {
    ElMessage.error(`${t('连接失败')}: ${e?.message || e}`)
  }
}

async function remove(id: string, name: string) {
  try {
    await ElMessageBox.confirm(t('确认删除集群 {name}？').replace('{name}', name), t('确认'), { type: 'warning' })
    await cs.remove(id)
    ElMessage.success(t('已删除'))
  } catch {}
}

function onSaved() {
  showForm.value = false
  cs.refresh()
}

function typeLabel(t: string) {
  return t === 'kubeconfig' ? 'kc' : 'tk'
}
</script>

<template>
  <aside class="sb">
    <!-- ============ brand ============ -->
    <header class="sb-brand" role="button" tabindex="0" @click="router.push({ name: 'welcome' })" @keydown.enter.prevent="router.push({ name: 'welcome' })">
      <div class="sb-logo" aria-hidden="true">
        <img :src="avatarUrl" alt="" />
      </div>
      <div class="sb-brand__text">
        <div class="sb-brand__name">KubeTrail</div>
        <div class="sb-brand__tag">Red-team client</div>
      </div>
    </header>

    <!-- ============ clusters ============ -->
    <section class="sb-section">
      <div class="sb-section__head">
        <span class="sb-section__label">Clusters</span>
        <span class="sb-section__count">{{ cs.entries.length }}</span>
        <button class="sb-icon-btn" @click="showForm = true" :title="t('新增集群')" :aria-label="t('新增集群')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="12" y1="5" x2="12" y2="19"/>
            <line x1="5" y1="12" x2="19" y2="12"/>
          </svg>
        </button>
      </div>

      <nav class="sb-list">
        <button
          v-for="c in cs.entries"
          :key="c.id"
          class="sb-item"
          :class="{ 'is-active': activeId === c.id }"
          @click="open(c.id)"
        >
          <span
            class="sb-item__dot"
            :class="{
              'is-on':  !!cs.connected[c.id],
              'is-proxy': !!c.apiPathPrefix,
            }"
            :title="cs.connected[c.id] ? 'connected' : 'idle'"
          />
          <span class="sb-item__name">{{ c.name }}</span>
          <span
            v-if="c.apiPathPrefix"
            class="sb-item__hint"
            title="via proxy / aggregated apiserver"
          >prx</span>
          <span class="sb-item__type">{{ typeLabel(c.type) }}</span>
          <button
            class="sb-item__rm"
            @click.stop="remove(c.id, c.name)"
            :title="t('删除')"
            :aria-label="t('删除集群')"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M6 6 L18 18 M18 6 L6 18"/>
            </svg>
          </button>
        </button>

        <div v-if="!cs.entries.length" class="sb-empty">
          <div class="sb-empty__title">No clusters</div>
          <button class="sb-empty__cta" @click="showForm = true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <line x1="12" y1="5" x2="12" y2="19"/>
              <line x1="5" y1="12" x2="19" y2="12"/>
            </svg>
            {{ t('添加第一个集群') }}
          </button>
        </div>
      </nav>
    </section>

    <!-- ============ toolkit ============ -->
    <section class="sb-section">
      <div class="sb-section__head">
        <span class="sb-section__label">Toolkit</span>
      </div>
      <nav class="sb-list">
        <button
          class="sb-item"
          :class="{ 'is-active': activeName === 'analysis' }"
          @click="router.push({ name: 'analysis' })"
        >
          <span class="sb-item__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/>
            </svg>
          </span>
          <span class="sb-item__name">{{ t('智能攻击') }}</span>
        </button>
        <button
          class="sb-item"
          :class="{ 'is-active': activeName === 'cheatsheet' }"
          @click="router.push({ name: 'cheatsheet' })"
        >
          <span class="sb-item__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="6 7 10 12 6 17"/>
              <line x1="12" y1="17" x2="18" y2="17"/>
            </svg>
          </span>
          <span class="sb-item__name">{{ t('命令速查') }}</span>
        </button>
        <button
          class="sb-item"
          :class="{ 'is-active': activeName === 'settings' }"
          @click="router.push({ name: 'settings' })"
        >
          <span class="sb-item__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="3"/>
              <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9c.26.604.852.997 1.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/>
            </svg>
          </span>
          <span class="sb-item__name">{{ t('Agent 设置') }}</span>
        </button>
        <button
          class="sb-item"
          :class="{ 'is-active': activeName === 'about' }"
          @click="router.push({ name: 'about' })"
        >
          <span class="sb-item__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="16" x2="12" y2="12"/>
              <line x1="12" y1="8" x2="12.01" y2="8"/>
            </svg>
          </span>
          <span class="sb-item__name">{{ t('关于项目') }}</span>
        </button>
      </nav>
    </section>

    <!-- ============ footer ============ -->
    <footer class="sb-foot">
      <span class="sb-foot__dot" />
      <span>Open Source v1.0 by ekkoo</span>
    </footer>

    <el-dialog v-model="showForm" :title="t('新增集群')" width="680px" destroy-on-close>
      <ConnectionForm @saved="onSaved" @cancel="showForm = false" />
    </el-dialog>
  </aside>
</template>

<style scoped>
/* ============= layout ============= */
.sb {
  display: flex;
  flex-direction: column;
  height: 100%;
  padding: 0;
  font-family: var(--kg-font-sans);
}

/* ============= brand ============= */
.sb-brand {
  display: flex;
  align-items: center;
  gap: 11px;
  padding: 18px 16px 16px;
  border-bottom: 1px solid var(--kg-border-soft);
  cursor: pointer;
  outline: none;
  transition: background var(--kg-dur) var(--kg-ease);
}
.sb-brand:hover { background: color-mix(in srgb, var(--kg-surface-2) 46%, transparent); }
.sb-logo {
  width: 38px;
  height: 38px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 9px;
  background: #030805;
  box-shadow: 0 2px 10px -2px rgba(16, 185, 129, 0.5),
              0 0 0 1px color-mix(in srgb, var(--kg-accent) 45%, var(--kg-border));
  flex-shrink: 0;
  overflow: hidden;
}
.sb-logo img { width: 100%; height: 100%; object-fit: cover; display: block; }
.sb-brand__text { line-height: 1.15; }
.sb-brand__name {
  font-size: 14.5px;
  font-weight: 600;
  letter-spacing: -0.1px;
  color: var(--kg-text);
}
.sb-brand__tag {
  font-family: var(--kg-font-mono);
  font-size: 10px;
  letter-spacing: 0.8px;
  color: var(--kg-text-dim);
  text-transform: uppercase;
  margin-top: 2px;
}

/* ============= section ============= */
.sb-section {
  padding: 14px 0 6px;
}
.sb-section__head {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0 16px 8px;
}
.sb-section__label {
  font-family: var(--kg-font-mono);
  font-size: 10.5px;
  font-weight: 600;
  letter-spacing: 1.4px;
  color: var(--kg-text-dim);
  text-transform: uppercase;
}
.sb-section__count {
  font-family: var(--kg-font-mono);
  font-size: 10.5px;
  font-weight: 500;
  color: var(--kg-text-muted);
  padding: 1px 6px;
  border-radius: 8px;
  background: var(--kg-surface-2);
  border: 1px solid var(--kg-border-soft);
}
.sb-section__head .sb-icon-btn { margin-left: auto; }

/* ============= icon button (add etc.) ============= */
.sb-icon-btn {
  width: 22px;
  height: 22px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: none;
  border-radius: 5px;
  color: var(--kg-text-dim);
  cursor: pointer;
  transition: background .15s var(--kg-ease), color .15s var(--kg-ease);
}
.sb-icon-btn:hover {
  background: var(--kg-surface-2);
  color: var(--kg-accent);
}
.sb-icon-btn:active { transform: scale(0.94); }
.sb-icon-btn svg { width: 14px; height: 14px; }

/* ============= list ============= */
.sb-list {
  display: flex;
  flex-direction: column;
  gap: 1px;
  padding: 0 8px;
}

/* ============= item ============= */
.sb-item {
  position: relative;
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  padding: 7px 10px 7px 12px;
  background: transparent;
  border: none;
  border-radius: 6px;
  color: var(--kg-text-muted);
  font-family: inherit;
  font-size: 13px;
  cursor: pointer;
  text-align: left;
  transition: background .15s var(--kg-ease), color .15s var(--kg-ease);
}
.sb-item:hover {
  background: var(--kg-surface-2);
  color: var(--kg-text);
}
.sb-item.is-active {
  background: var(--kg-accent-soft);
  color: var(--kg-text);
}
.sb-item.is-active::before {
  content: '';
  position: absolute;
  left: 2px;
  top: 8px;
  bottom: 8px;
  width: 2px;
  border-radius: 1px;
  background: var(--kg-accent);
}

/* status dot for cluster rows */
.sb-item__dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--kg-text-dim);
  box-shadow: 0 0 0 2px rgba(90, 100, 120, 0.16);
  flex-shrink: 0;
  transition: background .18s, box-shadow .18s;
}
.sb-item__dot.is-on {
  background: var(--kg-accent);
  box-shadow: 0 0 0 2px var(--kg-accent-soft);
}
.sb-item__dot.is-proxy {
  background: var(--kg-warn);
  box-shadow: 0 0 0 2px var(--kg-warn-soft);
}
.sb-item__dot.is-on.is-proxy {
  background: var(--kg-accent);
  box-shadow: 0 0 0 2px var(--kg-warn-soft);
}

/* icon slot for non-cluster items */
.sb-item__icon {
  width: 16px;
  height: 16px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: var(--kg-text-muted);
  flex-shrink: 0;
}
.sb-item:hover .sb-item__icon,
.sb-item.is-active .sb-item__icon { color: var(--kg-accent); }
.sb-item__icon svg { width: 15px; height: 15px; }

.sb-item__name {
  flex: 1;
  font-size: 13px;
  font-weight: 500;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  min-width: 0;
}

/* tiny mono tag at right: kc / tk */
.sb-item__type {
  font-family: var(--kg-font-mono);
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.6px;
  color: var(--kg-text-dim);
  text-transform: lowercase;
  padding: 1px 5px;
  border-radius: 3px;
  background: transparent;
  transition: color .15s;
}
.sb-item:hover .sb-item__type { color: var(--kg-text-muted); }
.sb-item.is-active .sb-item__type {
  color: var(--kg-accent);
  background: var(--kg-accent-soft);
}

/* proxy hint */
.sb-item__hint {
  font-family: var(--kg-font-mono);
  font-size: 10px;
  font-weight: 600;
  color: var(--kg-warn);
  padding: 1px 5px;
  border-radius: 3px;
  background: var(--kg-warn-soft);
  letter-spacing: 0.5px;
}

/* remove (× on hover) */
.sb-item__rm {
  width: 18px;
  height: 18px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: none;
  border-radius: 4px;
  color: var(--kg-text-dim);
  cursor: pointer;
  opacity: 0;
  transition: opacity .15s, color .15s, background .15s;
}
.sb-item:hover .sb-item__rm { opacity: 1; }
.sb-item__rm:hover {
  color: var(--kg-danger);
  background: var(--kg-danger-soft);
}
.sb-item__rm svg { width: 11px; height: 11px; }

/* hide the kc/tk + prx + × stack subtly on hover so name has more room visually */
.sb-item:hover .sb-item__type,
.sb-item:hover .sb-item__hint { opacity: 0.7; }

/* ============= empty state ============= */
.sb-empty {
  padding: 22px 14px 8px;
  text-align: center;
}
.sb-empty__title {
  font-family: var(--kg-font-mono);
  font-size: 11px;
  letter-spacing: 1px;
  color: var(--kg-text-dim);
  text-transform: uppercase;
  margin-bottom: 10px;
}
.sb-empty__cta {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 7px 11px;
  background: transparent;
  border: 1px dashed var(--kg-border);
  border-radius: 6px;
  color: var(--kg-text-muted);
  font-family: inherit;
  font-size: 12px;
  cursor: pointer;
  transition: border-color .15s, color .15s, background .15s;
}
.sb-empty__cta:hover {
  border-color: var(--kg-accent);
  color: var(--kg-accent);
  border-style: solid;
  background: var(--kg-accent-soft);
}
.sb-empty__cta svg { width: 12px; height: 12px; }

/* ============= footer ============= */
.sb-foot {
  margin-top: auto;
  padding: 12px 16px;
  display: flex;
  align-items: center;
  gap: 8px;
  border-top: 1px solid var(--kg-border-soft);
  font-family: var(--kg-font-mono);
  font-size: 10.5px;
  color: var(--kg-text-dim);
  letter-spacing: 0.3px;
}
.sb-foot__dot {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: var(--kg-accent);
  box-shadow: 0 0 6px var(--kg-accent);
  flex-shrink: 0;
}
</style>
