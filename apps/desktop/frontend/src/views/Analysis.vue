<script setup lang="ts">
import { useScanStore } from '../stores/scan'
import AgentPanel from '../components/AgentPanel.vue'

const scanStore = useScanStore()
</script>

<template>
  <el-header class="layout-header">
    <b style="font-size:14px;font-weight:600">AI 智能攻击</b>
    <span v-if="scanStore.activeResultId" class="analysis-badge">
      {{ scanStore.results.find(r => r.id === scanStore.activeResultId)?.factCount || 0 }} facts
    </span>
  </el-header>
  <el-main class="layout-main analysis-main">
    <AgentPanel />
  </el-main>
</template>

<style scoped>
.analysis-main {
  padding: 0;
  display: flex;
  flex-direction: column;
}
.analysis-main :deep(.agent-panel) {
  flex: 1;
}
.analysis-badge {
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 4px;
  background: var(--kg-accent-soft);
  color: var(--kg-accent);
  font-family: var(--kg-font-mono);
  font-weight: 500;
  margin-left: 8px;
}
</style>
