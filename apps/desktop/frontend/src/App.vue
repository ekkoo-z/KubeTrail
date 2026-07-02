<script setup lang="ts">
import { onMounted } from 'vue'
import { useClusterStore } from './stores/cluster'
import ClusterSidebar from './components/ClusterSidebar.vue'
import { api } from './api/wails'
import { setLocale } from './i18n'

const cs = useClusterStore()
onMounted(async () => {
  cs.refresh()
  try {
    const cfg = await api.GetAgentDisplayConfig()
    if ((cfg as any)?.language) {
      setLocale((cfg as any).language)
    }
  } catch {}
})
</script>

<template>
  <el-container class="layout-root">
    <el-aside width="240px" class="layout-aside">
      <ClusterSidebar />
    </el-aside>
    <el-container direction="vertical">
      <router-view />
    </el-container>
  </el-container>
</template>
