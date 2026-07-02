<script setup lang="ts">
import { onMounted } from 'vue'
import { useClusterStore } from './stores/cluster'
import ClusterSidebar from './components/ClusterSidebar.vue'

const cs = useClusterStore()
onMounted(() => { cs.refresh() })
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
