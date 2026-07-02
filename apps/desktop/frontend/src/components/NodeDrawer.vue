<script setup lang="ts">
import { ref, watch } from 'vue'
import NodeTerminal from './NodeTerminal.vue'
import NodeFiles from './NodeFiles.vue'

const props = defineProps<{
  clusterId: string
  node: string
}>()
const emit = defineEmits<{ (e: 'close'): void }>()

const open = ref(true)
const tab = ref('terminal')

watch(() => props.node, () => { tab.value = 'terminal' })

function onClose() {
  open.value = false
  emit('close')
}
</script>

<template>
  <el-drawer v-model="open" :title="`Node: ${node}`" size="70%" @close="onClose" destroy-on-close>
    <el-tabs v-model="tab" type="border-card">
      <el-tab-pane label="终端" name="terminal" lazy>
        <NodeTerminal :cluster-id="clusterId" :node="node" />
      </el-tab-pane>
      <el-tab-pane label="文件" name="files" lazy>
        <NodeFiles :cluster-id="clusterId" :node="node" />
      </el-tab-pane>
    </el-tabs>
  </el-drawer>
</template>
