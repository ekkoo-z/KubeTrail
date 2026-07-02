import { defineStore } from 'pinia'
import { ref } from 'vue'

export interface ScanResult {
  id: string
  source: string
  sourcePath?: string
  loadedAt: string
  factCount: number
  errorCount: number
  document?: any
}

export const useScanStore = defineStore('scan', () => {
  const results = ref<ScanResult[]>([])
  const activeResultId = ref<string | null>(null)
  const scanning = ref(false)

  function addResult(r: ScanResult) {
    results.value = results.value.filter(x => x.id !== r.id)
    results.value.unshift(r)
    activeResultId.value = r.id
  }

  function removeResult(id: string) {
    results.value = results.value.filter(x => x.id !== id)
    if (activeResultId.value === id) {
      activeResultId.value = results.value[0]?.id ?? null
    }
  }

  function setActive(id: string) {
    activeResultId.value = id
  }

  return { results, activeResultId, scanning, addResult, removeResult, setActive }
})
