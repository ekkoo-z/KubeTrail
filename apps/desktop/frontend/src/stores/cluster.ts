import { defineStore } from 'pinia'
import { api } from '../api/wails'

export interface ClusterEntry {
  id: string
  name: string
  type: 'kubeconfig' | 'token'
  apiServer?: string
  namespace?: string
  insecure?: boolean
  apiPathPrefix?: string
}

export interface ConnectedInfo {
  id: string
  name: string
  version: string
  namespace: string
  apiServer: string
}

export const useClusterStore = defineStore('cluster', {
  state: () => ({
    entries: [] as ClusterEntry[],
    connected: {} as Record<string, ConnectedInfo>,
    loading: false,
  }),
  actions: {
    async refresh() {
      this.loading = true
      try {
        const list = (await api.ListClusters()) as any[]
        this.entries = (list || []).map((e) => ({
          id: e.id,
          name: e.name,
          type: e.type,
          apiServer: e.apiServer,
          namespace: e.namespace,
          insecure: e.insecure,
          apiPathPrefix: e.apiPathPrefix,
        }))
      } finally {
        this.loading = false
      }
    },
    async connect(id: string) {
      const info = (await api.ConnectCluster(id)) as ConnectedInfo
      this.connected[id] = info
      return info
    },
    disconnect(id: string) {
      api.DisconnectCluster(id)
      delete this.connected[id]
    },
    async remove(id: string) {
      await api.DeleteCluster(id)
      delete this.connected[id]
      await this.refresh()
    },
  },
})
