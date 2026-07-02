import {defineConfig} from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [vue()],
  build: {
    rollupOptions: {
      onwarn(warning, warn) {
        if (
          warning.code === 'INVALID_ANNOTATION' &&
          warning.id?.includes('/@vueuse/core/')
        ) {
          return
        }
        warn(warning)
      },
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return
          if (id.includes('/@xterm/')) return 'xterm'
          if (id.includes('/@element-plus/icons-vue/')) return 'element-plus-icons'
          if (id.includes('/element-plus/es/components/')) {
            const match = id.match(/\/element-plus\/es\/components\/([^/]+)/)
            return match ? `element-plus-${match[1]}` : 'element-plus-components'
          }
          if (id.includes('/element-plus/')) return 'element-plus-core'
          if (id.includes('/vue') || id.includes('/vue-router/') || id.includes('/pinia/')) return 'vue'
          return 'vendor'
        },
      },
    },
  },
})
