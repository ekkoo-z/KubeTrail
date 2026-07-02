import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { ElButton } from 'element-plus/es/components/button/index'
import { ElCard } from 'element-plus/es/components/card/index'
import { ElCollapse, ElCollapseItem } from 'element-plus/es/components/collapse/index'
import { ElAside, ElContainer, ElHeader, ElMain } from 'element-plus/es/components/container/index'
import { ElDialog } from 'element-plus/es/components/dialog/index'
import { ElDivider } from 'element-plus/es/components/divider/index'
import { ElDrawer } from 'element-plus/es/components/drawer/index'
import { ElForm, ElFormItem } from 'element-plus/es/components/form/index'
import { ElIcon } from 'element-plus/es/components/icon/index'
import { ElInput } from 'element-plus/es/components/input/index'
import { ElInputNumber } from 'element-plus/es/components/input-number/index'
import { ElLoading } from 'element-plus/es/components/loading/index'
import { ElOption, ElSelect } from 'element-plus/es/components/select/index'
import { ElSegmented } from 'element-plus/es/components/segmented/index'
import { ElSwitch } from 'element-plus/es/components/switch/index'
import { ElTabPane, ElTabs } from 'element-plus/es/components/tabs/index'
import { ElTable, ElTableColumn } from 'element-plus/es/components/table/index'
import { ElAutoResizer, ElTableV2 } from 'element-plus/es/components/table-v2/index'
import { ElTag } from 'element-plus/es/components/tag/index'
import {
  Delete,
  Document,
  Folder,
  FolderOpened,
  Link,
  Loading,
  Plus,
  Refresh,
  Search,
  Upload,
} from '@element-plus/icons-vue'
import 'element-plus/dist/index.css'
import '@xterm/xterm/css/xterm.css'

import App from './App.vue'
import router from './router'
import './style.css'

const app = createApp(App)
app.use(createPinia())
app.use(router)
for (const component of [
  ElAside,
  ElAutoResizer,
  ElButton,
  ElCard,
  ElCollapse,
  ElCollapseItem,
  ElContainer,
  ElDialog,
  ElDivider,
  ElDrawer,
  ElForm,
  ElFormItem,
  ElHeader,
  ElIcon,
  ElInput,
  ElInputNumber,
  ElMain,
  ElOption,
  ElSegmented,
  ElSelect,
  ElSwitch,
  ElTabPane,
  ElTable,
  ElTableColumn,
  ElTableV2,
  ElTabs,
  ElTag,
]) {
  app.use(component)
}
app.use(ElLoading)
for (const icon of [
  Delete,
  Document,
  Folder,
  FolderOpened,
  Link,
  Loading,
  Plus,
  Refresh,
  Search,
  Upload,
]) {
  app.component(icon.name!, icon)
}
app.mount('#app')
