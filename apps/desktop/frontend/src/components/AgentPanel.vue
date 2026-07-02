<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import { api, on } from '../api/wails'
import { useAgentStore } from '../stores/agent'
import { useScanStore, type ScanResult } from '../stores/scan'
import ExpForgePanel from './ExpForgePanel.vue'

const props = defineProps<{ clusterId?: string }>()
const emit = defineEmits<{ import: [] }>()
const agentStore = useAgentStore()
const scanStore = useScanStore()

const inputMsg = ref('')
const inputRef = ref<HTMLTextAreaElement>()
const chatRef = ref<HTMLElement>()
const subTab = ref<'chat' | 'surface' | 'exp' | 'skills'>('chat')
const graphData = ref<any>(null)
const graphLoading = ref(false)
const aiAnalysisLoading = ref(false)
const aiAnalysisStatus = ref('')
const aiFindings = ref<any[]>([])
const exportLoading = ref(false)
const skillsLoading = ref(false)
const skillSaving = ref(false)
const skillList = ref<AgentSkillInfo[]>([])
const selectedSkillName = ref('')
const skillContent = ref('')
const newSkillName = ref('')
const expContext = ref<{ templateIds: string[]; findingIds: string[]; factIds: string[]; params: Record<string, string> }>({
  templateIds: [],
  findingIds: [],
  factIds: [],
  params: {},
})
const evidenceDialogVisible = ref(false)
const selectedEvidence = ref<EvidenceDetail | null>(null)
const editingSessionId = ref('')
const editingTitle = ref('')
const pendingPrompt = ref('')
const stoppingChat = ref(false)
const composingInput = ref(false)
let lastCompositionEnd = 0

const hasActiveScan = computed(() => !!scanStore.activeResultId)
const activeScanResult = computed(() => {
  if (!scanStore.activeResultId) return null
  return scanStore.results.find(item => item.id === scanStore.activeResultId) ?? null
})
const activeScanAnalysisKey = computed(() => scanAnalysisKey(activeScanResult.value))
const isReady = computed(() => agentStore.status.ready)
const historySessions = computed(() => agentStore.sessions)
const runtimeLabel = computed(() => {
  if (agentStore.model) return agentStore.model
  if (agentStore.streaming) return '启动中'
  return ''
})
const registeredExpTemplateIds = new Set([
  'cve-2021-4034-pwnkit',
  'external-cve-poc',
])
const surfaceTab = ref<'ai' | 'engine'>('ai')
const surfaceFindings = computed(() => {
  const byId = new Map<string, any>()
  const graphFindings = Array.isArray(graphData.value?.findings) ? graphData.value.findings : []
  for (const finding of graphFindings) {
    if (finding?.id) byId.set(String(finding.id), finding)
  }
  for (const finding of aiFindings.value) {
    if (finding?.id) byId.set(String(finding.id), finding)
  }
  return Array.from(byId.values()).filter(isDisplayableSurfaceFinding).sort(compareSurfaceFindings)
})
const aiSurfaceFindings = computed(() => {
  return surfaceFindings.value.filter(f =>
    isClusterAdminFinding(f) || String(f?.origin ?? '') === 'agent'
  )
})
const engineSurfaceFindings = computed(() => {
  return surfaceFindings.value.filter(f =>
    !isClusterAdminFinding(f) && String(f?.origin ?? '') !== 'agent'
  )
})
const promptSuggestions = [
  {
    label: 'RBAC 权限横移',
    prompt: [
      '请先使用 Skill: k8s-rbac-analysis，然后基于当前 KubeTrail 扫描结果分析 RBAC 权限横移路径。',
      '重点检查 ServiceAccount、Role/ClusterRole、RoleBinding/ClusterRoleBinding、impersonate、pods/exec、pods/attach、pods/portforward、secrets、configmaps、deployments、daemonsets、jobs/cronjobs、nodes/proxy 等权限信号。',
      '请按以下格式输出：',
      '1. 已调用的 Skills：说明使用了 k8s-rbac-analysis，以及是否需要联动 serviceaccount-secret-material、kubelet-runtime-etcd-bypass、workload-controller-persistence 或 exp-generation。',
      '2. 可行攻击路径：从当前身份到目标资源/命名空间/节点的步骤链路，按优先级排序。',
      '3. 关键证据：列出相关 factId、namespace、resource、verb、binding 或主体名称；没有证据时明确说明。',
      '4. 受限或不可行路径：说明缺少哪些 verb/resource 或 API 访问被拒绝。',
      '5. 下一步行动：给出授权红队验证顺序、需要调用的 EXP 模板或补采事实；区分只读验证和会产生副作用的动作。',
    ].join('\n'),
  },
  {
    label: 'Linux 提权漏洞',
    prompt: [
      '请先使用 Skill: exp-generation；如果需要判断容器运行时约束，请联动 Skill: pod-escape-surface。然后基于当前 KubeTrail 扫描结果分析容器/Pod 内 Linux 本地提权风险。',
      '重点检查内核版本、发行版、架构、capabilities、seccomp/AppArmor/SELinux、特权容器、hostPID/hostIPC、挂载点、SUID/SGID、可写路径、运行时信息以及已知 LPE 模板匹配情况。',
      '请按以下格式输出：',
      '1. 已调用的 Skills：说明使用了 exp-generation，以及是否联动 pod-escape-surface。',
      '2. 可行攻击路径：说明本地提权入口、适用条件、预期权限提升结果和置信度。',
      '3. 关键证据：列出相关 factId、版本、配置项、文件路径、权限位或模板匹配；没有证据时明确说明。',
      '4. 阻断条件：列出 seccomp、capability、只读文件系统、内核补丁、发行版 backport 等可能导致不可利用的因素。',
      '5. 下一步行动：给出授权红队验证顺序、候选 EXP 模板、需要补采的只读信息和副作用边界。',
    ].join('\n'),
  },
  {
    label: '容器逃逸',
    prompt: [
      '请先使用 Skill: pod-escape-surface，然后基于当前 KubeTrail 扫描结果分析容器逃逸与节点接管相关风险。',
      '如发现 kubelet、CRI、etcd、runtime socket 或 nodes/proxy 相关证据，请联动 Skill: kubelet-runtime-etcd-bypass；如需要验证计划，请联动 Skill: exp-generation。',
      '重点检查 privileged、capabilities、hostPath、hostNetwork、hostPID、hostIPC、Docker/containerd/socket 挂载、proc/sys 挂载、service account token、kubelet/CRI 访问、节点凭据与敏感 host 文件暴露。',
      '请按以下格式输出：',
      '1. 已调用的 Skills：说明使用了 pod-escape-surface，以及是否联动 kubelet-runtime-etcd-bypass 或 exp-generation。',
      '2. 可行攻击路径：从当前 Pod 到宿主机、kubelet、CRI、节点凭据或集群控制面的步骤链路。',
      '3. 关键证据：列出相关 factId、Pod/Container、mount、capability、namespace、node 或 sensitiveRef；没有证据时明确说明。',
      '4. 不可行路径：说明缺失的挂载、权限、网络可达性或 API 权限。',
      '5. 下一步行动：给出授权红队验证顺序、候选 EXP 模板、需要补采的只读事实和副作用边界。',
    ].join('\n'),
  },
  {
    label: '全部检测',
    prompt: [
      '请对当前 KubeTrail 扫描结果做一次完整攻击面检测，覆盖 RBAC 权限横移、Linux 本地提权漏洞、容器逃逸三类风险。',
      '请分别使用 Skill: k8s-rbac-analysis、exp-generation、pod-escape-surface；遇到 kubelet/CRI/etcd/nodes-proxy 证据时联动 kubelet-runtime-etcd-bypass，遇到敏感材料证据时联动 serviceaccount-secret-material。',
      '请先给出攻击路径总览优先级，再分模块分析。每个结论必须绑定扫描证据；无法从结果中确认的内容请标为待补采，不要编造。',
      '请按以下格式输出：',
      '1. 已调用的 Skills：列出实际使用的 skills 和每个 skill 负责的判断边界。',
      '2. 攻击路径总览：按高/中/低排序，说明最值得优先验证的路径。',
      '3. RBAC 权限横移：可行攻击路径、关键证据、受限点、下一步行动。',
      '4. Linux 提权漏洞：可行攻击路径、关键证据、阻断条件、下一步行动。',
      '5. 容器逃逸：可行攻击路径、关键证据、不可行路径、下一步行动。',
      '6. 缺口清单：为了提高置信度还需要补采哪些只读事实。',
      '7. 下一步攻击行动队列：给出授权红队验证顺序、候选 EXP 模板、预期结果和副作用边界。',
    ].join('\n'),
  },
]

let unsubs: (() => void)[] = []
let chatUnsubs: (() => void)[] = []
let aiAnalysisUnsubs: (() => void)[] = []
let aiAnalysisSessionId = ''
let aiAnalysisStopRequested = false

type AgentSkillInfo = {
  name: string
  path: string
  summary?: string
  size: number
  modifiedAt?: string
}

type AgentSkill = AgentSkillInfo & {
  content: string
}

type EvidenceDetail = {
  ref: string
  factId: string
  selector: string
  kind: 'fact' | 'target' | 'run' | 'errors' | 'missing'
  fact?: any
  value?: any
}

onMounted(async () => {
  try {
    const status = await api.GetAgentStatus()
    agentStore.setStatus(status as any)
  } catch {}

  if (!agentStore.sessionId) agentStore.newSession()
  restoreAiSurfaceFindings()
  loadSkills()
})

onUnmounted(() => {
  cleanupChatListeners()
  cleanupAiAnalysisListeners()
  if (aiAnalysisSessionId) {
    void (api as any).StopAgentChat(aiAnalysisSessionId)
  }
  unsubs.forEach(fn => fn())
})

function addChatUnsub(unsub: () => void) {
  chatUnsubs.push(unsub)
  unsubs.push(unsub)
}

function cleanupChatListeners() {
  if (!chatUnsubs.length) return
  for (const unsub of chatUnsubs) unsub()
  unsubs = unsubs.filter(unsub => !chatUnsubs.includes(unsub))
  chatUnsubs = []
}

function addAiAnalysisUnsub(unsub: () => void) {
  aiAnalysisUnsubs.push(unsub)
  unsubs.push(unsub)
}

function cleanupAiAnalysisListeners() {
  if (!aiAnalysisUnsubs.length) return
  for (const unsub of aiAnalysisUnsubs) unsub()
  unsubs = unsubs.filter(unsub => !aiAnalysisUnsubs.includes(unsub))
  aiAnalysisUnsubs = []
}

async function doImport() {
  try {
    const r = await api.ImportScanResult()
    if (r) scanStore.addResult(r as unknown as ScanResult)
  } catch (e: any) {
    ;(window as any).ElMessage?.error?.(String(e))
  }
}

async function loadSkills() {
  skillsLoading.value = true
  try {
    const list = await api.ListAgentSkills()
    skillList.value = Array.isArray(list) ? list as AgentSkillInfo[] : []
    if (!selectedSkillName.value && skillList.value.length) {
      await selectSkill(skillList.value[0].name)
    } else if (selectedSkillName.value && !skillList.value.some(item => item.name === selectedSkillName.value)) {
      selectedSkillName.value = ''
      skillContent.value = ''
    }
  } catch (e: any) {
    ;(window as any).ElMessage?.error?.(`Skills 加载失败: ${e}`)
  } finally {
    skillsLoading.value = false
  }
}

async function selectSkill(name: string) {
  if (!name || agentStore.streaming) return
  try {
    const skill = await api.GetAgentSkill(name) as AgentSkill
    selectedSkillName.value = skill.name
    skillContent.value = skill.content || ''
    newSkillName.value = ''
  } catch (e: any) {
    ;(window as any).ElMessage?.error?.(`Skill 读取失败: ${e}`)
  }
}

function startNewSkill() {
  if (agentStore.streaming) return
  selectedSkillName.value = ''
  skillContent.value = '# New KubeTrail Skill\n\n## Purpose\n\nDescribe the analysis boundary for this skill.\n\n## Evidence\n\n- Positive evidence:\n- Negative evidence:\n\n## Output\n\nReturn evidence-bound conclusions only.\n'
  newSkillName.value = ''
  nextTick(() => {
    const input = document.querySelector<HTMLInputElement>('.skill-name-input')
    input?.focus()
  })
}

async function saveSkill() {
  const name = (selectedSkillName.value || newSkillName.value).trim()
  if (!name) {
    ;(window as any).ElMessage?.warning?.('请输入 Skill 名称')
    return
  }
  if (!skillContent.value.trim()) {
    ;(window as any).ElMessage?.warning?.('Skill 内容不能为空')
    return
  }
  skillSaving.value = true
  try {
    const saved = await api.SaveAgentSkill({ name, content: skillContent.value }) as AgentSkill
    selectedSkillName.value = saved.name
    newSkillName.value = ''
    skillContent.value = saved.content || skillContent.value
    await loadSkills()
    agentStore.setStatus(await api.GetAgentStatus() as any)
    ;(window as any).ElMessage?.success?.('Skill 已保存，Agent 会在下次运行时重新加载')
  } catch (e: any) {
    ;(window as any).ElMessage?.error?.(`Skill 保存失败: ${e}`)
  } finally {
    skillSaving.value = false
  }
}

async function deleteSkill(name: string) {
  if (!name || agentStore.streaming) return
  if (!window.confirm(`删除 Skill "${name}"？`)) return
  skillSaving.value = true
  try {
    await api.DeleteAgentSkill(name)
    if (selectedSkillName.value === name) {
      selectedSkillName.value = ''
      skillContent.value = ''
    }
    await loadSkills()
    agentStore.setStatus(await api.GetAgentStatus() as any)
    ;(window as any).ElMessage?.success?.('Skill 已删除，Agent 会在下次运行时重新加载')
  } catch (e: any) {
    ;(window as any).ElMessage?.error?.(`Skill 删除失败: ${e}`)
  } finally {
    skillSaving.value = false
  }
}

function fillPrompt(prompt: string) {
  if (agentStore.streaming) return
  inputMsg.value = prompt
  nextTick(() => inputRef.value?.focus())
}

async function sendMessage() {
  const msg = inputMsg.value.trim()
  if (!msg || agentStore.streaming) return

  inputMsg.value = ''
  pendingPrompt.value = msg
  agentStore.clearRuntimeInfo()
  agentStore.addMessage({ role: 'user', content: msg, timestamp: Date.now() })
  agentStore.streaming = true

  if (!isReady.value) {
    agentStore.addMessage({ role: 'system', content: 'Agent 正在启动...', timestamp: Date.now() })
    try {
      await api.EnsureAgentRunning()
      const s = await api.GetAgentStatus()
      agentStore.setStatus(s as any)
    } catch (e: any) {
      agentStore.streaming = false
      agentStore.addMessage({ role: 'system', content: `Agent 启动失败: ${e}`, timestamp: Date.now() })
      return
    }
  }

  agentStore.addMessage({ role: 'assistant', content: '', timestamp: Date.now() })
  cleanupChatListeners()

  const sid = agentStore.sessionId
  const unsub = on(`agent:${sid}:message`, (line: string) => {
    try {
      const event = JSON.parse(line)
      if (event.type === 'system' && event.subtype === 'thinking_tokens') {
        return
      }
      if (event.sessionId) {
        agentStore.setClaudeSessionId(event.sessionId)
      }
      if (event.type === 'init') {
        agentStore.setRuntimeInfo({
          provider: typeof event.provider === 'string' ? event.provider : '',
          model: typeof event.model === 'string' ? event.model : '',
          tools: Array.isArray(event.tools) ? event.tools : [],
          skills: Array.isArray(event.skills) ? event.skills : [],
        })
      } else if (event.type === 'assistant' && event.text) {
        agentStore.setLastAssistantContent(event.text)
        scrollToBottom()
      } else if (event.type === 'result') {
        if (event.text) {
          agentStore.applyAssistantResult(event.text)
        }
        agentStore.streaming = false
        pendingPrompt.value = ''
        scrollToBottom()
        cleanupChatListeners()
      } else if (event.type === 'error') {
        agentStore.streaming = false
        pendingPrompt.value = ''
        const text = event.message || event.text || 'Agent 执行失败'
        const last = agentStore.messages[agentStore.messages.length - 1]
        if (last?.role === 'assistant' && !last.content) {
          last.content = `Error: ${text}`
        } else {
          agentStore.addMessage({ role: 'system', content: `Error: ${text}`, timestamp: Date.now() })
        }
        scrollToBottom()
        cleanupChatListeners()
      } else if ((event.type === 'system' || event.type === 'stderr') && event.text) {
        agentStore.addMessage({ role: 'system', content: event.text, timestamp: Date.now() })
        scrollToBottom()
      }
    } catch {
      agentStore.appendToLast(line)
      scrollToBottom()
    }
  })
  addChatUnsub(unsub)

  const unsubDone = on(`agent:${sid}:done`, () => {
    agentStore.streaming = false
    pendingPrompt.value = ''
    cleanupChatListeners()
  })
  addChatUnsub(unsubDone)

  const unsubErr = on(`agent:${sid}:error`, (err: string) => {
    agentStore.streaming = false
    pendingPrompt.value = ''
    agentStore.addMessage({ role: 'system', content: `Error: ${err}`, timestamp: Date.now() })
    cleanupChatListeners()
  })
  addChatUnsub(unsubErr)

  try {
    const resumeSessionId = await resumeSessionIdForCurrentProvider()
    await api.StartAgentChat(scanStore.activeResultId || '', msg, sid, resumeSessionId)
    const activeScan = scanStore.results.find(r => r.id === scanStore.activeResultId)
    if (activeScan?.sourcePath) {
      agentStore.setScanSourcePath(activeScan.sourcePath)
    }
  } catch (e: any) {
    agentStore.streaming = false
    pendingPrompt.value = ''
    agentStore.addMessage({ role: 'system', content: `Error: ${e}`, timestamp: Date.now() })
    cleanupChatListeners()
  }
}

async function resumeSessionIdForCurrentProvider(): Promise<string> {
  const currentProvider = await configuredAgentProvider()
  if (agentStore.provider && currentProvider && agentStore.provider !== currentProvider) {
    return ''
  }
  return agentStore.claudeSessionId || ''
}

async function configuredAgentProvider(): Promise<string> {
  try {
    const cfg = await api.GetAgentDisplayConfig()
    return (cfg as any)?.provider === 'codex' ? 'codex' : 'claude'
  } catch {
    return ''
  }
}

async function stopAndEditMessage() {
  if (!agentStore.streaming || stoppingChat.value) return
  const sid = agentStore.sessionId
  const prompt = pendingPrompt.value
  stoppingChat.value = true
  cleanupChatListeners()
  const stoppingAiAnalysis = aiAnalysisSessionId === sid
  if (stoppingAiAnalysis) {
    aiAnalysisStopRequested = true
    aiAnalysisStatus.value = '正在中断 AI 分析...'
    cleanupAiAnalysisListeners()
  }
  agentStore.streaming = false
  pendingPrompt.value = ''
  if (prompt) {
    inputMsg.value = prompt
    agentStore.removeLatestExchange(prompt)
  }
  try {
    await (api as any).StopAgentChat(sid)
  } catch (e: any) {
    ;(window as any).ElMessage?.warning?.(`中断失败: ${e}`)
  } finally {
    if (stoppingAiAnalysis) {
      aiAnalysisLoading.value = false
      aiAnalysisSessionId = ''
      aiAnalysisStopRequested = false
      aiAnalysisStatus.value = 'AI 分析已中断'
    }
    stoppingChat.value = false
    scrollToBottom()
    nextTick(() => inputRef.value?.focus())
  }
}

function scrollToBottom() {
  nextTick(() => {
    if (chatRef.value) chatRef.value.scrollTop = chatRef.value.scrollHeight
  })
}

async function loadGraph(): Promise<boolean> {
  if (!scanStore.activeResultId) return false
  graphLoading.value = true
  try {
    const data = await api.GetAttackGraph(scanStore.activeResultId)
    setGraphData(typeof data === 'string' ? JSON.parse(data) : data)
    return true
  } catch (e: any) {
    ;(window as any).ElMessage?.error?.(`攻击面加载失败: ${e}`)
    return false
  } finally {
    graphLoading.value = false
  }
}

async function runAiSurfaceAnalysis() {
  if (!scanStore.activeResultId || aiAnalysisLoading.value) return
  if (agentStore.streaming) {
    ;(window as any).ElMessage?.warning?.('当前对话正在运行，请稍后再执行一键智能分析')
    return
  }
  if (!graphData.value) {
    const loaded = await loadGraph()
    if (!loaded) return
  }

  cleanupAiAnalysisListeners()
  cleanupChatListeners()
  if (!agentStore.sessionId) agentStore.newSession()
  const visiblePrompt = '请基于当前扫描结果执行一键智能攻击面研判，并把 AI 确认的问题同步到攻击面列表。'
  const sid = agentStore.sessionId
  aiAnalysisLoading.value = true
  aiAnalysisStatus.value = 'Agent 启动中...'
  aiFindings.value = []
  clearCurrentAiSurfaceAnalysis()
  if (graphData.value) setGraphData(graphData.value)
  aiAnalysisSessionId = sid
  aiAnalysisStopRequested = false
  pendingPrompt.value = visiblePrompt
  agentStore.clearRuntimeInfo()
  agentStore.addMessage({ role: 'user', content: visiblePrompt, timestamp: Date.now() })
  agentStore.addMessage({ role: 'assistant', content: '正在启动 AI 攻击面研判...', timestamp: Date.now() })
  agentStore.streaming = true
  const activeScan = scanStore.results.find(r => r.id === scanStore.activeResultId)
  if (activeScan?.sourcePath) agentStore.setScanSourcePath(activeScan.sourcePath)
  subTab.value = 'chat'
  scrollToBottom()
  let finished = false

  const finish = (ok: boolean, message?: string) => {
    if (finished) return
    finished = true
    aiAnalysisLoading.value = false
    aiAnalysisSessionId = ''
    aiAnalysisStopRequested = false
    agentStore.streaming = false
    pendingPrompt.value = ''
    cleanupAiAnalysisListeners()
    if (ok) {
      aiAnalysisStatus.value = message || `AI 已识别 ${aiFindings.value.length} 个攻击面`
      persistCurrentAiSurfaceAnalysis(aiAnalysisStatus.value)
      ;(window as any).ElMessage?.success?.(aiAnalysisStatus.value)
    } else {
      aiAnalysisStatus.value = message || 'AI 分析失败'
      ;(window as any).ElMessage?.error?.(aiAnalysisStatus.value)
    }
  }

  addAiAnalysisUnsub(on(`agent:${sid}:message`, (line: string) => {
    try {
      const event = JSON.parse(line)
      if (event.sessionId) {
        agentStore.setClaudeSessionId(event.sessionId)
      }
      if (event.type === 'init') {
        agentStore.setRuntimeInfo({
          provider: typeof event.provider === 'string' ? event.provider : '',
          model: typeof event.model === 'string' ? event.model : '',
          tools: Array.isArray(event.tools) ? event.tools : [],
          skills: Array.isArray(event.skills) ? event.skills : [],
        })
        const modelLabel = event.model || 'model'
        const skillsLoaded = Array.isArray(event.skills) ? event.skills.length : 0
        aiAnalysisStatus.value = `Agent 分析中 · ${modelLabel} · ${skillsLoaded} Skills 已加载`
        const initMsg = [
          `启动分析: ${modelLabel}`,
          `已加载 ${skillsLoaded} 个分析技能`,
          '正在加载扫描结果...',
        ].join('\n')
        updateAiAnalysisChat(initMsg)
      } else if (event.type === 'tool_use') {
        const label = formatToolUseLabel(event.toolName, event.skillName, event.toolInput)
        aiAnalysisStatus.value = label
        appendAnalysisLog(label)
      } else if (event.type === 'assistant' && event.text) {
        aiAnalysisStatus.value = 'Agent 正在生成分析结果...'
        updateAiAnalysisChat(String(event.text))
        scrollToBottom()
      } else if (event.type === 'system' && event.text) {
        aiAnalysisStatus.value = String(event.text).slice(0, 120)
      } else if (event.type === 'result') {
        try {
          const rawText = String(event.text || '')
          const findings = parseAiSurfaceFindings(rawText)
          applyAiSurfaceFindings(findings)
          updateAiAnalysisChat(formatAiSurfaceChatResult(rawText, findings))
          scrollToBottom()
          finish(true, findings.length ? `AI 已识别 ${findings.length} 个攻击面` : 'AI 未返回新的可解析攻击面')
        } catch (e: any) {
          updateAiAnalysisChatError(`AI 结果解析失败: ${e?.message || e}`)
          finish(false, `AI 结果解析失败: ${e?.message || e}`)
        }
      } else if (event.type === 'error') {
        updateAiAnalysisChatError(event.message || event.text || 'Agent 执行失败')
        finish(false, event.message || event.text || 'Agent 执行失败')
      }
    } catch {
      // Ignore malformed stream fragments; the final result event is authoritative.
    }
  }))

  addAiAnalysisUnsub(on(`agent:${sid}:error`, (err: string) => {
    updateAiAnalysisChatError(err)
    finish(false, err)
  }))

  addAiAnalysisUnsub(on(`agent:${sid}:done`, () => {
    if (finished) return
    if (aiAnalysisStopRequested) {
      updateAiAnalysisChatError('AI 攻击面研判已中断')
      finish(false, 'AI 分析已中断')
      return
    }
    finish(true, aiFindings.value.length ? `AI 已识别 ${aiFindings.value.length} 个攻击面` : 'AI 分析结束，但未返回结构化结果')
  }))

  try {
    aiAnalysisStatus.value = 'Agent 分析中...'
    const resumeSessionId = await resumeSessionIdForCurrentProvider()
    await api.StartAgentChat(scanStore.activeResultId, buildAiSurfacePrompt(), sid, resumeSessionId)
  } catch (e: any) {
    updateAiAnalysisChatError(String(e?.message || e))
    finish(false, String(e?.message || e))
  }
}

function updateAiAnalysisChat(content: string) {
  const text = content.trim()
  if (!text) return
  agentStore.setLastAssistantContent(text)
}

function updateAiAnalysisChatError(message: string) {
  const text = String(message || 'Agent 执行失败').trim()
  const last = agentStore.messages[agentStore.messages.length - 1]
  if (last?.role === 'assistant' && last.content.trim()) {
    agentStore.setLastAssistantContent(`${last.content.trim()}\n\nError: ${text}`)
  } else {
    agentStore.setLastAssistantContent(`Error: ${text}`)
  }
  scrollToBottom()
}

function formatToolUseLabel(toolName: string, skillName?: string, _input?: Record<string, unknown>): string {
  if (toolName === 'Skill' && skillName) {
    return `调用分析技能: ${skillName}`
  }
  const labelMap: Record<string, string> = {
    kubetrail_load_result: '加载扫描结果...',
    kubetrail_summary: '读取目标上下文摘要...',
    kubetrail_list_facts: '枚举采集事实列表...',
    kubetrail_get_fact: '获取具体事实详情...',
    kubetrail_list_sensitive_refs: '列举敏感材料引用...',
    kubetrail_materialize_ref: '物化敏感材料...',
    Bash: '执行只读验证命令...',
    Read: '读取文件...',
    Grep: '搜索内容...',
    Glob: '查找文件...',
  }
  return labelMap[toolName] || `调用工具: ${toolName}`
}

function appendAnalysisLog(text: string) {
  const last = agentStore.messages[agentStore.messages.length - 1]
  if (last?.role === 'assistant') {
    const logLine = `- ${text}`
    if (!last.content.includes(logLine)) {
      agentStore.setLastAssistantContent(`${last.content}\n${logLine}`)
    }
    return
  }
  agentStore.addMessage({ role: 'system', content: text, timestamp: Date.now() })
}

async function stopAiSurfaceAnalysis() {
  if (!aiAnalysisSessionId) return
  const sid = aiAnalysisSessionId
  aiAnalysisStopRequested = true
  aiAnalysisStatus.value = '正在中断 AI 分析...'
  try {
    await (api as any).StopAgentChat(sid)
  } catch (e: any) {
    ;(window as any).ElMessage?.warning?.(`中断失败: ${e}`)
  }
}

async function openAiSurfaceAnalysis() {
  subTab.value = 'chat'
  await nextTick()
  await runAiSurfaceAnalysis()
}

function setGraphData(data: any) {
  graphData.value = mergeGraphWithAiFindings(data)
  agentStore.setGraph(graphData.value)
}

function applyAiSurfaceFindings(findings: any[]) {
  aiFindings.value = findings
  if (graphData.value) {
    setGraphData(graphData.value)
  }
}

function restoreAiSurfaceFindings() {
  const cached = agentStore.getSurfaceAnalysis(activeScanAnalysisKey.value)
  aiFindings.value = cached?.findings ?? []
  aiAnalysisStatus.value = cached?.status || (aiFindings.value.length ? `AI 已识别 ${aiFindings.value.length} 个攻击面` : '')
  if (graphData.value) {
    setGraphData(graphData.value)
  }
}

function persistCurrentAiSurfaceAnalysis(status = '') {
  const key = activeScanAnalysisKey.value
  if (!key || !aiFindings.value.length) return
  agentStore.setSurfaceAnalysis(key, aiFindings.value, status)
}

function clearCurrentAiSurfaceAnalysis() {
  const key = activeScanAnalysisKey.value
  if (!key) return
  agentStore.clearSurfaceAnalysis(key)
}

function mergeGraphWithAiFindings(data: any): any {
  if (!data || typeof data !== 'object') return data
  const baseFindings = Array.isArray(data.findings) ? data.findings : []
  const withoutAi = baseFindings.filter((finding: any) => String(finding?.origin ?? '') !== 'agent' && !String(finding?.id ?? '').startsWith('ai:'))
  return {
    ...data,
    findings: [...withoutAi, ...aiFindings.value].sort(compareSurfaceFindings),
  }
}

async function exportReport(format: 'json' | 'markdown') {
  if (!scanStore.activeResultId) return
  exportLoading.value = true
  try {
    await (api as any).ExportAnalysisReport(scanStore.activeResultId, format)
    ;(window as any).ElMessage?.success?.('报告导出成功')
  } catch (e: any) {
    ;(window as any).ElMessage?.error?.(`导出失败: ${e}`)
  } finally {
    exportLoading.value = false
  }
}

function newSession() {
  if (agentStore.streaming) return
  cleanupChatListeners()
  agentStore.newSession()
}

function selectHistorySession(id: string) {
  if (agentStore.streaming || id === agentStore.sessionId) return
  cleanupChatListeners()
  agentStore.selectSession(id)
  restoreSessionScan()
  scrollToBottom()
}

async function restoreSessionScan() {
  const path = agentStore.scanSourcePath
  if (!path) return
  const alreadyLoaded = scanStore.results.some(r => r.sourcePath === path)
  if (alreadyLoaded) {
    const existing = scanStore.results.find(r => r.sourcePath === path)
    if (existing) scanStore.setActive(existing.id)
    return
  }
  try {
    const r = await api.ImportScanResultPath(path)
    if (r) scanStore.addResult(r as unknown as ScanResult)
  } catch {
    ;(window as any).ElMessage?.warning?.('历史扫描结果文件不可用，请重新导入')
  }
}

function deleteHistorySession(id: string) {
  if (agentStore.streaming) return
  cleanupChatListeners()
  if (editingSessionId.value === id) cancelRename()
  agentStore.deleteSession(id)
  if (!agentStore.sessionId) agentStore.newSession()
  scrollToBottom()
}

function beginRename(id: string, title: string) {
  if (agentStore.streaming) return
  editingSessionId.value = id
  editingTitle.value = title
  nextTick(() => {
    const input = document.querySelector<HTMLInputElement>('.history-title-input')
    input?.focus()
    input?.select()
  })
}

function saveRename(id: string) {
  if (editingSessionId.value !== id) return
  agentStore.renameSession(id, editingTitle.value)
  editingSessionId.value = ''
  editingTitle.value = ''
}

function cancelRename() {
  editingSessionId.value = ''
  editingTitle.value = ''
}

function formatSessionTime(value: number): string {
  if (!value) return ''
  const date = new Date(value)
  const now = new Date()
  if (date.toDateString() === now.toDateString()) {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  }
  return date.toLocaleDateString([], { month: '2-digit', day: '2-digit' })
}

function expTemplatesForFinding(finding: any): string[] {
  if (String(finding?.category ?? '') !== 'lpe') return []
  const templates = Array.isArray(finding?.templates) ? finding.templates : []
  return templates.filter((id: unknown): id is string => typeof id === 'string' && registeredExpTemplateIds.has(id))
}

function evidenceFactIds(finding: any): string[] {
  const evidence = Array.isArray(finding?.evidence) ? finding.evidence : []
  const ids = evidence
    .map((item: unknown) => String(item).split(':')[0].trim())
    .filter(Boolean)
  return Array.from(new Set(ids))
}

function openExpForFinding(finding: any) {
  const templateIds = expTemplatesForFinding(finding)
  if (!templateIds.length) return
  expContext.value = {
    templateIds,
    findingIds: finding?.id ? [String(finding.id)] : [],
    factIds: evidenceFactIds(finding),
    params: expParamsForFinding(finding, templateIds),
  }
  subTab.value = 'exp'
}

function severityLabel(value: string): string {
  const labels: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
    unknown: '未知',
    blocked: '不可利用',
  }
  return labels[value] || value
}

function categoryLabel(value: string): string {
  const labels: Record<string, string> = {
    escape: '逃逸',
    exploit: '利用',
    lpe: '提权',
    material: '凭据',
    blocked: '不可利用',
    context: '上下文',
  }
  return labels[value] || value
}

function originLabel(value: string): string {
  const labels: Record<string, string> = {
    graph: 'Graph',
    document: 'Doc',
    catalog: 'Catalog',
    agent: 'AI 确认',
  }
  return labels[value] || value
}

function isDocFinding(finding: any): boolean {
  return String(finding?.origin ?? '') === 'document' || String(finding?.origin ?? '') === 'catalog'
}

function confidenceLabel(value: string): string {
  const labels: Record<string, string> = {
    confirmed: '确认',
    probable: '较高',
    signal: '信号',
    blocked: '不可利用',
    unknown: '未知',
  }
  return labels[value] || value
}

function expParamsForFinding(finding: any, templateIds: string[]): Record<string, string> {
  if (finding?.expParams && typeof finding.expParams === 'object') {
    return { ...finding.expParams }
  }
  return expParamsForFindingText(`${finding?.title ?? ''} ${finding?.description ?? ''}`, templateIds)
}

function expParamsForFindingText(value: string, templateIds: string[]): Record<string, string> {
  if (!templateIds.includes('external-cve-poc')) return {}
  const text = value.toLowerCase()
  const cve = text.match(/cve-\d{4}-\d{4,7}/)?.[0]
  if (cve) return { pocId: cve, binaryName: cve }
  const catalogId = text.match(/lpe-catalog:([a-z0-9_.-]+)/)?.[1]
  return catalogId ? { pocId: catalogId, binaryName: catalogId } : {}
}

function scanAnalysisKey(result: ScanResult | null): string {
  if (!result) return ''
  const runId = result.document?.run?.id
  if (typeof runId === 'string' && runId.trim()) return `run:${runId.trim()}`
  if (result.sourcePath) return `path:${result.sourcePath}`
  return result.id ? `scan:${result.id}` : ''
}

function buildAiSurfacePrompt(): string {
  const graphSummary = graphData.value
    ? JSON.stringify({
        summary: graphData.value.summary,
        stats: graphData.value.stats,
        existingFindingIds: Array.isArray(graphData.value.findings)
          ? graphData.value.findings.map((item: any) => item?.id).filter(Boolean).slice(0, 80)
          : [],
      }, null, 2)
    : '{}'
  return [
    '请对当前 KubeTrail 扫描结果做一键智能攻击面分析。',
    '',
    '## 工具调用',
    '必须先调用 kubetrail_load_result 加载扫描数据，然后按需调用 kubetrail_summary、kubetrail_list_facts、kubetrail_get_fact 获取具体证据。',
    '',
    '## Skill 调用（按需使用，不要泛泛全调）',
    '- 发现 RBAC 相关证据时，调用 Skill: k8s-rbac-analysis 做权限分析',
    '- 发现 Secret/Token/凭据材料时，调用 Skill: serviceaccount-secret-material',
    '- 发现 privileged/hostPath/capability/runtime socket 时，调用 Skill: pod-escape-surface',
    '- 发现内核版本/SUID/capability 时，调用 Skill: exp-generation 判断 LPE 可行性',
    '- 发现 kubelet/CRI/etcd/nodes-proxy 证据时，调用 Skill: kubelet-runtime-etcd-bypass',
    '- 其他 Skill 按证据触发，不要无缘无故调用',
    '',
    '## 覆盖范围',
    'RBAC 横移、容器逃逸、Linux LPE、凭据/Secret 材料、受限或缺口。只输出有扫描证据支撑的可验证攻击面。',
    '不要执行任何有副作用动作，不要生成真实攻击执行步骤；只输出验证计划和证据。',
    '',
    '已有基础图谱摘要如下，用于避免重复输出完全相同的 finding：',
    graphSummary,
    '',
    '## 输出要求',
    '- 用”🔍 研判过程”小节开头，逐步说明分析步骤（如”已加载结果 → 核对 RBAC → 检查逃逸面 → 评估 LPE → 整理 blocked 项”），每一步用一两句话说发现了什么。',
    '- 最后输出一个 fenced JSON code block，语言标记为 json；该 JSON 是桌面端解析攻击面的唯一数据源。',
    '- JSON 之后不要再输出其他内容。',
    'JSON schema：',
    '{',
    '  “findings”: [',
    '    {',
    '      “id”: “short-stable-id”,',
    '      “title”: “一句话标题”,',
    '      “category”: “escape|exploit|lpe|material|blocked”,',
    '      “severity”: “critical|high|medium|low|blocked”,',
    '      “confidence”: “confirmed|probable|signal|blocked”,',
    '      “description”: “为什么这是攻击面，必须绑定事实”,',
    '      “evidence”: [“factId”, “factId:selector”],',
    '      “templates”: [“可选 EXP 模板 ID”],',
    '      “nextSteps”: [“只读/受控验证下一步”, “需要补采的事实”],',
    '      “clusterAdmin”: false',
    '    }',
    '  ]',
    '}',
    '规则：',
    '- 最高优先级：如果 SSRR 中存在 verbs=[“*”]+resources=[“*”]+apiGroups=[“*”] 的 wildcard 规则，或 high_value_access+expanded_wildcards 中所有集群管控类权限（clusterrolebindings_create、nodes_*、webhook_* 等）均返回 allowed:true，则判定为”已获得整个集群管理权限”。',
    '- 集群管理员判定成立时，输出 id=”cluster-admin-achieved”、clusterAdmin=true、title=”已获得整个集群管理权限”、category=”exploit”、severity=”critical”、confidence=”confirmed” 的 finding，作为 findings 数组的第一项。',
    '- 集群管理员 finding 中，templates 和 nextSteps 必须为空数组，description 需明确说明”无需容器逃逸或权限提升，已实质上控制整个集群”。',
    '- evidence 只能使用扫描结果中真实存在的 factId、target/run/errors，或 factId:具体权限ID 形式。',
    '- confidence=confirmed 只用于扫描证据直接证明可行的攻击面；AI 确认的问题会在桌面端攻击面列表前置显示。',
    '- 如果 AI 验证后判断”不太可能利用 / 不满足关键前置条件 / 只能作为排除项”，必须输出 category=blocked、severity=blocked、confidence=blocked；不要把这类结论标为 low。',
    '- blocked 项仍需要 evidence 和 nextSteps，nextSteps 应说明不可利用原因或需要补采后才能重新判断的事实。',
    '- 如果没有证据，不要输出该 finding。',
    '- 最多输出 12 条，按优先级排序（集群管理员 finding 必须是第一条）。',
    '- 如果没有新增可解析攻击面，输出 {“findings”:[]}。',
  ].join('\n')
}

function parseAiSurfaceFindings(text: string): any[] {
  const parsed = parseJsonFromText(text)
  const rawFindings = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.findings) ? parsed.findings : []
  return rawFindings
    .map((item: any, index: number) => normalizeAiFinding(item, index))
    .filter((item: any): item is any => Boolean(item))
    .slice(0, 20)
}

function parseJsonFromText(text: string): any {
  const trimmed = text.trim()
  const candidates = [
    trimmed,
    ...Array.from(trimmed.matchAll(/```(?:json)?\s*([\s\S]*?)```/gi), match => match[1]?.trim() || ''),
  ].filter(Boolean)
  const objectStart = trimmed.indexOf('{')
  const objectEnd = trimmed.lastIndexOf('}')
  if (objectStart >= 0 && objectEnd > objectStart) candidates.push(trimmed.slice(objectStart, objectEnd + 1))
  const arrayStart = trimmed.indexOf('[')
  const arrayEnd = trimmed.lastIndexOf(']')
  if (arrayStart >= 0 && arrayEnd > arrayStart) candidates.push(trimmed.slice(arrayStart, arrayEnd + 1))

  for (const candidate of candidates) {
    try {
      return JSON.parse(candidate)
    } catch {}
  }
  throw new Error('AI 返回内容不是可解析 JSON')
}

function formatAiSurfaceChatResult(rawText: string, findings: any[]): string {
  const processText = stripFinalJsonFromText(rawText)
  const clusterAdmin = findings.filter(isClusterAdminFinding)
  const confirmed = findings.filter(isAiConfirmedFinding).filter(f => !isClusterAdminFinding(f))
  const blocked = findings.filter(isNonExploitableFinding)
  const lines: string[] = []
  if (processText) lines.push(processText)
  lines.push('')
  if (findings.length) {
    if (clusterAdmin.length) {
      lines.push('🔴 集群管理员权限：当前身份已获得整个集群管理权限，无需逃逸或提权。')
    }
    lines.push(`结构化同步：已写入 ${findings.length} 个 AI 研判项，其中 ${confirmed.length} 个 AI 确认问题会显示在攻击面列表最前面，${blocked.length} 个标记为不可利用。`)
    if (clusterAdmin.length) {
      lines.push('集群管理员权限：')
      for (const finding of clusterAdmin.slice(0, 3)) {
        lines.push(`- 🔴 ${finding.title || finding.id}`)
      }
    }
    if (confirmed.length) {
      lines.push('AI 确认问题：')
      for (const finding of confirmed.slice(0, 6)) {
        lines.push(`- ${finding.title || finding.id}`)
      }
    }
    if (blocked.length) {
      lines.push('不可利用：')
      for (const finding of blocked.slice(0, 6)) {
        lines.push(`- 🚫 ${finding.title || finding.id}`)
      }
    }
  } else {
    lines.push('结构化同步：未解析到新的可验证攻击面。')
  }
  return lines.join('\n').trim()
}

function stripFinalJsonFromText(text: string): string {
  let value = text.trim()
  if (!value) return ''

  const blocks = Array.from(value.matchAll(/```(?:json)?\s*([\s\S]*?)```/gi))
  for (const block of blocks) {
    const raw = block[0]
    const inner = block[1]?.trim() || ''
    try {
      JSON.parse(inner)
      value = value.replace(raw, '').trim()
    } catch {}
  }

  const objectEnd = value.lastIndexOf('}')
  if (objectEnd >= 0) {
    let objectStart = value.indexOf('{')
    while (objectStart >= 0 && objectStart < objectEnd) {
      const candidate = value.slice(objectStart, objectEnd + 1).trim()
      try {
        JSON.parse(candidate)
        value = `${value.slice(0, objectStart)}${value.slice(objectEnd + 1)}`.trim()
        break
      } catch {
        objectStart = value.indexOf('{', objectStart + 1)
      }
    }
  }

  return value.replace(/\n{3,}/g, '\n\n').trim()
}

function normalizeAiFinding(item: any, index: number): any | null {
  if (!item || typeof item !== 'object') return null
  const isClusterAdmin = item.clusterAdmin === true || String(item.id || '').toLowerCase() === 'cluster-admin-achieved'
  let category = normalizeAiCategory(item.category)
  let severity = normalizeAiSeverity(item.severity)
  let confidence = normalizeAiConfidence(item.confidence)
  const title = String(item.title || '').trim()
  const description = String(item.description || '').trim()
  const evidence = normalizeStringArray(item.evidence)
  if (isNonExploitableAiInput(item) && !isClusterAdmin) {
    category = 'blocked'
    severity = 'blocked'
    confidence = 'blocked'
  }
  if (!category || !severity || !title || !description || !evidence.length) return null
  const baseId = String(item.id || title || `finding-${index}`).trim()
  const templates = isClusterAdmin ? [] : (category === 'blocked' ? [] : normalizeStringArray(item.templates))
  const nextSteps = isClusterAdmin ? [] : normalizeStringArray(item.nextSteps)
  return {
    id: `ai:${stableSurfaceId(baseId)}`,
    title,
    category: isClusterAdmin ? 'exploit' : category,
    severity: isClusterAdmin ? 'critical' : severity,
    confidence: isClusterAdmin ? 'confirmed' : confidence,
    description,
    evidence,
    nodes: [],
    templates,
    nextSteps,
    origin: 'agent',
    clusterAdmin: isClusterAdmin || undefined,
    expParams: item.expParams && typeof item.expParams === 'object' ? item.expParams : undefined,
  }
}

function normalizeAiCategory(value: unknown): string {
  const category = String(value ?? '').toLowerCase()
  if (isBlockedToken(category)) return 'blocked'
  return ['escape', 'exploit', 'lpe', 'material', 'blocked'].includes(category) ? category : ''
}

function normalizeAiSeverity(value: unknown): string {
  const severity = String(value ?? '').toLowerCase()
  if (isBlockedToken(severity)) return 'blocked'
  return ['critical', 'high', 'medium', 'low', 'blocked'].includes(severity) ? severity : ''
}

function normalizeAiConfidence(value: unknown): string {
  const confidence = String(value ?? '').toLowerCase()
  if (isBlockedToken(confidence)) return 'blocked'
  return ['confirmed', 'probable', 'signal', 'blocked'].includes(confidence) ? confidence : 'signal'
}

function isNonExploitableAiInput(item: any): boolean {
  if (item?.exploitable === false) return true
  const values = [
    item?.category,
    item?.severity,
    item?.confidence,
    item?.status,
    item?.verdict,
    item?.result,
    item?.risk,
    item?.exploitability,
    item?.title,
    item?.description,
    item?.reason,
    Array.isArray(item?.nextSteps) ? item.nextSteps.join(' ') : item?.nextSteps,
  ]
  return values.some(value => isBlockedToken(String(value ?? '').toLowerCase()))
}

function isBlockedToken(value: string): boolean {
  const text = value.toLowerCase().replace(/[\s_-]+/g, ' ').trim()
  if (!text) return false
  return [
    'blocked',
    'unexploitable',
    'not exploitable',
    'non exploitable',
    'unlikely exploitable',
    'unlikely to exploit',
    'infeasible',
    'not feasible',
    '不可利用',
    '无法利用',
    '不太可能利用',
    '不可行',
    '受阻',
    '阻断',
  ].some(token => text.includes(token))
}

function normalizeStringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return Array.from(new Set(value.map(item => String(item).trim()).filter(Boolean)))
  }
  if (typeof value === 'string' && value.trim()) return [value.trim()]
  return []
}

function stableSurfaceId(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9\u4e00-\u9fa5_.-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) || crypto.randomUUID()
}

function isDisplayableSurfaceFinding(finding: any): boolean {
  if (!finding) return false
  if (isClusterAdminFinding(finding)) return true
  if (finding.category === 'context') return false
  if (isNonExploitableFinding(finding)) {
    return String(finding?.origin ?? '') === 'agent' || String(finding?.id ?? '').startsWith('ai:')
  }
  if (finding.category === 'blocked') return false
  return ['critical', 'high', 'medium', 'low'].includes(String(finding.severity || ''))
}

function compareSurfaceFindings(a: any, b: any): number {
  const priority = surfacePriority(b) - surfacePriority(a)
  if (priority !== 0) return priority
  return String(a?.title || a?.id || '').localeCompare(String(b?.title || b?.id || ''), 'zh-Hans-CN')
}

function surfacePriority(finding: any): number {
  if (isClusterAdminFinding(finding)) return 10000
  const confirmedBoost = isAiConfirmedFinding(finding) ? 1000 : 0
  return confirmedBoost + severityRank(finding?.severity) * 10 + confidenceRank(finding?.confidence)
}

function isAiConfirmedFinding(finding: any): boolean {
  return String(finding?.origin ?? '') === 'agent' && String(finding?.confidence ?? '') === 'confirmed'
}

function isNonExploitableFinding(finding: any): boolean {
  return String(finding?.category ?? '') === 'blocked' ||
    String(finding?.severity ?? '') === 'blocked' ||
    String(finding?.confidence ?? '') === 'blocked'
}

function isClusterAdminFinding(finding: any): boolean {
  return String(finding?.id ?? '') === 'cluster-admin-achieved' ||
    String(finding?.id ?? '').startsWith('ai:cluster-admin') ||
    finding?.clusterAdmin === true
}

function severityRank(value: unknown): number {
  const ranks: Record<string, number> = { critical: 6, high: 5, medium: 4, low: 3, unknown: 2, info: 1, blocked: 0 }
  return ranks[String(value ?? '')] ?? 0
}

function confidenceRank(value: unknown): number {
  const ranks: Record<string, number> = { confirmed: 4, probable: 3, signal: 2, unknown: 1, blocked: 0 }
  return ranks[String(value ?? '')] ?? 0
}

const selectedEvidenceValue = computed(() => {
  if (!selectedEvidence.value) return ''
  return formatEvidenceValue(filteredEvidenceValue(selectedEvidence.value))
})

function openEvidence(ref: unknown) {
  selectedEvidence.value = resolveEvidence(String(ref ?? ''))
  evidenceDialogVisible.value = true
}

function resolveEvidence(ref: string): EvidenceDetail {
  const { factId, selector } = parseEvidenceRef(ref)
  const doc = activeScanResult.value?.document
  if (!doc) return { ref, factId, selector, kind: 'missing' }
  if (factId === 'errors') return { ref, factId, selector, kind: 'errors', value: doc.errors ?? [] }
  if (factId === 'target' || factId.startsWith('target.')) return { ref, factId, selector, kind: 'target', value: doc.target ?? {} }
  if (factId === 'run' || factId.startsWith('run.')) return { ref, factId, selector, kind: 'run', value: doc.run ?? {} }
  const facts = Array.isArray(doc.facts) ? doc.facts : []
  const fact = facts.find((item: any) => String(item?.id ?? '') === factId)
  return fact ? { ref, factId, selector, kind: 'fact', fact, value: fact.value } : { ref, factId, selector, kind: 'missing' }
}

function parseEvidenceRef(ref: string): { factId: string; selector: string } {
  const index = ref.indexOf(':')
  if (index <= 0) return { factId: ref.trim(), selector: '' }
  return {
    factId: ref.slice(0, index).trim(),
    selector: ref.slice(index + 1).trim(),
  }
}

function filteredEvidenceValue(detail: EvidenceDetail): any {
  const value = detail.value
  if (!detail.selector || !Array.isArray(value)) return value
  const selectors = detail.selector.split(',').map(item => item.trim()).filter(Boolean)
  if (!selectors.length) return value
  const filtered = value.filter((item: any) => selectors.includes(String(item?.id ?? '')))
  return filtered.length ? filtered : value
}

function formatEvidenceValue(value: any): string {
  if (value === undefined) return ''
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

watch(subTab, (v) => {
  if (v === 'surface' && !graphData.value) loadGraph()
  if (v === 'skills' && !skillList.value.length) loadSkills()
  // Default to AI tab if AI results exist, otherwise engine tab
  if (v === 'surface') {
    surfaceTab.value = aiSurfaceFindings.value.length ? 'ai' : 'engine'
  }
})

watch(aiSurfaceFindings, (list) => {
  // When AI analysis finishes, auto-switch to AI results tab
  if (list.length && subTab.value === 'surface') {
    surfaceTab.value = 'ai'
  }
})

watch(() => scanStore.activeResultId, (newId) => {
  graphData.value = null
  selectedEvidence.value = null
  evidenceDialogVisible.value = false
  cleanupAiAnalysisListeners()
  if (aiAnalysisSessionId) {
    void (api as any).StopAgentChat(aiAnalysisSessionId)
    aiAnalysisSessionId = ''
    aiAnalysisLoading.value = false
    aiAnalysisStopRequested = false
    agentStore.streaming = false
    pendingPrompt.value = ''
  }
  agentStore.setGraph(null)
  restoreAiSurfaceFindings()
  // 自动解析攻击面（本地扫描和导入扫描均自动触发）
  if (newId) {
    nextTick(() => { loadGraph() })
  }
})

function handleKeydown(e: KeyboardEvent) {
  if (e.key === 'Enter' && !e.shiftKey) {
    if (e.isComposing || composingInput.value || (e as any).keyCode === 229 || Date.now() - lastCompositionEnd < 80) {
      return
    }
    e.preventDefault()
    sendMessage()
  }
}

function handleCompositionStart() {
  composingInput.value = true
}

function handleCompositionEnd() {
  composingInput.value = false
  lastCompositionEnd = Date.now()
}
</script>

<template>
  <div class="agent-panel">
    <!-- Status bar -->
    <div class="agent-status-bar">
      <span class="status-dot" :class="{ ready: isReady }"></span>
      <span v-if="isReady" class="status-text">Agent 就绪</span>
      <span v-else class="status-text warn">Agent 未就绪 — 发送消息时将自动启动</span>
      <span style="flex:1"></span>
      <span v-if="hasActiveScan" class="scan-badge">
        {{ scanStore.results.find(r => r.id === scanStore.activeResultId)?.factCount || 0 }} facts
      </span>
      <el-button
        size="small"
        type="primary"
        plain
        @click="doImport"
      >
        <el-icon><Upload /></el-icon> 导入服务端扫描结果
      </el-button>
      <el-button
        v-if="hasActiveScan && subTab !== 'surface'"
        size="small"
        type="primary"
        plain
        :loading="aiAnalysisLoading"
        :disabled="agentStore.streaming"
        @click="openAiSurfaceAnalysis"
      >一键智能分析攻击面</el-button>
    </div>

    <!-- Sub tabs -->
    <el-segmented class="agent-tabs" v-model="subTab" :options="[
      { label: '对话', value: 'chat' },
      { label: '攻击面', value: 'surface' },
      { label: 'EXP Forge', value: 'exp' },
      { label: 'Skills', value: 'skills' },
    ]" size="small" />

    <!-- Chat -->
    <template v-if="subTab === 'chat'">
      <div class="chat-shell">
        <aside class="chat-history">
          <div class="history-head">
            <span>历史对话</span>
            <el-button size="small" text @click="newSession" :disabled="agentStore.streaming" title="新会话">
              <el-icon><Plus /></el-icon>
            </el-button>
          </div>
          <div class="history-list">
            <div
              v-for="session in historySessions"
              :key="session.id"
              class="history-item"
              :class="{ active: session.id === agentStore.sessionId, disabled: agentStore.streaming }"
              role="button"
              tabindex="0"
              @click="selectHistorySession(session.id)"
              @keydown.enter.prevent="selectHistorySession(session.id)"
            >
              <div class="history-top">
                <input
                  v-if="editingSessionId === session.id"
                  v-model="editingTitle"
                  class="history-title-input"
                  maxlength="48"
                  @click.stop
                  @keydown.enter.prevent="saveRename(session.id)"
                  @keydown.esc.prevent="cancelRename"
                  @blur="saveRename(session.id)"
                />
                <span
                  v-else
                  class="history-title"
                  title="双击重命名"
                  @dblclick.stop="beginRename(session.id, session.title)"
                >{{ session.title }}</span>
                <span class="history-actions">
                  <button
                    type="button"
                    class="history-action history-delete"
                    title="删除"
                    :disabled="agentStore.streaming"
                    @click.stop="deleteHistorySession(session.id)"
                  >×</button>
                </span>
              </div>
              <span class="history-meta">
                <span class="history-count">{{ session.messages.length }} 条</span>
                <span class="history-time">{{ formatSessionTime(session.updatedAt) }}</span>
              </span>
            </div>
            <div v-if="!historySessions.length" class="history-empty">暂无历史</div>
          </div>
        </aside>

        <section class="chat-main">
          <div v-if="agentStore.streaming || agentStore.loadedSkills.length" class="agent-runtime">
            <span class="runtime-state" :class="{ active: agentStore.streaming }">
              {{ agentStore.streaming ? '运行中' : '最近运行' }}
            </span>
            <span v-if="runtimeLabel" class="runtime-model">{{ runtimeLabel }}</span>
            <div class="runtime-skills" :class="{ empty: !agentStore.loadedSkills.length }">
              <span class="runtime-prefix">Skills</span>
              <span v-if="!agentStore.loadedSkills.length" class="runtime-muted">加载中...</span>
              <span v-for="skill in agentStore.loadedSkills" :key="skill" class="skill-chip">{{ skill }}</span>
            </div>
          </div>
          <div ref="chatRef" class="chat-messages">
            <!-- 无扫描数据且无历史消息时的空状态 -->
            <div v-if="!hasActiveScan && !agentStore.messages.length" class="chat-empty">
              <div class="empty-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                  <polyline points="14 2 14 8 20 8"/>
                  <line x1="16" y1="13" x2="8" y2="13"/>
                  <line x1="16" y1="17" x2="8" y2="17"/>
                </svg>
              </div>
              <p>导入服务端扫描结果开始智能攻击，或直接与 Agent 对话</p>
            </div>
            <!-- 有数据时的空聊天状态 -->
            <div v-else-if="hasActiveScan && !agentStore.messages.length" class="chat-empty">
              <p>基于扫描结果与 Agent 对话，分析横移路径、攻击面和下一步行动</p>
              <div class="suggestions">
                <el-button
                  v-for="item in promptSuggestions"
                  :key="item.label"
                  size="small"
                  plain
                  @click="fillPrompt(item.prompt)"
                >{{ item.label }}</el-button>
              </div>
            </div>
            <div v-for="(msg, i) in agentStore.messages" :key="i" class="chat-msg" :class="msg.role">
              <div class="msg-role">{{ msg.role === 'user' ? '你' : msg.role === 'assistant' ? 'Agent' : '系统' }}</div>
              <div class="msg-content" v-html="renderContent(msg.content)"></div>
            </div>
            <div v-if="agentStore.streaming" class="typing-indicator">
              <span></span><span></span><span></span>
            </div>
          </div>

          <div class="chat-input-area">
            <textarea
              ref="inputRef"
              v-model="inputMsg"
              class="chat-input"
              :placeholder="'输入消息... (Enter 发送, Shift+Enter 换行)'"
              :disabled="agentStore.streaming"
              @keydown="handleKeydown"
              @compositionstart="handleCompositionStart"
              @compositionend="handleCompositionEnd"
              rows="2"
            ></textarea>
            <el-button v-if="agentStore.streaming" class="chat-action-btn is-stop" type="warning" plain :loading="stoppingChat" @click="stopAndEditMessage">
              中断并编辑
            </el-button>
            <el-button v-else class="chat-action-btn is-send" type="primary" :disabled="!inputMsg.trim()" @click="sendMessage">
              发送
            </el-button>
          </div>
        </section>
      </div>
    </template>

    <!-- EXP Forge -->
    <template v-if="subTab === 'exp'">
      <ExpForgePanel
        class="agent-exp"
        :scan-id="scanStore.activeResultId ?? undefined"
        :initial-template-ids="expContext.templateIds"
        :initial-finding-ids="expContext.findingIds"
        :initial-fact-ids="expContext.factIds"
        :initial-params="expContext.params"
      />
    </template>

    <!-- Skills -->
    <template v-if="subTab === 'skills'">
      <div class="skills-shell">
        <aside class="skills-rail">
          <div class="skills-head">
            <span>Agent Skills</span>
            <el-button size="small" text :disabled="agentStore.streaming" @click="startNewSkill">新增</el-button>
          </div>
          <div v-if="skillsLoading" class="skills-empty">加载中...</div>
          <div v-else-if="!skillList.length" class="skills-empty">暂无 Skills</div>
          <div v-else class="skills-list">
            <button
              v-for="skill in skillList"
              :key="skill.name"
              type="button"
              class="skill-row"
              :class="{ active: selectedSkillName === skill.name }"
              :disabled="agentStore.streaming"
              @click="selectSkill(skill.name)"
            >
              <span class="skill-row__name">{{ skill.name }}</span>
              <span class="skill-row__summary">{{ skill.summary || 'SKILL.md' }}</span>
            </button>
          </div>
        </aside>
        <section class="skill-editor">
          <div class="skill-editor__bar">
            <input
              v-model="newSkillName"
              class="skill-name-input"
              :readonly="!!selectedSkillName"
              :placeholder="selectedSkillName || 'skill-name'"
              :disabled="agentStore.streaming || skillSaving"
            />
            <span v-if="selectedSkillName" class="skill-path">.claude/skills/{{ selectedSkillName }}/SKILL.md</span>
            <span v-else class="skill-path">.claude/skills/&lt;name&gt;/SKILL.md</span>
            <el-button size="small" type="primary" :loading="skillSaving" :disabled="agentStore.streaming || !skillContent.trim()" @click="saveSkill">保存</el-button>
            <el-button
              size="small"
              type="danger"
              plain
              :disabled="agentStore.streaming || !selectedSkillName"
              @click="deleteSkill(selectedSkillName)"
            >删除</el-button>
          </div>
          <textarea
            v-model="skillContent"
            class="skill-content"
            spellcheck="false"
            :disabled="agentStore.streaming || skillSaving"
            placeholder="# Skill Name"
          ></textarea>
          <div v-if="agentStore.streaming" class="skill-lock">Agent 运行中，当前不可编辑 Skills</div>
        </section>
      </div>
    </template>

    <!-- Attack Surface -->
    <template v-if="subTab === 'surface'">
      <div class="graph-container">
        <div v-if="graphLoading" class="graph-loading">
          <el-icon class="is-loading"><Loading /></el-icon> 正在解析攻击面...
        </div>
        <div v-else-if="!graphData" class="graph-empty">
          <p>需要先加载扫描数据</p>
          <div class="graph-empty-actions">
            <el-button @click="loadGraph" :disabled="!hasActiveScan || graphLoading">解析攻击面</el-button>
            <el-button
              type="primary"
              :loading="aiAnalysisLoading"
              :disabled="!hasActiveScan || graphLoading || agentStore.streaming"
              @click="runAiSurfaceAnalysis"
            >一键智能分析攻击面</el-button>
          </div>
        </div>
        <div v-else class="graph-content">
          <div class="graph-stats">
            <span>{{ surfaceFindings.length }} 个研判项</span>
            <span v-if="aiSurfaceFindings.length">AI: {{ aiSurfaceFindings.length }}</span>
            <span v-if="engineSurfaceFindings.length">引擎: {{ engineSurfaceFindings.length }}</span>
            <span>{{ graphData.summary?.factCount || 0 }} facts</span>
            <span v-if="graphData.summary?.errorCount">{{ graphData.summary.errorCount }} 个采集错误</span>
            <el-button size="small" plain @click="loadGraph">刷新</el-button>
            <span style="flex:1"></span>
            <el-button
              size="small"
              type="primary"
              plain
              :loading="aiAnalysisLoading"
              :disabled="agentStore.streaming"
              @click="runAiSurfaceAnalysis"
            >一键智能分析</el-button>
            <el-button
              v-if="aiAnalysisLoading"
              size="small"
              type="warning"
              plain
              @click="stopAiSurfaceAnalysis"
            >中断</el-button>
            <el-button size="small" plain :loading="exportLoading" @click="exportReport('json')">导出 JSON</el-button>
            <el-button size="small" plain :loading="exportLoading" @click="exportReport('markdown')">导出 Markdown</el-button>
          </div>

          <div v-if="aiAnalysisStatus" class="ai-analysis-status" :class="{ running: aiAnalysisLoading }">
            <span class="status-dot" :class="{ ready: !aiAnalysisLoading }"></span>
            <span>{{ aiAnalysisStatus }}</span>
          </div>

          <!-- Tab switcher: AI vs Engine -->
          <el-segmented
            v-if="aiSurfaceFindings.length || engineSurfaceFindings.length"
            v-model="surfaceTab"
            :options="[
              { label: `AI 分析结果 (${aiSurfaceFindings.length})`, value: 'ai' },
              { label: `引擎推断 (${engineSurfaceFindings.length})`, value: 'engine' },
            ]"
            size="small"
            class="surface-tabs"
          />

          <!-- AI tab: AI confirmed + cluster admin -->
          <div v-if="surfaceTab === 'ai' && aiSurfaceFindings.length" class="surface-list">
            <article
              v-for="finding in aiSurfaceFindings"
              :key="finding.id"
              class="surface-item"
              :class="[`is-${finding.severity}`, `cat-${finding.category}`, { 'is-cluster-admin': isClusterAdminFinding(finding), 'is-blocked': isNonExploitableFinding(finding) }]"
            >
              <header class="surface-head">
                <span v-if="isClusterAdminFinding(finding)" class="surface-cluster-badge">🔴 集群管理员</span>
                <span v-else-if="isNonExploitableFinding(finding)" class="surface-blocked-badge">🚫 不可利用</span>
                <span class="surface-severity">{{ severityLabel(finding.severity) }}</span>
                <span class="surface-category">{{ categoryLabel(finding.category) }}</span>
                <span v-if="finding.origin" class="surface-origin" :class="`is-${finding.origin}`">{{ originLabel(finding.origin) }}</span>
                <span v-if="finding.confidence" class="surface-confidence">{{ confidenceLabel(finding.confidence) }}</span>
                <div class="surface-title">
                  <div class="surface-name">{{ finding.title || finding.id }}</div>
                  <div class="surface-id">{{ finding.id }}</div>
                </div>
                <el-button
                  v-if="!isClusterAdminFinding(finding) && !isNonExploitableFinding(finding)"
                  size="small"
                  type="danger"
                  plain
                  :disabled="!expTemplatesForFinding(finding).length"
                  @click="openExpForFinding(finding)"
                >EXP</el-button>
              </header>

              <p class="surface-desc">{{ finding.description }}</p>

              <div v-if="isClusterAdminFinding(finding)" class="surface-cluster-notice">
                无需执行容器逃逸或权限提升操作，当前身份已实质上控制整个集群，可直接操作任意命名空间中的任意资源。
              </div>

              <div v-if="finding.evidence?.length && !isClusterAdminFinding(finding)" class="surface-row">
                <span class="surface-label">证据</span>
                <button
                  v-for="e in finding.evidence"
                  :key="e"
                  type="button"
                  class="surface-chip surface-chip-btn"
                  :title="`查看证据 ${e}`"
                  @click="openEvidence(e)"
                >{{ e }}</button>
              </div>

              <div v-if="expTemplatesForFinding(finding).length && !isClusterAdminFinding(finding)" class="surface-row">
                <span class="surface-label">模板</span>
                <span v-for="t in expTemplatesForFinding(finding)" :key="t" class="surface-chip is-template">{{ t }}</span>
              </div>

              <div v-if="finding.nextSteps?.length && !isClusterAdminFinding(finding)" class="surface-next">
                <div class="surface-label">下一步</div>
                <ul>
                  <li v-for="step in finding.nextSteps" :key="step">{{ step }}</li>
                </ul>
              </div>
            </article>
          </div>

          <!-- Engine tab: Doc/Graph/Catalog findings -->
          <div v-if="surfaceTab === 'engine' && engineSurfaceFindings.length" class="surface-list">
            <article
              v-for="finding in engineSurfaceFindings"
              :key="finding.id"
              class="surface-item"
              :class="[`is-${finding.severity}`, `cat-${finding.category}`, { 'is-doc-origin': isDocFinding(finding), 'is-blocked': isNonExploitableFinding(finding) }]"
            >
              <header class="surface-head">
                <span v-if="isNonExploitableFinding(finding)" class="surface-blocked-badge">🚫 不可利用</span>
                <span class="surface-severity">{{ severityLabel(finding.severity) }}</span>
                <span class="surface-category">{{ categoryLabel(finding.category) }}</span>
                <span v-if="finding.origin" class="surface-origin" :class="`is-${finding.origin}`">{{ originLabel(finding.origin) }}</span>
                <span v-if="finding.confidence" class="surface-confidence is-heuristic">{{ confidenceLabel(finding.confidence) }}</span>
                <span v-if="isDocFinding(finding)" class="surface-unverified">待验证</span>
                <div class="surface-title">
                  <div class="surface-name">{{ finding.title || finding.id }}</div>
                  <div class="surface-id">{{ finding.id }}</div>
                </div>
                <el-button
                  v-if="!isNonExploitableFinding(finding)"
                  size="small"
                  type="danger"
                  plain
                  :disabled="!expTemplatesForFinding(finding).length"
                  @click="openExpForFinding(finding)"
                >EXP</el-button>
              </header>

              <p class="surface-desc">{{ finding.description }}</p>

              <div v-if="finding.evidence?.length" class="surface-row">
                <span class="surface-label">证据</span>
                <button
                  v-for="e in finding.evidence"
                  :key="e"
                  type="button"
                  class="surface-chip surface-chip-btn"
                  :title="`查看证据 ${e}`"
                  @click="openEvidence(e)"
                >{{ e }}</button>
              </div>

              <div v-if="expTemplatesForFinding(finding).length" class="surface-row">
                <span class="surface-label">模板</span>
                <span v-for="t in expTemplatesForFinding(finding)" :key="t" class="surface-chip is-template">{{ t }}</span>
              </div>

              <div v-if="finding.nextSteps?.length" class="surface-next">
                <div class="surface-label">下一步</div>
                <ul>
                  <li v-for="step in finding.nextSteps" :key="step">{{ step }}</li>
                </ul>
              </div>
            </article>
          </div>

          <div v-if="!aiSurfaceFindings.length && !engineSurfaceFindings.length" class="surface-empty">
            未从当前扫描结果解析出可验证攻击面问题。
          </div>
        </div>
      </div>
    </template>

    <el-dialog v-model="evidenceDialogVisible" title="证据详情" width="720px">
      <div v-if="selectedEvidence" class="evidence-dialog">
        <div class="evidence-meta">
          <span class="evidence-kv"><b>ref</b>{{ selectedEvidence.ref }}</span>
          <span class="evidence-kv"><b>fact</b>{{ selectedEvidence.factId }}</span>
          <span v-if="selectedEvidence.selector" class="evidence-kv"><b>selector</b>{{ selectedEvidence.selector }}</span>
          <span class="evidence-kv"><b>kind</b>{{ selectedEvidence.kind }}</span>
        </div>
        <div v-if="selectedEvidence.fact" class="evidence-fact-meta">
          <span>{{ selectedEvidence.fact.collector || 'unknown collector' }}</span>
          <span>{{ selectedEvidence.fact.category || 'unknown category' }}</span>
          <span v-if="selectedEvidence.fact.source">{{ selectedEvidence.fact.source }}</span>
          <span v-if="selectedEvidence.fact.sensitive">sensitive</span>
        </div>
        <div v-if="selectedEvidence.kind === 'missing'" class="evidence-missing">
          当前导入文档中没有找到这个 fact。它可能是 graph 派生证据、target/run 字段片段，或来自旧版扫描结果。
        </div>
        <pre v-else class="evidence-json">{{ selectedEvidenceValue }}</pre>
      </div>
    </el-dialog>
  </div>
</template>

<script lang="ts">
function renderContent(content: string): string {
  if (!content) return ''
  return content
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\n/g, '<br>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
}
</script>

<style scoped>
.agent-panel {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  padding: 12px;
  gap: 10px;
  background:
    linear-gradient(180deg, rgba(96, 165, 250, 0.035), transparent 180px),
    var(--kg-bg);
}
.agent-status-bar {
  flex: 0 0 auto;
  min-height: 38px;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 7px 10px;
  border-radius: 8px;
  background: color-mix(in srgb, var(--kg-surface) 88%, var(--kg-surface-2));
  border: 1px solid var(--kg-border);
  font-size: 12px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.14);
}
.status-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--kg-text-dim); }
.status-dot.ready { background: var(--kg-accent); }
.status-text { color: var(--kg-text-muted); }
.status-text.warn { color: var(--kg-warn); }
.scan-badge { font-size: 11px; padding: 2px 6px; border-radius: 3px; background: var(--kg-surface-2); font-family: var(--kg-font-mono); }
.agent-tabs {
  flex: 0 0 auto;
  width: 100%;
  max-width: 100%;
}
.agent-tabs :deep(.el-segmented__group) {
  width: 100%;
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
}
.agent-tabs :deep(.el-segmented__item) {
  min-width: 0;
}
.agent-tabs :deep(.el-segmented__item-label) {
  width: 100%;
  min-width: 0;
  text-align: center;
}
.chat-shell { flex: 1; min-height: 0; display: grid; grid-template-columns: minmax(220px, 270px) minmax(0, 1fr); gap: 10px; }
.chat-history {
  min-height: 0;
  display: flex;
  flex-direction: column;
  border: 1px solid var(--kg-border);
  border-radius: 8px;
  background: color-mix(in srgb, var(--kg-surface) 92%, var(--kg-bg));
  overflow: hidden;
}
.history-head { height: 38px; flex: 0 0 auto; display: flex; align-items: center; justify-content: space-between; padding: 0 8px 0 12px; border-bottom: 1px solid var(--kg-border); font-size: 12px; font-weight: 800; color: var(--kg-text); }
.history-list { min-height: 0; overflow-y: auto; overflow-x: hidden; padding: 7px; display: flex; flex-direction: column; gap: 5px; }
.history-item { box-sizing: border-box; width: 100%; max-width: 100%; min-height: 58px; display: flex; flex-direction: column; gap: 6px; padding: 8px 9px; border: 1px solid transparent; border-radius: 7px; background: transparent; color: var(--kg-text); text-align: left; cursor: pointer; outline: none; transition: background var(--kg-dur) var(--kg-ease), border-color var(--kg-dur) var(--kg-ease); }
.history-item:hover { background: var(--kg-surface-2); }
.history-item.active { border-color: color-mix(in srgb, var(--kg-accent) 65%, var(--kg-border)); background: var(--kg-accent-soft); }
.history-item.disabled { cursor: default; opacity: 0.75; }
.history-top { min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr) 22px; align-items: center; gap: 8px; }
.history-title { font-size: 12px; font-weight: 600; line-height: 1.25; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.history-title-input { width: 100%; height: 20px; min-width: 0; border: 1px solid var(--kg-accent); border-radius: 4px; background: var(--kg-bg); color: var(--kg-text); font-size: 12px; font-weight: 600; padding: 1px 5px; outline: none; }
.history-meta { min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr) max-content; gap: 10px; color: var(--kg-text-muted); font-size: 10px; font-family: var(--kg-font-mono); }
.history-count { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.history-time { white-space: nowrap; justify-self: end; }
.history-actions { display: flex; align-items: center; justify-content: flex-end; }
.history-action { width: 22px; height: 20px; border: 0; border-radius: 4px; background: transparent; color: var(--kg-text-muted); display: flex; align-items: center; justify-content: center; font-size: 16px; font-weight: 700; line-height: 1; cursor: pointer; padding: 0; }
.history-action:disabled { cursor: default; opacity: 0.5; }
.history-delete:hover:not(:disabled) { background: var(--kg-warn); color: #fff; }
.history-empty { padding: 16px 6px; text-align: center; color: var(--kg-text-muted); font-size: 12px; }
.chat-main {
  min-width: 0;
  min-height: 0;
  display: flex;
  flex-direction: column;
  border: 1px solid var(--kg-border);
  border-radius: 8px;
  background: color-mix(in srgb, var(--kg-surface) 72%, var(--kg-bg));
  overflow: hidden;
}
.agent-runtime { flex: 0 0 auto; display: flex; align-items: center; gap: 8px; padding: 7px 9px; border-bottom: 1px solid var(--kg-border); background: var(--kg-surface); min-height: 36px; overflow: hidden; }
.runtime-state { flex: 0 0 auto; font-size: 11px; font-weight: 700; color: var(--kg-text-muted); }
.runtime-state.active { color: var(--kg-accent); }
.runtime-model { flex: 0 0 auto; max-width: 160px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 11px; font-family: var(--kg-font-mono); color: var(--kg-text-muted); }
.runtime-skills { min-width: 0; display: flex; align-items: center; gap: 5px; overflow-x: auto; scrollbar-width: thin; }
.runtime-skills.empty { overflow: hidden; }
.runtime-prefix { flex: 0 0 auto; font-size: 10px; font-weight: 700; color: var(--kg-text-dim); text-transform: uppercase; }
.runtime-muted { flex: 0 0 auto; color: var(--kg-text-muted); font-size: 11px; }
.skill-chip { flex: 0 0 auto; max-width: 190px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; padding: 2px 6px; border-radius: 4px; background: var(--kg-surface-2); color: var(--kg-text); font-size: 11px; font-family: var(--kg-font-mono); }
.chat-messages { flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 9px; padding: 12px; min-height: 0; }
.chat-empty {
  align-self: stretch;
  margin: auto;
  text-align: center;
  color: var(--kg-text-muted);
  padding: 36px 18px;
  border: 1px dashed var(--kg-border);
  border-radius: 8px;
  background: color-mix(in srgb, var(--kg-surface) 70%, transparent);
}
.chat-empty p { margin: 0 0 16px; font-size: 14px; }
.empty-icon { margin: 0 auto 16px; width: 48px; height: 48px; display: flex; align-items: center; justify-content: center; border-radius: 8px; background: var(--kg-surface-2); color: var(--kg-text-dim); }
.empty-icon svg { width: 24px; height: 24px; }
.suggestions { display: flex; gap: 8px; justify-content: center; flex-wrap: wrap; }
.chat-msg { padding: 9px 12px; border-radius: 8px; max-width: min(86%, 860px); border: 1px solid transparent; }
.chat-msg.user { align-self: flex-end; background: color-mix(in srgb, var(--kg-accent) 90%, #ffffff); color: #06281d; }
.chat-msg.assistant { align-self: flex-start; background: var(--kg-surface-2); border-color: var(--kg-border); }
.chat-msg.system { align-self: center; background: var(--kg-surface); border-color: var(--kg-border); font-size: 12px; color: var(--kg-warn); }
.msg-role { font-size: 10px; font-weight: 600; margin-bottom: 2px; opacity: 0.7; }
.msg-content { font-size: 13px; line-height: 1.5; word-break: break-word; }
.msg-content :deep(code) { font-family: var(--kg-font-mono); font-size: 12px; background: rgba(0,0,0,0.2); padding: 1px 4px; border-radius: 3px; }
.typing-indicator { display: flex; gap: 4px; padding: 8px 12px; align-self: flex-start; }
.typing-indicator span { width: 6px; height: 6px; border-radius: 50%; background: var(--kg-text-muted); animation: typing 1.2s infinite; }
.typing-indicator span:nth-child(2) { animation-delay: 0.2s; }
.typing-indicator span:nth-child(3) { animation-delay: 0.4s; }
@keyframes typing { 0%, 60%, 100% { opacity: 0.3; } 30% { opacity: 1; } }
.chat-input-area { flex: 0 0 auto; display: flex; gap: 10px; align-items: stretch; padding: 10px; border-top: 1px solid var(--kg-border); background: var(--kg-surface); }
.chat-input { flex: 1 1 auto; width: 100%; min-width: 0; min-height: 46px; max-height: 132px; resize: vertical; background: var(--kg-bg); border: 1px solid var(--kg-border); border-radius: 7px; padding: 10px 11px; color: var(--kg-text); font-size: 13px; font-family: inherit; outline: none; line-height: 1.45; box-sizing: border-box; }
.chat-input:focus { border-color: var(--kg-accent); box-shadow: 0 0 0 3px var(--kg-accent-ring); }
.chat-input:disabled { opacity: 0.5; cursor: not-allowed; }
.chat-action-btn {
  flex: 0 0 auto;
  min-height: 46px;
  margin-left: 0;
  padding: 0 12px;
}
.chat-action-btn.is-send { width: 78px; }
.chat-action-btn.is-stop { width: 118px; }
.agent-exp {
  flex: 1;
  min-height: 0;
}
.skills-shell {
  flex: 1;
  min-height: 0;
  display: grid;
  grid-template-columns: minmax(220px, 280px) minmax(0, 1fr);
  gap: 10px;
}
.skills-rail {
  min-height: 0;
  display: flex;
  flex-direction: column;
  border: 1px solid var(--kg-border);
  border-radius: 8px;
  background: color-mix(in srgb, var(--kg-surface) 90%, var(--kg-bg));
  overflow: hidden;
}
.skills-head {
  height: 38px;
  flex: 0 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 0 8px 0 12px;
  border-bottom: 1px solid var(--kg-border);
  color: var(--kg-text);
  font-size: 12px;
  font-weight: 800;
}
.skills-list {
  min-height: 0;
  overflow-y: auto;
  padding: 7px;
  display: flex;
  flex-direction: column;
  gap: 5px;
}
.skills-empty {
  padding: 18px 10px;
  text-align: center;
  color: var(--kg-text-muted);
  font-size: 12px;
}
.skill-row {
  width: 100%;
  min-height: 50px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 8px 9px;
  border: 1px solid transparent;
  border-radius: 7px;
  background: transparent;
  color: var(--kg-text);
  text-align: left;
  cursor: pointer;
}
.skill-row:hover:not(:disabled) { background: var(--kg-surface-2); }
.skill-row.active {
  border-color: color-mix(in srgb, var(--kg-accent) 65%, var(--kg-border));
  background: var(--kg-accent-soft);
}
.skill-row:disabled {
  cursor: default;
  opacity: 0.7;
}
.skill-row__name {
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 12px;
  font-weight: 700;
  font-family: var(--kg-font-mono);
}
.skill-row__summary {
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--kg-text-muted);
  font-size: 11px;
}
.skill-editor {
  min-width: 0;
  min-height: 0;
  display: flex;
  flex-direction: column;
  border: 1px solid var(--kg-border);
  border-radius: 8px;
  background: color-mix(in srgb, var(--kg-surface) 76%, var(--kg-bg));
  overflow: hidden;
}
.skill-editor__bar {
  flex: 0 0 auto;
  display: grid;
  grid-template-columns: minmax(130px, 210px) minmax(0, 1fr) max-content max-content;
  gap: 8px;
  align-items: center;
  padding: 8px;
  border-bottom: 1px solid var(--kg-border);
  background: var(--kg-surface);
}
.skill-name-input {
  width: 100%;
  min-width: 0;
  height: 30px;
  box-sizing: border-box;
  border: 1px solid var(--kg-border);
  border-radius: 6px;
  background: var(--kg-bg);
  color: var(--kg-text);
  font-family: var(--kg-font-mono);
  font-size: 12px;
  padding: 0 8px;
  outline: none;
}
.skill-name-input:focus {
  border-color: var(--kg-accent);
  box-shadow: 0 0 0 3px var(--kg-accent-ring);
}
.skill-name-input[readonly] { color: var(--kg-text-muted); }
.skill-path {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--kg-text-muted);
  font-size: 11px;
  font-family: var(--kg-font-mono);
}
.skill-content {
  flex: 1 1 auto;
  min-height: 0;
  width: 100%;
  box-sizing: border-box;
  border: 0;
  resize: none;
  outline: none;
  padding: 12px;
  background: var(--kg-bg);
  color: var(--kg-text);
  font-size: 12px;
  line-height: 1.55;
  font-family: var(--kg-font-mono);
}
.skill-content:disabled { opacity: 0.65; }
.skill-lock {
  flex: 0 0 auto;
  padding: 7px 10px;
  border-top: 1px solid var(--kg-border);
  color: var(--kg-warn);
  background: var(--kg-surface);
  font-size: 12px;
}
.graph-container {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  border: 1px solid var(--kg-border);
  border-radius: 8px;
  background: color-mix(in srgb, var(--kg-surface) 78%, var(--kg-bg));
}
.graph-loading { text-align: center; padding: 44px 0; color: var(--kg-text-muted); }
.graph-empty { text-align: center; padding: 44px 0; color: var(--kg-text-muted); }
.graph-empty-actions { display: flex; justify-content: center; gap: 8px; flex-wrap: wrap; }
.graph-content { display: flex; flex-direction: column; gap: 12px; padding: 12px; }
.graph-stats {
  position: sticky;
  top: 0;
  z-index: 1;
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  font-size: 12px;
  color: var(--kg-text-muted);
  align-items: center;
  padding: 8px;
  border: 1px solid var(--kg-border);
  border-radius: 8px;
  background: color-mix(in srgb, var(--kg-surface) 92%, var(--kg-bg));
}
.ai-analysis-status {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 7px 9px;
  border: 1px solid var(--kg-border-soft);
  border-radius: 6px;
  background: var(--kg-surface);
  color: var(--kg-text-muted);
  font-size: 12px;
}
.ai-analysis-status.running { color: var(--kg-accent); }
.surface-empty { padding: 28px 12px; text-align: center; color: var(--kg-text-muted); border: 1px dashed var(--kg-border); border-radius: 8px; background: var(--kg-surface); font-size: 13px; }
.surface-tabs {
  flex: 0 0 auto;
  width: 100%;
  max-width: 100%;
}
.surface-tabs :deep(.el-segmented__group) {
  width: 100%;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
}
.surface-tabs :deep(.el-segmented__item-label) {
  width: 100%;
  min-width: 0;
  text-align: center;
}
.surface-list { display: flex; flex-direction: column; gap: 10px; }
.surface-item { position: relative; display: flex; flex-direction: column; gap: 9px; padding: 12px; border: 1px solid var(--kg-border); border-radius: 8px; background: var(--kg-surface); overflow: hidden; }
.surface-item::before { content: ""; position: absolute; inset: 0 auto 0 0; width: 3px; background: var(--kg-border); }
.surface-item.is-critical { border-color: color-mix(in srgb, var(--kg-danger) 70%, var(--kg-border)); }
.surface-item.is-critical::before { background: var(--kg-danger); }
.surface-item.is-high { border-color: color-mix(in srgb, var(--kg-warn) 70%, var(--kg-border)); }
.surface-item.is-high::before { background: var(--kg-warn); }
.surface-item.is-medium::before { background: var(--kg-info); }
.surface-item.is-blocked { border-color: var(--kg-border-soft); background: color-mix(in srgb, var(--kg-surface) 80%, var(--kg-bg)); opacity: 0.78; }
.surface-item.is-blocked::before { background: var(--kg-text-dim); }
.surface-item.is-cluster-admin {
  border-color: color-mix(in srgb, #f59e0b 60%, var(--kg-border));
  background: color-mix(in srgb, #fef3c7 8%, var(--kg-surface));
  box-shadow: 0 0 0 1px color-mix(in srgb, #f59e0b 35%, transparent), 0 4px 16px rgba(245, 158, 11, 0.12);
}
.surface-item.is-cluster-admin::before { background: #f59e0b; }
.surface-head { min-width: 0; display: flex; align-items: center; gap: 8px; padding-left: 2px; }
.surface-severity, .surface-category, .surface-origin, .surface-confidence { flex: 0 0 auto; font-size: 10px; font-weight: 800; padding: 3px 7px; border-radius: 4px; line-height: 1.2; }
.surface-severity { background: var(--kg-danger); color: #fff; }
.surface-item.is-high .surface-severity { background: var(--kg-warn); }
.surface-item.is-medium .surface-severity { background: var(--kg-info); }
.surface-item.is-low .surface-severity { background: var(--kg-text-dim); color: #fff; }
.surface-item.is-info .surface-severity { background: var(--kg-surface-2); color: var(--kg-text-muted); }
.surface-item.is-blocked .surface-severity { background: var(--kg-text-dim); color: #fff; }
.surface-item.is-doc-origin {
  border-style: dashed;
  background: color-mix(in srgb, var(--kg-surface) 88%, var(--kg-bg));
  opacity: 0.82;
}
.surface-category { background: var(--kg-surface-2); color: var(--kg-text-muted); }
.surface-origin { background: var(--kg-surface-2); color: var(--kg-text-dim); border: 1px solid var(--kg-border-soft); }
.surface-origin.is-agent { background: var(--kg-accent-soft); color: var(--kg-accent); border-color: color-mix(in srgb, var(--kg-accent) 40%, var(--kg-border-soft)); }
.surface-origin.is-document,
.surface-origin.is-catalog { opacity: 0.65; }
.surface-confidence { background: transparent; color: var(--kg-text-dim); border: 1px dashed var(--kg-border); }
.surface-confidence.is-heuristic { opacity: 0.55; }
.surface-unverified {
  flex: 0 0 auto;
  font-size: 9px;
  font-weight: 700;
  padding: 2px 6px;
  border-radius: 3px;
  background: color-mix(in srgb, var(--kg-warn) 18%, transparent);
  color: var(--kg-warn);
  border: 1px solid color-mix(in srgb, var(--kg-warn) 35%, transparent);
}
.surface-cluster-badge {
  flex: 0 0 auto;
  font-size: 11px;
  font-weight: 800;
  padding: 4px 9px;
  border-radius: 4px;
  line-height: 1.2;
  background: #f59e0b;
  color: #fff;
  animation: clusterPulse 2s ease-in-out infinite;
}
@keyframes clusterPulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(245, 158, 11, 0.5); }
  50% { box-shadow: 0 0 0 6px rgba(245, 158, 11, 0); }
}
.surface-blocked-badge {
  flex: 0 0 auto;
  font-size: 11px;
  font-weight: 800;
  padding: 4px 9px;
  border-radius: 4px;
  line-height: 1.2;
  background: var(--kg-text-dim);
  color: #fff;
}
.surface-cluster-notice {
  margin: 0;
  padding: 8px 12px;
  border-radius: 6px;
  background: color-mix(in srgb, #f59e0b 12%, transparent);
  border: 1px solid color-mix(in srgb, #f59e0b 35%, var(--kg-border-soft));
  color: #92400e;
  font-size: 12px;
  font-weight: 600;
  line-height: 1.5;
}
.surface-title { min-width: 0; flex: 1; }
.surface-name { color: var(--kg-text); font-size: 13px; font-weight: 700; line-height: 1.3; }
.surface-id { margin-top: 2px; color: var(--kg-text-dim); font-size: 10px; font-family: var(--kg-font-mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.surface-desc { margin: 0; color: var(--kg-text-muted); font-size: 12px; line-height: 1.5; }
.surface-row { display: flex; align-items: center; gap: 5px; flex-wrap: wrap; padding-left: 2px; }
.surface-label { flex: 0 0 auto; color: var(--kg-text-dim); font-size: 10px; font-weight: 800; text-transform: uppercase; }
.surface-chip { max-width: min(420px, 100%); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; padding: 2px 6px; border-radius: 4px; background: var(--kg-surface-2); color: var(--kg-text-muted); font-size: 10px; font-family: var(--kg-font-mono); }
.surface-chip-btn { border: 1px solid transparent; cursor: pointer; text-align: left; }
.surface-chip-btn:hover { border-color: var(--kg-accent); color: var(--kg-accent); background: var(--kg-accent-soft); }
.surface-chip.is-template { color: var(--kg-text); border: 1px solid var(--kg-border); }
.surface-next { display: grid; grid-template-columns: 58px minmax(0, 1fr); gap: 8px; padding: 4px 0 0 2px; }
.surface-next ul { margin: 0; padding-left: 16px; color: var(--kg-text); font-size: 12px; line-height: 1.45; }
.surface-next li { margin-bottom: 3px; }
.evidence-dialog { display: flex; flex-direction: column; gap: 10px; min-width: 0; }
.evidence-meta,
.evidence-fact-meta { display: flex; flex-wrap: wrap; gap: 6px; }
.evidence-kv,
.evidence-fact-meta span { display: inline-flex; align-items: center; gap: 5px; max-width: 100%; padding: 3px 7px; border-radius: 4px; background: var(--kg-surface-2); color: var(--kg-text-muted); font: 11px var(--kg-font-mono); }
.evidence-kv b { color: var(--kg-text-dim); font: 700 10px var(--kg-font-sans); text-transform: uppercase; }
.evidence-missing { padding: 10px 12px; border: 1px solid var(--kg-border-soft); border-radius: 6px; background: var(--kg-surface); color: var(--kg-text-muted); font-size: 12px; }
.evidence-json { max-height: 440px; overflow: auto; margin: 0; padding: 12px; border-radius: 6px; background: var(--kg-surface-2); color: var(--kg-text); font: 11.5px/1.5 var(--kg-font-mono); white-space: pre-wrap; word-break: break-word; }
.section-title { font-size: 13px; font-weight: 600; margin-bottom: 4px; }
.graph-nodes { max-height: 300px; overflow-y: auto; }
.node-item { display: flex; align-items: center; gap: 8px; padding: 3px 0; font-size: 12px; }
.node-type { font-size: 10px; font-weight: 600; padding: 1px 5px; border-radius: 3px; background: var(--kg-surface-2); min-width: 60px; text-align: center; }
.node-type.pod, .node-type.container { color: #60a5fa; }
.node-type.serviceaccount { color: #34d399; }
.node-type.permission { color: #fbbf24; }
.node-type.secret, .node-type.material { color: #f87171; }
.node-type.node { color: #9ca3af; }
.node-type.runtime { color: #a78bfa; }
.node-label { font-family: var(--kg-font-mono); font-size: 11px; color: var(--kg-text-muted); }
@media (max-width: 820px) {
  .chat-shell { grid-template-columns: 1fr; grid-template-rows: 150px minmax(0, 1fr); }
  .chat-history { min-height: 0; }
  .skills-shell {
    grid-template-columns: 1fr;
    grid-template-rows: 190px minmax(0, 1fr);
  }
  .skills-rail { min-height: 0; }
  .skill-editor__bar { grid-template-columns: 1fr; }
}
</style>
