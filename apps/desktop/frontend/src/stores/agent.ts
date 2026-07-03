import { defineStore } from 'pinia'
import { ref } from 'vue'

const sessionsStorageKey = 'kubetrail.agent.sessions.v1'
const activeSessionStorageKey = 'kubetrail.agent.activeSession.v1'
const surfaceAnalysisStorageKey = 'kubetrail.agent.surfaceAnalysis.v1'
const maxSessions = 50
const maxSurfaceAnalyses = 50

export interface ChatMessage {
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: number
}

export interface ChatSession {
  id: string
  title: string
  createdAt: number
  updatedAt: number
  claudeSessionId: string
  scanSourcePath: string
  messages: ChatMessage[]
}

export interface AgentStatus {
  running: boolean
  ready: boolean
  pid: number
  error?: string
}

export interface SurfaceAnalysisCache {
  scanKey: string
  updatedAt: number
  status: string
  findings: any[]
}

export const useAgentStore = defineStore('agent', () => {
  const status = ref<AgentStatus>({ running: false, ready: false, pid: 0 })
  const sessions = ref<ChatSession[]>(loadSessions())
  const surfaceAnalyses = ref<SurfaceAnalysisCache[]>(loadSurfaceAnalyses())
  const messages = ref<ChatMessage[]>([])
  const streaming = ref(false)
  const sessionId = ref<string>(loadActiveSessionId())
  const claudeSessionId = ref<string>('')
  const scanSourcePath = ref<string>('')
  const model = ref('')
  const provider = ref('')
  const loadedTools = ref<string[]>([])
  const loadedSkills = ref<string[]>([])
  const attackGraph = ref<any>(null)

  if (sessionId.value && sessions.value.some(s => s.id === sessionId.value)) {
    selectSession(sessionId.value)
  } else {
    sessionId.value = ''
  }

  function addMessage(msg: ChatMessage) {
    ensureSession()
    messages.value.push(msg)
    persistCurrentSession()
  }

  function appendToLast(content: string) {
    for (let i = messages.value.length - 1; i >= 0; i--) {
      const msg = messages.value[i]
      if (msg.role === 'assistant') {
        msg.content += content
        persistCurrentSession()
        return
      }
    }
  }

  function setLastAssistantContent(content: string) {
    const text = content.trim()
    if (!text) return
    for (let i = messages.value.length - 1; i >= 0; i--) {
      const msg = messages.value[i]
      if (msg.role !== 'assistant') continue
      if (!sameAssistantText(msg.content, text)) {
        msg.content = text
      }
      persistCurrentSession()
      return
    }
    addMessage({ role: 'assistant', content: text, timestamp: Date.now() })
  }

  function setMessageContentAt(index: number, role: ChatMessage['role'], content: string): boolean {
    const msg = messages.value[index]
    if (!msg || msg.role !== role) return false
    if (!sameAssistantText(msg.content, content)) {
      msg.content = content
    }
    persistCurrentSession()
    return true
  }

  function applyAssistantResult(content: string) {
    const text = content.trim()
    if (!text) return
    for (let i = messages.value.length - 1; i >= 0; i--) {
      const msg = messages.value[i]
      if (msg.role !== 'assistant') continue
      msg.content = text
      removeDuplicateAssistantMessages(text, i)
      persistCurrentSession()
      return
    }
    addMessage({ role: 'assistant', content: text, timestamp: Date.now() })
  }

  function removeDuplicateAssistantMessages(content: string, keepIndex: number) {
    const normalized = normalizeAssistantText(content)
    if (!normalized) return
    for (let i = messages.value.length - 1; i >= 0; i--) {
      if (i === keepIndex) continue
      const msg = messages.value[i]
      if (msg.role === 'assistant' && normalizeAssistantText(msg.content) === normalized) {
        messages.value.splice(i, 1)
      }
    }
  }

  function clearMessages() {
    messages.value = []
    persistCurrentSession()
  }

  function setStatus(s: AgentStatus) {
    status.value = s
  }

  function setGraph(g: any) {
    attackGraph.value = g
  }

  function setClaudeSessionId(id: string) {
    ensureSession()
    claudeSessionId.value = id
    persistCurrentSession()
  }

  function setScanSourcePath(path: string) {
    if (!path || path === scanSourcePath.value) return
    ensureSession()
    scanSourcePath.value = path
    persistCurrentSession()
  }

  function setRuntimeInfo(info: { provider?: string; model?: string; tools?: string[]; skills?: string[] }) {
    provider.value = info.provider || ''
    model.value = info.model || ''
    loadedTools.value = Array.isArray(info.tools) ? [...info.tools] : []
    loadedSkills.value = Array.isArray(info.skills) ? [...info.skills] : []
  }

  function clearRuntimeInfo() {
    model.value = ''
    loadedTools.value = []
    loadedSkills.value = []
  }

  function removeLatestExchange(userContent: string): boolean {
    let changed = false
    const normalized = userContent.trim()
    const last = messages.value[messages.value.length - 1]
    if (last?.role === 'assistant') {
      messages.value.pop()
      changed = true
    }
    const user = messages.value[messages.value.length - 1]
    if (user?.role === 'user' && user.content.trim() === normalized) {
      messages.value.pop()
      changed = true
    }
    if (changed) persistCurrentSession()
    return changed
  }

  function newSession() {
    const now = Date.now()
    const session: ChatSession = {
      id: crypto.randomUUID(),
      title: randomSessionTitle(),
      createdAt: now,
      updatedAt: now,
      claudeSessionId: '',
      scanSourcePath: '',
      messages: [],
    }
    sessions.value = [session, ...sessions.value].slice(0, maxSessions)
    activateSession(session)
    persistSessions()
  }

  function selectSession(id: string): boolean {
    const session = sessions.value.find(item => item.id === id)
    if (!session) return false
    activateSession(session)
    return true
  }

  function deleteSession(id: string) {
    const index = sessions.value.findIndex(item => item.id === id)
    if (index < 0) return
    sessions.value.splice(index, 1)
    if (sessionId.value === id) {
      const next = sessions.value[0]
      if (next) {
        activateSession(next)
      } else {
        sessionId.value = ''
        claudeSessionId.value = ''
        scanSourcePath.value = ''
        messages.value = []
        localStorage.removeItem(activeSessionStorageKey)
      }
    }
    persistSessions()
  }

  function renameSession(id: string, title: string) {
    const session = sessions.value.find(item => item.id === id)
    if (!session) return
    const normalized = normalizeSessionTitle(title)
    session.title = normalized || randomSessionTitle()
    session.updatedAt = Date.now()
    sessions.value = [...sessions.value].sort((a, b) => b.updatedAt - a.updatedAt)
    persistSessions()
  }

  function touchCurrentSession() {
    persistCurrentSession()
  }

  function getSurfaceAnalysis(scanKey: string): SurfaceAnalysisCache | null {
    const key = normalizeScanKey(scanKey)
    if (!key) return null
    const entry = surfaceAnalyses.value.find(item => item.scanKey === key)
    if (!entry) return null
    return {
      ...entry,
      findings: cloneFindings(entry.findings),
    }
  }

  function setSurfaceAnalysis(scanKey: string, findings: any[], status = '') {
    const key = normalizeScanKey(scanKey)
    if (!key) return
    const entry: SurfaceAnalysisCache = {
      scanKey: key,
      updatedAt: Date.now(),
      status: String(status || '').trim(),
      findings: cloneFindings(Array.isArray(findings) ? findings : []),
    }
    surfaceAnalyses.value = [entry, ...surfaceAnalyses.value.filter(item => item.scanKey !== key)]
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .slice(0, maxSurfaceAnalyses)
    persistSurfaceAnalyses()
  }

  function clearSurfaceAnalysis(scanKey: string) {
    const key = normalizeScanKey(scanKey)
    if (!key) return
    const next = surfaceAnalyses.value.filter(item => item.scanKey !== key)
    if (next.length === surfaceAnalyses.value.length) return
    surfaceAnalyses.value = next
    persistSurfaceAnalyses()
  }

  function activateSession(session: ChatSession) {
    sessionId.value = session.id
    claudeSessionId.value = session.claudeSessionId || ''
    scanSourcePath.value = session.scanSourcePath || ''
    messages.value = session.messages.map(item => ({ ...item }))
    localStorage.setItem(activeSessionStorageKey, session.id)
  }

  function ensureSession() {
    if (!sessionId.value || !sessions.value.some(item => item.id === sessionId.value)) {
      newSession()
    }
  }

  function persistCurrentSession() {
    if (!sessionId.value) return
    const session = sessions.value.find(item => item.id === sessionId.value)
    if (!session) return
    session.messages = messages.value.map(item => ({ ...item }))
    session.claudeSessionId = claudeSessionId.value
    session.scanSourcePath = scanSourcePath.value
    session.updatedAt = Date.now()
    sessions.value = [...sessions.value]
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .slice(0, maxSessions)
    persistSessions()
  }

  function persistSessions() {
    try {
      localStorage.setItem(sessionsStorageKey, JSON.stringify(sessions.value))
      if (sessionId.value) {
        localStorage.setItem(activeSessionStorageKey, sessionId.value)
      }
    } catch {
      // Storage quota or disabled storage should not break chat.
    }
  }

  function persistSurfaceAnalyses() {
    try {
      localStorage.setItem(surfaceAnalysisStorageKey, JSON.stringify(surfaceAnalyses.value))
    } catch {
      // Analysis cache is best-effort UI state.
    }
  }

  return { status, sessions, surfaceAnalyses, messages, streaming, sessionId, claudeSessionId, scanSourcePath, provider, model, loadedTools, loadedSkills, attackGraph, addMessage, appendToLast, setLastAssistantContent, setMessageContentAt, applyAssistantResult, clearMessages, setStatus, setGraph, setClaudeSessionId, setScanSourcePath, setRuntimeInfo, clearRuntimeInfo, removeLatestExchange, newSession, selectSession, deleteSession, renameSession, touchCurrentSession, getSurfaceAnalysis, setSurfaceAnalysis, clearSurfaceAnalysis }
})

function loadSessions(): ChatSession[] {
  try {
    const raw = localStorage.getItem(sessionsStorageKey)
    if (!raw) return []
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed
      .map(normalizeSession)
      .filter((item): item is ChatSession => Boolean(item))
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .slice(0, maxSessions)
  } catch {
    return []
  }
}

function loadActiveSessionId(): string {
  try {
    return localStorage.getItem(activeSessionStorageKey) || ''
  } catch {
    return ''
  }
}

function loadSurfaceAnalyses(): SurfaceAnalysisCache[] {
  try {
    const raw = localStorage.getItem(surfaceAnalysisStorageKey)
    if (!raw) return []
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed
      .map(normalizeSurfaceAnalysis)
      .filter((item): item is SurfaceAnalysisCache => Boolean(item))
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .slice(0, maxSurfaceAnalyses)
  } catch {
    return []
  }
}

function normalizeSession(value: any): ChatSession | null {
  if (!value || typeof value !== 'object' || typeof value.id !== 'string') return null
  const now = Date.now()
  const messages = Array.isArray(value.messages)
    ? value.messages
        .filter((msg: any) => msg && ['user', 'assistant', 'system'].includes(msg.role) && typeof msg.content === 'string')
        .map((msg: any) => ({ role: msg.role, content: msg.content, timestamp: Number(msg.timestamp) || now }))
    : []
  return {
    id: value.id,
    title: normalizeSessionTitle(value.title) || randomSessionTitle(),
    createdAt: Number(value.createdAt) || now,
    updatedAt: Number(value.updatedAt) || now,
    claudeSessionId: typeof value.claudeSessionId === 'string' ? value.claudeSessionId : '',
    scanSourcePath: typeof value.scanSourcePath === 'string' ? value.scanSourcePath : '',
    messages,
  }
}

function normalizeSurfaceAnalysis(value: any): SurfaceAnalysisCache | null {
  if (!value || typeof value !== 'object') return null
  const scanKey = normalizeScanKey(value.scanKey)
  if (!scanKey) return null
  return {
    scanKey,
    updatedAt: Number(value.updatedAt) || Date.now(),
    status: typeof value.status === 'string' ? value.status : '',
    findings: cloneFindings(Array.isArray(value.findings) ? value.findings : []),
  }
}

function normalizeSessionTitle(value: unknown): string {
  if (typeof value !== 'string') return ''
  return value.replace(/\s+/g, ' ').trim().slice(0, 48)
}

function randomSessionTitle(): string {
  const value = Math.floor(Math.random() * 10000)
  return `Trail-${String(value).padStart(4, '0')}`
}

function sameAssistantText(left: string, right: string): boolean {
  return normalizeAssistantText(left) === normalizeAssistantText(right)
}

function normalizeAssistantText(value: string): string {
  return value.replace(/\s+/g, ' ').trim()
}

function normalizeScanKey(value: unknown): string {
  return typeof value === 'string' ? value.trim().slice(0, 512) : ''
}

function cloneFindings(findings: any[]): any[] {
  try {
    return JSON.parse(JSON.stringify(findings))
  } catch {
    return []
  }
}
