import type { FitAddon } from '@xterm/addon-fit'
import type { Terminal } from '@xterm/xterm'

type ResizeOptions = {
  getTerminal: () => Terminal | null
  getFitAddon: () => FitAddon | null
  getSessionId: () => string
  sendResize: (sessionId: string, cols: number, rows: number) => Promise<void> | void
  minCols?: number
}

export function createTerminalResizeController(options: ResizeOptions) {
  const minCols = options.minCols ?? 32
  let lastSentCols = 0
  let lastSentRows = 0
  let fitFrame: number | null = null

  function currentSize() {
    const terminal = options.getTerminal()
    if (!terminal) return null
    const { cols, rows } = terminal
    if (!validSize(cols, rows)) {
      return null
    }
    return { cols, rows }
  }

  function validSize(cols: number, rows: number) {
    return Number.isFinite(cols) && Number.isFinite(rows) && cols >= minCols && rows >= 1
  }

  function fitLocal() {
    const terminal = options.getTerminal()
    const fit = options.getFitAddon()
    if (!terminal || !fit) return
    const dims = fit.proposeDimensions()
    if (!dims || !validSize(dims.cols, dims.rows)) return
    if (terminal.cols === dims.cols && terminal.rows === dims.rows) return
    terminal.resize(dims.cols, dims.rows)
  }

  async function syncRemoteNow() {
    const sessionId = options.getSessionId()
    const size = currentSize()
    if (!sessionId || !size) return
    if (size.cols === lastSentCols && size.rows === lastSentRows) return

    lastSentCols = size.cols
    lastSentRows = size.rows
    await Promise.resolve(options.sendResize(sessionId, size.cols, size.rows)).catch(() => {})
  }

  async function fitNow(syncRemote = false) {
    fitLocal()
    if (syncRemote) await syncRemoteNow()
  }

  function queueFit() {
    if (fitFrame !== null) return
    fitFrame = window.requestAnimationFrame(() => {
      fitFrame = null
      fitLocal()
    })
  }

  function reset() {
    if (fitFrame !== null) {
      window.cancelAnimationFrame(fitFrame)
      fitFrame = null
    }
    lastSentCols = 0
    lastSentRows = 0
  }

  return { fitNow, queueFit, reset, syncRemoteNow }
}
