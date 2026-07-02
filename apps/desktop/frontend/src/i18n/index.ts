import { nextTick, readonly, ref, watch } from 'vue'
import { phraseZhToEn, zhToEn } from './translations'

export type Locale = 'zh-CN' | 'en-US'

const localeKey = 'kubetrail.locale'
const currentLocaleRef = ref<Locale>(normalizeLocale(localStorage.getItem(localeKey) || 'zh-CN'))
const textOriginals = new WeakMap<Text, string>()
const attrOriginals = new WeakMap<Element, Map<string, string>>()
let observer: MutationObserver | null = null
let rootNode: ParentNode | null = null

const sortedPhrases = Object.entries({ ...phraseZhToEn, ...zhToEn })
  .sort((a, b) => b[0].length - a[0].length)

export const currentLocale = readonly(currentLocaleRef)

export function normalizeLocale(value: unknown): Locale {
  return String(value || '').toLowerCase() === 'en-us' || String(value || '').toLowerCase() === 'en'
    ? 'en-US'
    : 'zh-CN'
}

export function setLocale(value: unknown): void {
  const next = normalizeLocale(value)
  if (currentLocaleRef.value === next) {
    return
  }
  currentLocaleRef.value = next
}

export function isEnglish(): boolean {
  return currentLocaleRef.value === 'en-US'
}

export function t(source: string): string {
  return currentLocaleRef.value === 'en-US' ? translateText(source) : source
}

export function translateText(source: string): string {
  if (!source || !containsChinese(source)) {
    return source
  }
  const leading = source.match(/^\s*/)?.[0] ?? ''
  const trailing = source.match(/\s*$/)?.[0] ?? ''
  const trimmed = source.trim().replace(/\s+/g, ' ')
  const exact = zhToEn[trimmed] || phraseZhToEn[trimmed]
  if (exact) {
    return `${leading}${exact}${trailing}`
  }

  let out = source
  for (const [zh, en] of sortedPhrases) {
    if (zh && out.includes(zh)) {
      out = out.split(zh).join(en)
    }
  }
  return out
}

export function startDomTranslator(root: ParentNode = document.body): void {
  rootNode = root
  applyDocumentLanguage()
  translateDom(root)
  observer?.disconnect()
  observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === 'characterData') {
        const node = mutation.target
        if (node.nodeType === Node.TEXT_NODE) {
          translateTextNode(node as Text)
        }
        continue
      }
      if (mutation.type === 'attributes') {
        translateElementAttributes(mutation.target as Element)
        continue
      }
      for (const added of mutation.addedNodes) {
        translateNode(added)
      }
    }
  })
  observer.observe(root, {
    childList: true,
    subtree: true,
    characterData: true,
    attributes: true,
    attributeFilter: ['placeholder', 'title', 'aria-label', 'alt'],
  })
}

export function stopDomTranslator(): void {
  observer?.disconnect()
  observer = null
  rootNode = null
}

export function translateDom(root: ParentNode = document.body): void {
  translateNode(root as Node)
}

watch(currentLocaleRef, (value) => {
  localStorage.setItem(localeKey, value)
  applyDocumentLanguage()
  void nextTick(() => {
    if (rootNode) {
      translateDom(rootNode)
    }
  })
})

function applyDocumentLanguage(): void {
  document.documentElement.lang = currentLocaleRef.value
}

function translateNode(node: Node): void {
  if (node.nodeType === Node.TEXT_NODE) {
    translateTextNode(node as Text)
    return
  }
  if (node.nodeType !== Node.ELEMENT_NODE && node.nodeType !== Node.DOCUMENT_NODE && node.nodeType !== Node.DOCUMENT_FRAGMENT_NODE) {
    return
  }
  const element = node.nodeType === Node.ELEMENT_NODE ? node as Element : null
  if (element && shouldSkipElement(element)) {
    return
  }
  if (element) {
    translateElementAttributes(element)
  }
  const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT, {
    acceptNode(candidate) {
      if (candidate.nodeType === Node.ELEMENT_NODE && shouldSkipElement(candidate as Element)) {
        return NodeFilter.FILTER_REJECT
      }
      return NodeFilter.FILTER_ACCEPT
    },
  })
  let current: Node | null = walker.currentNode
  while (current) {
    if (current.nodeType === Node.TEXT_NODE) {
      translateTextNode(current as Text)
    } else if (current.nodeType === Node.ELEMENT_NODE) {
      translateElementAttributes(current as Element)
    }
    current = walker.nextNode()
  }
}

function translateTextNode(node: Text): void {
  const parent = node.parentElement
  if (!parent || shouldSkipElement(parent)) {
    return
  }
  if (!textOriginals.has(node) || containsChinese(node.data)) {
    textOriginals.set(node, node.data)
  }
  const original = textOriginals.get(node) ?? node.data
  const desired = currentLocaleRef.value === 'en-US' ? translateText(original) : original
  if (node.data !== desired) {
    node.data = desired
  }
}

function translateElementAttributes(element: Element): void {
  if (shouldSkipElement(element)) {
    return
  }
  for (const name of ['placeholder', 'title', 'aria-label', 'alt']) {
    const value = element.getAttribute(name)
    if (value === null) {
      continue
    }
    let originals = attrOriginals.get(element)
    if (!originals) {
      originals = new Map()
      attrOriginals.set(element, originals)
    }
    if (!originals.has(name) || containsChinese(value)) {
      originals.set(name, value)
    }
    const original = originals.get(name) ?? value
    const desired = currentLocaleRef.value === 'en-US' ? translateText(original) : original
    if (value !== desired) {
      element.setAttribute(name, desired)
    }
  }
}

function shouldSkipElement(element: Element): boolean {
  return ['SCRIPT', 'STYLE', 'TEXTAREA', 'CODE', 'PRE'].includes(element.tagName)
}

function containsChinese(value: string): boolean {
  return /[\u3400-\u9fff]/.test(value)
}
