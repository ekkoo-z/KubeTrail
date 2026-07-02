// Thin wrapper around Wails-generated bindings + event helpers.
// All Go-side methods on App are exposed under window.go.main.App at runtime,
// and as typed imports from `../../wailsjs/go/main/App` when bindings are generated.

import * as App from '../../wailsjs/go/main/App'
import { EventsOn, EventsOff } from '../../wailsjs/runtime/runtime'

export const api = App

export function on<T = any>(event: string, cb: (data: T) => void): () => void {
  EventsOn(event, cb as any)
  return () => EventsOff(event)
}

export function b64encode(s: string): string {
  return btoa(unescape(encodeURIComponent(s)))
}

export function b64decodeToBytes(b64: string): Uint8Array {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export function b64decodeToText(b64: string): string {
  return decodeURIComponent(escape(atob(b64)))
}
