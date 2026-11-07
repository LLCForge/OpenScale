"use client"

// One shared subscription to the service's event stream (#328, F-182,
// /api/app/diag/stream). Pages refresh their data when something happens
// instead of polling every few seconds. All components share a single
// EventSource: it opens when the first subscriber mounts and closes with
// the last one.
//
// - A dropped stream is reopened with exponential back-off and jitter
//   (1 s doubling up to 60 s); a successful open resets it. The server
//   ends every stream after ten minutes, which reconnects at once.
// - While the page is hidden the stream is closed; when it is shown again
//   it reopens and every subscriber refreshes once ("resync"), because
//   events may have been missed.
// - A reconnect asks for the events after the last one seen (?since=), so
//   nothing that is still in the service's buffer is lost.

import { useEffect, useEffectEvent, useSyncExternalStore } from "react"
import { useSWRConfig } from "swr"

export interface StreamEvent {
  seq: number
  at: string
  kind: string
  category: string
  severity: string
  peer?: string
  message: string
}

export type StreamState = "idle" | "connecting" | "open" | "retrying" | "paused" | "unsupported"

/** null means "resync": refresh everything, events may have been missed. */
type Listener = (ev: StreamEvent | null) => void

const streamUrl = "/api/app/diag/stream"
const minBackoffMs = 1_000
const maxBackoffMs = 60_000
/** Several events in a burst cause one refresh. */
const debounceMs = 500

const listeners = new Set<Listener>()
const stateListeners = new Set<() => void>()
let state: StreamState = "idle"
let source: EventSource | null = null
let retryTimer: ReturnType<typeof setTimeout> | undefined
let attempt = 0
let lastSeq = 0
let everOpened = false
let visibilityBound = false

function setState(next: StreamState): void {
  if (state === next) return
  state = next
  for (const l of stateListeners) l()
}

function emit(ev: StreamEvent | null): void {
  for (const l of listeners) {
    try {
      l(ev)
    } catch {
      // One broken subscriber does not stop the others.
    }
  }
}

/** Back-off of the given attempt (1-based) with ±25% jitter. */
export function backoffDelay(n: number, random: () => number = Math.random): number {
  const base = Math.min(maxBackoffMs, minBackoffMs * 2 ** Math.max(0, Math.min(n - 1, 16)))
  return Math.round(base * (0.75 + random() * 0.5))
}

function parseEvent(raw: unknown): StreamEvent | null {
  if (typeof raw !== "string" || raw.length > 64 * 1024) return null
  let data: unknown
  try {
    data = JSON.parse(raw)
  } catch {
    return null
  }
  if (!data || typeof data !== "object") return null
  const d = data as Record<string, unknown>
  if (typeof d.seq !== "number" || typeof d.kind !== "string") return null
  return {
    seq: d.seq,
    at: typeof d.at === "string" ? d.at : "",
    kind: d.kind,
    category: typeof d.category === "string" ? d.category : "",
    severity: typeof d.severity === "string" ? d.severity : "info",
    peer: typeof d.peer === "string" ? d.peer : undefined,
    message: typeof d.message === "string" ? d.message : "",
  }
}

function closeSource(): void {
  if (source) {
    source.onopen = null
    source.onmessage = null
    source.onerror = null
    source.close()
    source = null
  }
  if (retryTimer !== undefined) {
    clearTimeout(retryTimer)
    retryTimer = undefined
  }
}

function scheduleRetry(): void {
  closeSource()
  attempt += 1
  setState("retrying")
  retryTimer = setTimeout(() => {
    retryTimer = undefined
    open()
  }, backoffDelay(attempt))
}

function open(): void {
  if (listeners.size === 0) return
  if (typeof EventSource === "undefined") {
    setState("unsupported")
    return
  }
  if (typeof document !== "undefined" && document.hidden) {
    closeSource()
    setState("paused")
    return
  }
  closeSource()
  setState("connecting")
  const url = lastSeq > 0 ? `${streamUrl}?since=${lastSeq}` : streamUrl
  const es = new EventSource(url, { withCredentials: true })
  source = es
  es.onopen = () => {
    attempt = 0
    setState("open")
    // After a drop or a pause the data may be stale.
    if (everOpened) emit(null)
    everOpened = true
  }
  es.onmessage = (e: MessageEvent) => {
    const ev = parseEvent(e.data)
    if (!ev) return
    if (ev.seq > lastSeq) lastSeq = ev.seq
    emit(ev)
  }
  es.onerror = () => {
    // Replace the browser's own fixed-interval retry with the back-off.
    scheduleRetry()
  }
}

function onVisibility(): void {
  if (listeners.size === 0) return
  if (document.hidden) {
    closeSource()
    attempt = 0
    setState("paused")
  } else {
    open()
  }
}

function subscribe(l: Listener): () => void {
  listeners.add(l)
  if (!visibilityBound && typeof document !== "undefined") {
    document.addEventListener("visibilitychange", onVisibility)
    visibilityBound = true
  }
  if (listeners.size === 1) open()
  return () => {
    listeners.delete(l)
    if (listeners.size === 0) {
      closeSource()
      attempt = 0
      setState("idle")
      if (visibilityBound) {
        document.removeEventListener("visibilitychange", onVisibility)
        visibilityBound = false
      }
    }
  }
}

function subscribeState(fn: () => void): () => void {
  stateListeners.add(fn)
  return () => stateListeners.delete(fn)
}

/** The shared stream's state (re-renders when it changes). */
export function useStreamState(): StreamState {
  return useSyncExternalStore(
    subscribeState,
    () => state,
    () => "idle" as StreamState,
  )
}

/**
 * Subscribes to the stream while the component is mounted. onEvent gets
 * each event, or null after a reconnect or when the page is shown again.
 */
export function useEventStream(onEvent: (ev: StreamEvent | null) => void, enabled = true): StreamState {
  const handle = useEffectEvent(onEvent)
  useEffect(() => {
    if (!enabled) return
    return subscribe((ev) => handle(ev))
  }, [enabled])
  return useStreamState()
}

/**
 * Refreshes the SWR keys that start with one of the prefixes whenever the
 * stream reports something (debounced), and once after a reconnect.
 */
export function useStreamRefresh(prefixes: readonly string[], enabled = true): StreamState {
  const { mutate } = useSWRConfig()
  const refresh = useEffectEvent(() => {
    void mutate((key) => typeof key === "string" && prefixes.some((p) => key.startsWith(p)))
  })
  useEffect(() => {
    if (!enabled) return
    let timer: ReturnType<typeof setTimeout> | undefined
    const unsubscribe = subscribe(() => {
      if (timer) clearTimeout(timer)
      timer = setTimeout(() => refresh(), debounceMs)
    })
    return () => {
      if (timer) clearTimeout(timer)
      unsubscribe()
    }
  }, [enabled])
  return useStreamState()
}

/**
 * A polling interval that relaxes while the stream is open: the stream
 * brings the changes, a slow poll stays as a safety net. Without the
 * stream the given interval is used.
 */
export function useLiveInterval(baseMs: number): number {
  const s = useStreamState()
  if (baseMs <= 0) return baseMs
  return s === "open" ? Math.max(baseMs * 4, 20_000) : baseMs
}

/** Data the Control Center shows (refreshed on stream events). */
export const controlCenterStreamKeys = ["/api/overview", "/api/devices", "/api/app/status", "/api/invites", "/api/membership", "/api/history"] as const

/** Data the Devices page shows. */
export const devicesStreamKeys = ["/api/devices", "/api/app/status", "/api/app/rdesk", "/api/p02/"] as const
