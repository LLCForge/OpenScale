"use client"

import { useEffect, useSyncExternalStore } from "react"

// The page address fragment (#kok-anahtar) as React state. Links from other
// pages ("Düzelt" in the Control Center) carry the section to open; tab
// strips write the open tab back without scrolling or adding history.

const listeners = new Set<() => void>()

function notify() {
  for (const l of listeners) l()
}

function subscribe(onChange: () => void) {
  listeners.add(onChange)
  window.addEventListener("hashchange", onChange)
  window.addEventListener("popstate", onChange)
  return () => {
    listeners.delete(onChange)
    window.removeEventListener("hashchange", onChange)
    window.removeEventListener("popstate", onChange)
  }
}

function read(): string {
  return decodeURIComponent(window.location.hash.replace(/^#/, ""))
}

/** The current fragment without "#", "" on the server and when there is none. */
export function useHash(): string {
  return useSyncExternalStore(subscribe, read, () => "")
}

/** Replaces the fragment without scrolling or a new history entry. */
export function setHash(hash: string) {
  const url = `${window.location.pathname}${window.location.search}${hash ? `#${encodeURIComponent(hash)}` : ""}`
  window.history.replaceState(window.history.state, "", url)
  notify()
}

/**
 * Scrolls the element with the fragment's id into view once it exists
 * (sections render after their data arrives). `ready` re-runs the check.
 */
export function useScrollToHash(hash: string, ready: boolean) {
  useEffect(() => {
    if (!hash || !ready) return
    const el = document.getElementById(hash)
    if (!el) return
    el.scrollIntoView({ block: "start" })
  }, [hash, ready])
}
