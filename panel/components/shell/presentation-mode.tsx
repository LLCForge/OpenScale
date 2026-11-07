"use client"

// Presentation mode (#532, P08): one switch blurs IP addresses,
// fingerprints, invite codes and endpoints so the panel can be shown on a
// shared screen or captured in a screenshot without leaking them. The
// blur is pure CSS (app/globals.css, :root[data-presentation="on"]) over
// monospace text, code, kbd, pre and anything marked data-sensitive; it is
// not lifted on hover, so a stray mouse pointer reveals nothing. Copy
// buttons keep working. The choice is a per-browser convenience kept in
// localStorage, so a reload during a screen share stays blurred; nothing is
// sent to the server.

import { useEffect, useSyncExternalStore } from "react"
import { Eye, EyeOff } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

const storageKey = "openscale.presentation"
const listeners = new Set<() => void>()
// Used when the browser refuses storage (private mode, blocked site data).
let memory: boolean | null = null

function readMode(): boolean {
  if (memory !== null) return memory
  try {
    return window.localStorage.getItem(storageKey) === "on"
  } catch {
    return false
  }
}

function subscribe(onChange: () => void): () => void {
  listeners.add(onChange)
  const onStorage = (e: StorageEvent) => {
    if (e.key === storageKey) onChange()
  }
  window.addEventListener("storage", onStorage)
  return () => {
    listeners.delete(onChange)
    window.removeEventListener("storage", onStorage)
  }
}

export function setPresentationMode(on: boolean): void {
  memory = on
  try {
    window.localStorage.setItem(storageKey, on ? "on" : "off")
  } catch {
    // Storage blocked: the choice lasts until the page is closed.
  }
  for (const l of listeners) l()
}

export function usePresentationMode(): boolean {
  return useSyncExternalStore(subscribe, readMode, () => false)
}

/** Keeps <html data-presentation> in step and handles Alt+Shift+P. */
function usePresentationSync(on: boolean): void {
  useEffect(() => {
    document.documentElement.dataset.presentation = on ? "on" : "off"
  }, [on])
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.altKey && e.shiftKey && !e.ctrlKey && !e.metaKey && e.code === "KeyP") {
        e.preventDefault()
        setPresentationMode(!readMode())
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])
}

/** Header switch for presentation mode. */
export function PresentationToggle() {
  const { t } = useI18n()
  const on = usePresentationMode()
  usePresentationSync(on)
  const label = on ? t("Sunum kipini kapat") : t("Sunum kipini aç")
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Button
            variant={on ? "secondary" : "ghost"}
            size="sm"
            aria-pressed={on}
            aria-label={label}
            className={cn("gap-1.5 pointer-coarse:h-11 pointer-coarse:min-w-11", on ? "text-foreground" : "text-muted-foreground")}
            onClick={() => setPresentationMode(!on)}
          />
        }
      >
        {on ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
        <span className={cn(on ? "inline" : "hidden sm:inline")}>{on ? t("Sunum kipi açık") : t("Sunum")}</span>
      </TooltipTrigger>
      <TooltipContent side="bottom">
        {t("IP'leri, parmak izlerini, davet kodlarını ve uç noktaları bulanıklaştırır (Alt+Shift+P)")}
      </TooltipContent>
    </Tooltip>
  )
}
