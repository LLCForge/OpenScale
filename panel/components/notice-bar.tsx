"use client"

import { useSyncExternalStore } from "react"
import { X } from "lucide-react"

import { Button } from "@/components/ui/button"
import { useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

// Calm one-line notice for the top of the page. A dismissed notice stays
// hidden for this browser tab (sessionStorage); when storage is blocked it
// stays hidden until the page reloads.

const listeners = new Set<() => void>()
const memory = new Set<string>()

function storageKey(id: string): string {
  return `openscale.notice.${id}`
}

function isDismissed(id: string): boolean {
  if (memory.has(id)) return true
  try {
    return window.sessionStorage.getItem(storageKey(id)) === "1"
  } catch {
    return false
  }
}

function dismiss(id: string) {
  memory.add(id)
  try {
    window.sessionStorage.setItem(storageKey(id), "1")
  } catch {
    // Storage blocked: the in-memory set keeps it hidden until reload.
  }
  for (const l of listeners) l()
}

function subscribe(onChange: () => void) {
  listeners.add(onChange)
  return () => {
    listeners.delete(onChange)
  }
}

interface NoticeBarProps {
  /** Stable id for remembering the dismissal; omit for a notice that cannot be closed. */
  id?: string
  icon?: React.ReactNode
  children: React.ReactNode
  /** A link or small button at the end of the line. */
  action?: React.ReactNode
  className?: string
}

export function NoticeBar({ id, icon, children, action, className }: NoticeBarProps) {
  const { t } = useI18n()
  const hidden = useSyncExternalStore(
    subscribe,
    () => (id ? isDismissed(id) : false),
    () => false
  )
  if (hidden) return null
  return (
    <div
      role="status"
      className={cn(
        "flex items-center gap-3 rounded-lg border bg-muted/40 py-1.5 pr-1.5 pl-3 text-sm text-muted-foreground [&>svg]:size-4 [&>svg]:shrink-0",
        className
      )}
    >
      {icon}
      <div className="min-w-0 flex-1 text-pretty">{children}</div>
      {action ? <div className="shrink-0">{action}</div> : null}
      {id ? (
        <Button variant="ghost" size="icon-sm" aria-label={t("Bildirimi kapat")} onClick={() => dismiss(id)}>
          <X />
        </Button>
      ) : null}
    </div>
  )
}
