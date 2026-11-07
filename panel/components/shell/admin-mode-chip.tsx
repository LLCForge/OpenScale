"use client"

import { useEffect, useState } from "react"
import { usePathname } from "next/navigation"
import useSWR from "swr"
import { KeyRound, Lock } from "lucide-react"

import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { AuthStatus, DiscreetInfo } from "@/lib/pa-types"
import { cn } from "@/lib/utils"

function mmss(sec: number): string {
  const s = Math.max(0, Math.floor(sec))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`
}

/**
 * Top bar chip for the administrator mode (ADR-0197, ADR-0199): shown only
 * when the mode is on, with the time left. The server decides; the chip
 * only counts down between polls.
 */
export function AdminModeChip() {
  const { t } = useI18n()
  const { data } = useSWR<AuthStatus>("/api/auth/status", fetcher, { refreshInterval: 30_000, shouldRetryOnError: false })
  const [left, setLeft] = useState(0)
  useEffect(() => {
    if (!data?.admin_active) return
    const end = Date.now() + data.admin_left_sec * 1000
    const tick = () => setLeft(Math.max(0, Math.round((end - Date.now()) / 1000)))
    tick()
    const t = setInterval(tick, 1000)
    return () => clearInterval(t)
  }, [data?.admin_active, data?.admin_left_sec])

  if (!data?.signed_in || !data.admin_mode) return null
  const active = data.admin_active && left > 0
  const text = active
    ? data.admin_token
      ? t("Yönetici kipi açık (donanım anahtarı takılı), {left} kaldı", { left: mmss(left) })
      : t("Yönetici kipi açık, {left} kaldı", { left: mmss(left) })
    : data.admin_token
      ? t("Yönetici anahtarı takılı değil (salt okunur)")
      : t("Yönetici kipi kapalı (salt okunur)")
  return (
    <span
      role="status"
      title={text}
      className={cn(
        "hidden h-7 items-center gap-1.5 rounded-full px-2.5 text-xs font-medium sm:inline-flex [&>svg]:size-3.5",
        active ? "bg-success/15 text-success" : "bg-secondary text-muted-foreground"
      )}
    >
      {active ? <KeyRound aria-hidden="true" /> : <Lock aria-hidden="true" />}
      <span className="max-w-56 truncate tabular-nums">{active ? t("Yönetici kipi · {left}", { left: mmss(left) }) : t("Salt okunur")}</span>
      <span className="sr-only">{text}</span>
    </span>
  )
}

/**
 * Discreet name mode (ADR-0196): the tab title shows the neutral name.
 * Runs after each navigation because every page sets its own title.
 */
export function DiscreetTitle() {
  const pathname = usePathname()
  const { t } = useI18n()
  const connection = t("bağlantı")
  const { data } = useSWR<DiscreetInfo>("/api/desktop/discreet", fetcher, { revalidateOnFocus: false, shouldRetryOnError: false })
  useEffect(() => {
    if (!data?.enabled) return
    const name = data.name
    const apply = () => {
      const next = document.title.replace(/OpenScale/g, name).replace(/\bVPN\b/g, connection)
      if (next !== document.title) document.title = next
    }
    apply()
    const timer = setTimeout(apply, 50)
    return () => clearTimeout(timer)
  }, [data?.enabled, data?.name, pathname, connection])
  return null
}
