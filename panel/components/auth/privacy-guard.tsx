"use client"

import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react"
import { createPortal } from "react-dom"
import Link from "next/link"
import useSWR, { useSWRConfig } from "swr"
import { Eye, Lock, MonitorUp, ScreenShare, ShieldCheck } from "lucide-react"

import "./privacy.css"

import { requestReauth, ReauthHost, useAuthStatus } from "@/components/auth/reauth"
import { CodedError, optionalGet, postCoded } from "@/components/auth/strict-api"
import { Button } from "@/components/ui/button"
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { errorMessage } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

// Panel-wide privacy surfaces, mounted once in the panel layout:
// the idle lock (#661), the screen sharing guard (#689), the admin mode
// strip (#678), the remote desktop presence strip and the
// re-authentication dialog (#676).

export interface LockStatus {
  locked: boolean
  minutes: number
  idle_seconds: number
  remaining_seconds: number
  method: "passphrase" | "app" | "none"
}

export interface ScreenShareStatus {
  level: "none" | "possible" | "active"
  apps: string[] | null
  blur: boolean
  browser_note: string
  supported: boolean
  checked_at: string
}

// --- 423 detection -------------------------------------------------------
// Any API answer 423 locks the page at once, whichever component asked.

let lockedBy423 = false
const lockListeners = new Set<() => void>()

function setLocked423(v: boolean) {
  if (lockedBy423 === v) return
  lockedBy423 = v
  for (const l of lockListeners) l()
}

function subscribeLock(l: () => void) {
  lockListeners.add(l)
  return () => {
    lockListeners.delete(l)
  }
}

let fetchWrapped = false

function wrapFetch() {
  if (fetchWrapped || typeof window === "undefined") return
  fetchWrapped = true
  const original = window.fetch.bind(window)
  window.fetch = async (...args: Parameters<typeof fetch>) => {
    const res = await original(...args)
    if (res.status === 423) setLocked423(true)
    return res
  }
}

// --- screen share preference (local, per browser) -----------------------

const sharePrefKey = "openscale.privacy.hideOnShare"
const prefListeners = new Set<() => void>()

export function hideOnShareEnabled(): boolean {
  try {
    return window.localStorage.getItem(sharePrefKey) !== "0"
  } catch {
    return true
  }
}

export function setHideOnShare(on: boolean) {
  try {
    window.localStorage.setItem(sharePrefKey, on ? "1" : "0")
  } catch {
    // Storage blocked: the default (on) stays.
  }
  for (const l of prefListeners) l()
}

export function useHideOnShare(): boolean {
  return useSyncExternalStore(
    (l) => {
      prefListeners.add(l)
      return () => {
        prefListeners.delete(l)
      }
    },
    hideOnShareEnabled,
    () => true
  )
}

const activityEvery = 30_000

/** Lock and re-authentication dialogs; mounted around the shell so every page has them. */
export function PrivacyOverlays() {
  useEffect(() => {
    wrapFetch()
  }, [])
  return (
    <>
      <IdleLock />
      <ReauthHost />
    </>
  )
}

/** Calm strips at the top of the page content. */
export function PrivacyStrips() {
  return (
    <>
      <AdminModeStrip />
      <RemotePresenceStrip />
      <ScreenShareStrip />
    </>
  )
}

function IdleLock() {
  const { mutate: mutateAll } = useSWRConfig()
  const { data, mutate } = useSWR<LockStatus | null>("/api/app/privacy/lock", optionalGet, { refreshInterval: 10_000 })
  const forced = useSyncExternalStore(subscribeLock, () => lockedBy423, () => false)
  const locked = forced || data?.locked === true
  const lastSent = useRef(0)
  const enabled = (data?.minutes ?? 0) > 0

  // Real input counts as activity; background polling does not.
  useEffect(() => {
    if (!enabled || locked) return
    const onInput = () => {
      const now = Date.now()
      if (now - lastSent.current < activityEvery) return
      lastSent.current = now
      postCoded("/api/app/privacy/activity", {}).catch(() => undefined)
    }
    const events = ["pointerdown", "keydown", "touchstart", "wheel"] as const
    for (const e of events) window.addEventListener(e, onInput, { passive: true })
    return () => {
      for (const e of events) window.removeEventListener(e, onInput)
    }
  }, [enabled, locked])

  const onUnlocked = useCallback(async () => {
    setLocked423(false)
    await mutate()
    // Everything that failed with 423 is fetched again.
    await mutateAll(() => true)
  }, [mutate, mutateAll])

  if (!locked) return null
  return <LockOverlay method={data?.method ?? "passphrase"} onUnlocked={onUnlocked} />
}

function LockOverlay({ method, onUnlocked }: { method: LockStatus["method"]; onUnlocked: () => void }) {
  const { t } = useI18n()
  const [secret, setSecret] = useState("")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const rootRef = useRef<HTMLDivElement | null>(null)

  // The page behind the dialog is hidden from assistive technology and input.
  useEffect(() => {
    const own = rootRef.current
    const others = Array.from(document.body.children).filter((c): c is HTMLElement => c !== own && c instanceof HTMLElement)
    for (const o of others) {
      o.setAttribute("aria-hidden", "true")
      o.inert = true
    }
    return () => {
      for (const o of others) {
        o.removeAttribute("aria-hidden")
        o.inert = false
      }
    }
  }, [])

  async function unlock(e: React.FormEvent) {
    e.preventDefault()
    if (!secret) {
      setError(t("Parola gerekli."))
      return
    }
    setBusy(true)
    setError("")
    try {
      await postCoded("/api/app/privacy/unlock", { secret })
      setSecret("")
      onUnlocked()
    } catch (err) {
      setSecret("")
      if (err instanceof CodedError && err.status === 429) setError(errorMessage(err))
      else setError(t("Kilit açılamadı. Parolayı kontrol edin."))
    } finally {
      setBusy(false)
    }
  }

  return createPortal(
    <div ref={rootRef} className="panel-lock-backdrop fixed inset-0 z-[100] flex items-center justify-center bg-background/60 p-4">
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby="panel-lock-title"
        aria-describedby="panel-lock-desc"
        className="w-full max-w-sm rounded-2xl border bg-card p-8 shadow-xl shadow-black/20"
      >
        <div className="mb-6 flex flex-col items-center gap-2 text-center">
          <Lock className="size-5 text-muted-foreground" aria-hidden="true" />
          <h2 id="panel-lock-title" className="text-lg font-semibold">
            {t("Panel kilitlendi")}
          </h2>
          <p id="panel-lock-desc" className="text-sm leading-relaxed text-muted-foreground text-pretty">
            {method === "app"
              ? t("Devam etmek için bilgisayar parolanızı girin veya YubiKey'inize dokunun.")
              : t("Devam etmek için ağ parolasını girin.")}
          </p>
        </div>
        <form onSubmit={unlock} noValidate className="flex flex-col gap-5">
          <FieldGroup>
            <Field data-invalid={error ? true : undefined}>
              <FieldLabel htmlFor="panel-lock-secret">{t("Parola")}</FieldLabel>
              <Input
                id="panel-lock-secret"
                data-secret-exempt=""
                type="password"
                autoComplete="current-password"
                autoFocus
                maxLength={1024}
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                aria-invalid={error ? true : undefined}
              />
              <FieldError>{error}</FieldError>
            </Field>
          </FieldGroup>
          <Button type="submit" disabled={busy}>
            {busy ? <Spinner data-icon="inline-start" /> : null}
            {t("Kilidi aç")}
          </Button>
        </form>
      </section>
    </div>,
    document.body
  )
}

/** "Şimdi kilitle" control for the top bar or a settings row. */
export function LockNowButton({ className }: { className?: string }) {
  const { t } = useI18n()
  const { data } = useSWR<LockStatus | null>("/api/app/privacy/lock", optionalGet)
  const [busy, setBusy] = useState(false)
  if (!data || data.method === "none") return null
  return (
    <Button
      variant="outline"
      size="sm"
      className={className}
      disabled={busy}
      onClick={async () => {
        setBusy(true)
        try {
          await postCoded("/api/app/privacy/lock", {})
          setLocked423(true)
        } catch {
          // The status poll shows the real state.
        } finally {
          setBusy(false)
        }
      }}
    >
      <Lock data-icon="inline-start" />
      {t("Şimdi kilitle")}
    </Button>
  )
}

function ScreenShareStrip() {
  const { t, ts } = useI18n()
  const pref = useHideOnShare()
  const { data } = useSWR<ScreenShareStatus | null>("/api/app/privacy/screen-share", optionalGet, { refreshInterval: 3_000 })
  const [revealed, setRevealed] = useState(false)
  const hide = pref && data?.blur === true && data.level !== "none" && !revealed

  useEffect(() => {
    const root = document.documentElement
    if (hide) root.setAttribute("data-secrets-hidden", "")
    else root.removeAttribute("data-secrets-hidden")
    return () => root.removeAttribute("data-secrets-hidden")
  }, [hide])

  useEffect(() => {
    if (!revealed) return
    const t = window.setTimeout(() => setRevealed(false), 10_000)
    return () => window.clearTimeout(t)
  }, [revealed])

  if (!data || data.level === "none" || !pref) return null
  const apps = (data.apps ?? []).join(", ")
  const active = data.level === "active"
  return (
    <div
      role="status"
      className={cn(
        "flex flex-col gap-1 rounded-lg border px-3 py-2 text-sm",
        active ? "border-warning/40 bg-warning/10" : "bg-muted/40"
      )}
    >
      <div className="flex items-center gap-3">
        {active ? <ScreenShare className="size-4 shrink-0" aria-hidden="true" /> : <MonitorUp className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />}
        <p className="min-w-0 flex-1 text-pretty">
          {active
            ? t("Ekranınız paylaşılıyor veya kaydediliyor olabilir ({apps}). Sırlar gizlendi.", { apps })
            : t("Ekranı paylaşabilecek bir uygulama açık ({apps}). Sırlar gizlendi.", { apps })}
        </p>
        <Button variant="ghost" size="sm" onClick={() => setRevealed(true)} disabled={revealed}>
          <Eye data-icon="inline-start" />
          {t("10 sn göster")}
        </Button>
      </div>
      {data.browser_note ? <p className="pl-7 text-xs text-muted-foreground text-pretty">{ts(data.browser_note)}</p> : null}
    </div>
  )
}

function AdminModeStrip() {
  const { t } = useI18n()
  const { data } = useAuthStatus()
  if (!data || !data.signed_in || !data.admin_mode) return null
  if (data.admin_active) {
    const minutes = Math.max(1, Math.ceil(data.admin_left_sec / 60))
    return (
      <div role="status" className="flex items-center gap-2 self-end rounded-md bg-secondary px-2.5 py-1 text-xs text-muted-foreground">
        <ShieldCheck className="size-3.5" aria-hidden="true" />
        <span className="tabular-nums">{t("Yönetici kipi: {minutes} dk", { minutes })}</span>
      </div>
    )
  }
  return (
    <div role="status" className="flex flex-col gap-2 rounded-lg border bg-muted/40 px-3 py-2 text-sm sm:flex-row sm:items-center">
      <p className="min-w-0 flex-1 text-pretty">{t("Yönetici kipi kapandı; panel salt okunur.")}</p>
      <Button variant="outline" size="sm" className="w-fit" onClick={() => requestReauth("admin")}>
        {t("Yeniden doğrula")}
      </Button>
    </div>
  )
}

interface RDeskPresence {
  sessions: { id: string; peer: string; mode: string }[] | null
}

async function quietGet<T>(path: string): Promise<T | null> {
  const res = await fetch(path, { credentials: "same-origin", cache: "no-store" })
  if (!res.ok) return null
  return (await res.json()) as T
}

/** Shows that another device is on this screen right now. */
function RemotePresenceStrip() {
  const { t } = useI18n()
  const { data } = useSWR<RDeskPresence | null>("/api/app/rdesk", quietGet, { refreshInterval: 5_000 })
  const sessions = data?.sessions ?? []
  if (sessions.length === 0) return null
  const peers = Array.from(new Set(sessions.map((s) => s.peer)))
  const control = sessions.some((s) => s.mode === "control")
  const [before, after = ""] = (
    control
      ? t("Bu bilgisayar uzaktan yönetiliyor: {peers}. Hemen kesmek için Ctrl+Alt+Shift+K.")
      : t("Bu bilgisayarın ekranı izleniyor: {peers}. Hemen kesmek için Ctrl+Alt+Shift+K.")
  ).split("{peers}")
  return (
    <div role="status" className="flex flex-col gap-2 rounded-lg border border-warning/40 bg-warning/10 px-3 py-2 text-sm sm:flex-row sm:items-center">
      <MonitorUp className="hidden size-4 shrink-0 sm:block" aria-hidden="true" />
      <p className="min-w-0 flex-1 text-pretty">
        {before}
        <span className="font-medium">{peers.join(", ")}</span>
        {after}
      </p>
      <Button
        variant="outline"
        size="sm"
        className="w-fit"
        nativeButton={false}
        render={<Link href={`/devices/detail?name=${encodeURIComponent(peers[0] ?? "")}#uzak-masaustu`} />}
      >
        {t("Oturumu gör")}
      </Button>
    </div>
  )
}
