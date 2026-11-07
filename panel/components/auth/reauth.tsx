"use client"

import { useState, useSyncExternalStore } from "react"
import useSWR from "swr"
import { KeyRound, ShieldAlert } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { errorMessage, fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import { CodedError, getAssertion, postCoded, webAuthnError, webAuthnUsable } from "@/components/auth/strict-api"

// Re-authentication for critical actions (#676) and admin mode (#678,
// ADR-0202). A request answered 403 "reauth_required" or
// "admin_mode_required" opens one dialog; after a fresh proof the same
// request is sent once more. The dialog lives once in the panel layout.

export interface AuthStatus {
  signed_in: boolean
  pending: boolean
  methods?: string[]
  remote: boolean
  webauthn: { id: string; name: string; created_at: string; last_used?: string }[] | null
  totp: boolean
  totp_remote: boolean
  reauth_critical: boolean
  reauth_valid_sec: number
  admin_mode: boolean
  admin_active: boolean
  admin_left_sec: number
  admin_token: boolean
  local_mfa: boolean
  rp_id: string
}

/** Panel sign-in state; the endpoint answers before and after sign-in. */
export function useAuthStatus() {
  return useSWR<AuthStatus>("/api/auth/status", fetcher, { refreshInterval: 15_000 })
}

type Waiter = (ok: boolean) => void

let waiters: Waiter[] = []
let openReason: "reauth" | "admin" | null = null
const listeners = new Set<() => void>()

function emit() {
  for (const l of listeners) l()
}

function subscribe(l: () => void) {
  listeners.add(l)
  return () => {
    listeners.delete(l)
  }
}

/** Opens the dialog; resolves true after a successful proof. */
export function requestReauth(reason: "reauth" | "admin" = "reauth"): Promise<boolean> {
  return new Promise((resolve) => {
    waiters.push(resolve)
    if (openReason === null) {
      openReason = reason
      emit()
    }
  })
}

function finish(ok: boolean) {
  const pending = waiters
  waiters = []
  openReason = null
  emit()
  for (const w of pending) w(ok)
}

export function needsReauth(err: unknown): "reauth" | "admin" | null {
  if (err instanceof CodedError && err.status === 403) {
    if (err.code === "reauth_required") return "reauth"
    if (err.code === "admin_mode_required") return "admin"
  }
  return null
}

/** Runs fn; on a re-authentication answer asks for proof and runs it once more. */
export async function withReauth<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (err) {
    const reason = needsReauth(err)
    if (!reason) throw err
    const ok = await requestReauth(reason)
    if (!ok) throw err
    return fn()
  }
}

interface ReauthOK {
  ok: boolean
  valid_sec: number
  admin_sec: number
}

export function ReauthHost() {
  const reason = useSyncExternalStore(subscribe, () => openReason, () => null)
  return (
    <Dialog open={reason !== null} onOpenChange={(open) => (open ? undefined : finish(false))}>
      <DialogContent className="sm:max-w-md">{reason !== null ? <ReauthForm reason={reason} /> : null}</DialogContent>
    </Dialog>
  )
}

/** The dialog body; unmounted on close, so typed secrets do not stay in state. */
function ReauthForm({ reason }: { reason: "reauth" | "admin" }) {
  const { t } = useI18n()
  const { data: status, mutate } = useAuthStatus()
  const [passphrase, setPassphrase] = useState("")
  const [code, setCode] = useState("")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState<"pass" | "key" | null>(null)

  const remote = status?.remote === true
  const keys = status?.webauthn ?? []
  const canKey = keys.length > 0 && webAuthnUsable()
  const showCode = status?.totp === true && (!remote || status.totp_remote)

  async function withPassphrase(e: React.FormEvent) {
    e.preventDefault()
    if (!passphrase) {
      setError(t("Parola gerekli."))
      return
    }
    setBusy("pass")
    setError("")
    try {
      const body: { passphrase: string; code?: string } = { passphrase }
      if (showCode && code.trim()) body.code = code.trim()
      await postCoded<ReauthOK>("/api/auth/reauth", body)
      setPassphrase("")
      setCode("")
      await mutate()
      finish(true)
    } catch (err) {
      setPassphrase("")
      setError(err instanceof Error ? errorMessage(err) : t("Doğrulama yapılamadı."))
    } finally {
      setBusy(null)
    }
  }

  async function withKey() {
    setBusy("key")
    setError("")
    try {
      const ch = await postCoded<{ challenge: string; rp_id: string; allow_credentials?: string[]; timeout_ms: number }>(
        "/api/auth/reauth/webauthn/begin",
        {}
      )
      const assertion = await getAssertion(ch)
      await postCoded<ReauthOK>("/api/auth/reauth/webauthn/finish", assertion)
      await mutate()
      finish(true)
    } catch (err) {
      setError(webAuthnError(err))
    } finally {
      setBusy(null)
    }
  }

  return (
    <>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldAlert className="size-4 text-muted-foreground" aria-hidden="true" />
            {reason === "admin" ? t("Yönetici kipini yeniden aç") : t("Kimliğinizi yeniden doğrulayın")}
          </DialogTitle>
          <DialogDescription>
            {reason === "admin"
              ? t("Yönetici kipi kapandı; panel salt okunur. Değişikliğe devam etmek için kimliğinizi doğrulayın.")
              : t("Bu işlem için kimliğinizi yeniden doğrulayın. Doğrulama iki dakika geçerlidir ve tek işlem içindir.")}
          </DialogDescription>
        </DialogHeader>
        <form id="reauth-form" onSubmit={withPassphrase} noValidate>
          <FieldGroup>
            <Field data-invalid={error ? true : undefined}>
              <FieldLabel htmlFor="reauth-passphrase">{remote ? t("Uzak erişim parolası") : t("Kök anahtar parolası")}</FieldLabel>
              <Input
                id="reauth-passphrase"
                type="password"
                autoComplete="current-password"
                autoFocus
                value={passphrase}
                maxLength={1024}
                onChange={(e) => setPassphrase(e.target.value)}
                aria-invalid={error ? true : undefined}
              />
              {showCode ? null : <FieldError>{error}</FieldError>}
            </Field>
            {showCode ? (
              <Field data-invalid={error ? true : undefined}>
                <FieldLabel htmlFor="reauth-code">{t("Doğrulama kodu")}</FieldLabel>
                <Input
                  id="reauth-code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]*"
                  maxLength={6}
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                  className="font-mono tabular-nums tracking-widest"
                />
                <FieldDescription>{t("Kimlik doğrulama uygulaması açıksa kodu da girin.")}</FieldDescription>
                <FieldError>{error}</FieldError>
              </Field>
            ) : null}
          </FieldGroup>
        </form>
        <DialogFooter className="gap-2 sm:justify-between">
          {canKey ? (
            <Button type="button" variant="outline" onClick={withKey} disabled={busy !== null}>
              {busy === "key" ? <Spinner data-icon="inline-start" /> : <KeyRound data-icon="inline-start" />}
              {t("Güvenlik anahtarıyla")}
            </Button>
          ) : (
            <span />
          )}
          <Button type="submit" form="reauth-form" disabled={busy !== null}>
            {busy === "pass" ? <Spinner data-icon="inline-start" /> : null}
            {t("Doğrula")}
          </Button>
        </DialogFooter>
    </>
  )
}
