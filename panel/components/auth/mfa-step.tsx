"use client"

import { useState } from "react"
import { KeyRound, Smartphone } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { getAssertion, postCoded, webAuthnError, webAuthnUsable } from "@/components/auth/strict-api"
import { errorMessage } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"

// Second sign-in step (#673 WebAuthn, #674 TOTP; ADR-0198, ADR-0199).
// The session is half open for two minutes; only these endpoints answer.
// The second-step endpoints check Origin and need no CSRF header.

interface MfaStepProps {
  methods: string[]
  onDone: () => void
  onRestart: () => void
}

export function MfaStep({ methods, onDone, onRestart }: MfaStepProps) {
  const { t } = useI18n()
  const keyAllowed = methods.includes("webauthn")
  const keyUsable = keyAllowed && webAuthnUsable()
  const codeAllowed = methods.includes("totp")
  const [mode, setMode] = useState<"key" | "code">(keyUsable ? "key" : "code")
  const [code, setCode] = useState("")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)

  async function useKey() {
    setBusy(true)
    setError("")
    try {
      const ch = await postCoded<{ challenge: string; rp_id: string; allow_credentials?: string[]; timeout_ms: number }>(
        "/api/auth/mfa/webauthn/begin",
        {},
        { csrf: false }
      )
      const assertion = await getAssertion(ch)
      await postCoded("/api/auth/mfa/webauthn/finish", assertion, { csrf: false })
      onDone()
    } catch (err) {
      setError(webAuthnError(err))
    } finally {
      setBusy(false)
    }
  }

  async function sendCode(e: React.FormEvent) {
    e.preventDefault()
    if (!/^\d{6}$/.test(code)) {
      setError(t("Altı haneli kodu girin."))
      return
    }
    setBusy(true)
    setError("")
    try {
      await postCoded("/api/auth/mfa/totp", { code }, { csrf: false })
      setCode("")
      onDone()
    } catch (err) {
      setCode("")
      if (err instanceof Error && "status" in err && err.status === 401) {
        setError(t("Kod yanlış veya süresi geçmiş."))
      } else {
        setError(err instanceof Error ? errorMessage(err) : t("Kod doğrulanamadı."))
      }
    } finally {
      setBusy(false)
    }
  }

  const noMethod = !keyUsable && !codeAllowed
  const [hostBefore, hostAfter = ""] = t(
    "Güvenlik anahtarı yalnızca ad ile açılan adreste çalışır. Paneli {host} adresiyle açıp yeniden giriş yapın."
  ).split("{host}")

  return (
    <section aria-labelledby="mfa-title" className="w-full max-w-md rounded-2xl border bg-card p-8 shadow-xl shadow-black/20 sm:p-10">
      <div className="mb-8 flex flex-col items-center gap-2 text-center">
        <h1 id="mfa-title" className="text-xl leading-tight font-semibold">
          {t("İkinci doğrulama")}
        </h1>
        <p className="text-sm text-muted-foreground text-pretty">
          {mode === "key" ? t("YubiKey'inize dokunun") : t("Kimlik doğrulama uygulamasındaki kodu girin")}
        </p>
      </div>

      {noMethod ? (
        <div className="flex flex-col gap-4 text-sm leading-relaxed text-muted-foreground">
          <p className="text-pretty">
            {hostBefore}
            <span className="font-mono text-foreground">localhost</span>
            {hostAfter}
          </p>
          <Button variant="outline" onClick={onRestart}>
            {t("Girişe dön")}
          </Button>
        </div>
      ) : mode === "key" ? (
        <div className="flex flex-col gap-4">
          <Button size="lg" className="h-11 text-base" onClick={useKey} disabled={busy} autoFocus>
            {busy ? <Spinner data-icon="inline-start" /> : <KeyRound data-icon="inline-start" />}
            {t("Güvenlik anahtarını kullan")}
          </Button>
          {error ? (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          ) : null}
          {codeAllowed ? (
            <Button variant="link" className="self-center" onClick={() => { setMode("code"); setError("") }}>
              {t("Anahtarım yanımda değil: kod kullan")}
            </Button>
          ) : null}
        </div>
      ) : (
        <form onSubmit={sendCode} noValidate className="flex flex-col gap-6">
          <FieldGroup>
            <Field data-invalid={error ? true : undefined}>
              <FieldLabel htmlFor="mfa-code">{t("Doğrulama kodu")}</FieldLabel>
              <Input
                id="mfa-code"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]*"
                maxLength={6}
                autoFocus
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                aria-invalid={error ? true : undefined}
                className="h-11 text-center font-mono text-lg tabular-nums tracking-[0.4em]"
              />
              <FieldError>{error}</FieldError>
              <FieldDescription>{t("Kod 30 saniyede bir değişir. İki dakika içinde bitirmezseniz parola yeniden sorulur.")}</FieldDescription>
            </Field>
          </FieldGroup>
          <Button type="submit" size="lg" className="h-11 text-base" disabled={busy}>
            {busy ? <Spinner data-icon="inline-start" /> : <Smartphone data-icon="inline-start" />}
            {t("Doğrula")}
          </Button>
          {keyUsable ? (
            <Button type="button" variant="link" className="self-center" onClick={() => { setMode("key"); setError("") }}>
              {t("Güvenlik anahtarı kullan")}
            </Button>
          ) : null}
        </form>
      )}
    </section>
  )
}
