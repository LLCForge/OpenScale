"use client"

import { useState } from "react"
import useSWR from "swr"
import { useRouter } from "next/navigation"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { Eye, EyeOff, LockKeyhole } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput } from "@/components/ui/input-group"
import { Spinner } from "@/components/ui/spinner"
import { MfaStep } from "@/components/auth/mfa-step"
import { ApiError, errorMessage, fetcher } from "@/lib/api"
import { msg, useI18n } from "@/lib/i18n/i18n"

const schema = z.object({
  passphrase: z.string().min(1, msg("Parola gerekli")).max(1024, msg("Parola çok uzun")),
})

type LoginValues = z.infer<typeof schema>

interface SignInResult {
  mfa_required?: boolean
  methods?: string[]
}

async function signIn(passphrase: string): Promise<SignInResult> {
  const res = await fetch("/api/login", {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ passphrase }),
  })
  if (!res.ok) {
    let message: string = msg("Giriş yapılamadı.")
    try {
      const data: unknown = await res.json()
      if (data && typeof data === "object" && "error" in data && typeof data.error === "string") message = data.error
    } catch {
      // Keep the generic message.
    }
    throw new ApiError(message, res.status)
  }
  try {
    const data: unknown = await res.json()
    if (data && typeof data === "object" && "mfa_required" in data && data.mfa_required === true) {
      const methods = "methods" in data && Array.isArray(data.methods) ? data.methods.filter((m): m is string => typeof m === "string") : []
      return { mfa_required: true, methods }
    }
  } catch {
    // Older servers answer without a body.
  }
  return {}
}

interface AppInfo {
  app: boolean
  hasNetwork: boolean
}

export function LoginForm() {
  const { t } = useI18n()
  const { data: info } = useSWR<AppInfo>("/api/app/info", fetcher, { revalidateOnFocus: false })
  if (info?.app && !info.hasNetwork) {
    return (
      <section aria-labelledby="login-title" className="w-full max-w-md rounded-2xl border bg-card p-8 text-center shadow-xl shadow-black/20 sm:p-10">
        <h1 id="login-title" className="mb-2 text-xl font-semibold tracking-tight">
          {t("OpenScale'i uygulamadan aç")}
        </h1>
        <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
          {t(
            "Bu bilgisayarda parolayla girilecek bir ağ yok. Görev çubuğundaki OpenScale simgesine tıkla veya programa çift tıkla; panel kendiliğinden açılır."
          )}
        </p>
      </section>
    )
  }
  return <PassphraseForm />
}

interface LoginInfo {
  remote: boolean
}

const loginCopy = {
  unknown: {
    title: msg("Giriş yap"),
    lead: msg("Parolanı gir"),
    placeholder: msg("Parola"),
    help: msg("5 yanlış denemeden sonra giriş 5 dakika kilitlenir."),
  },
  remote: {
    title: msg("Uzak panele giriş"),
    lead: msg("Uzak erişim parolanı gir"),
    placeholder: msg("Uzak erişim parolası"),
    help: msg("Yönetici bilgisayarda 'openscale panel-remote password' ile belirlenen parola. Kök anahtar parolasını burada yazma. Uzak panel yalnızca okunur; 5 yanlış denemeden sonra giriş 5 dakika kilitlenir."),
  },
  local: {
    title: msg("Giriş yap"),
    lead: msg("Kök anahtar parolanı gir"),
    placeholder: msg("Kök anahtar parolası"),
    help: msg("'openscale network init' sırasında belirlediğin parola. 5 yanlış denemeden sonra giriş 5 dakika kilitlenir."),
  },
} as const

function PassphraseForm() {
  const { t } = useI18n()
  // ADR-0107: from another device the panel asks for the remote access
  // password; the root key passphrase is never typed there.
  const { data: loginInfo, error: loginInfoError } = useSWR<LoginInfo>("/api/login-info", fetcher, { revalidateOnFocus: false })
  // Until the answer arrives no parola is named: a remote screen must never
  // ask for the root key passphrase, not even for a moment.
  const kind: "unknown" | "remote" | "local" = loginInfo === undefined ? "unknown" : loginInfo.remote ? "remote" : "local"
  const copy = loginCopy[kind]
  const router = useRouter()
  const [visible, setVisible] = useState(false)
  const [mfa, setMfa] = useState<string[] | null>(null)
  const form = useForm<LoginValues>({ resolver: zodResolver(schema), defaultValues: { passphrase: "" } })
  const { errors, isSubmitting } = form.formState

  async function onSubmit(values: LoginValues) {
    try {
      const result = await signIn(values.passphrase)
      form.reset()
      if (result.mfa_required) {
        setMfa(result.methods ?? [])
        return
      }
      router.replace("/")
    } catch (err) {
      form.setValue("passphrase", "")
      form.setError("passphrase", { message: errorMessage(err) })
    }
  }

  if (mfa) {
    return <MfaStep methods={mfa} onDone={() => router.replace("/")} onRestart={() => setMfa(null)} />
  }

  return (
    <section aria-labelledby="login-title" className="w-full max-w-md rounded-2xl border bg-card p-8 shadow-xl shadow-black/20 sm:p-10">
      <div className="mb-8 flex flex-col items-center gap-2 text-center">
        <h1 id="login-title" className="text-xl leading-tight font-semibold">
          {t(copy.title)}
        </h1>
        <p className="text-sm text-muted-foreground">{t(copy.lead)}</p>
      </div>
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-6">
        <FieldGroup>
          <Field data-invalid={errors.passphrase ? true : undefined}>
            <FieldLabel htmlFor="login-passphrase">{t("Parola")}</FieldLabel>
            <InputGroup className="h-11">
              <InputGroupAddon>
                <LockKeyhole />
              </InputGroupAddon>
              <InputGroupInput
                id="login-passphrase"
                type={visible ? "text" : "password"}
                autoComplete="current-password"
                autoFocus
                placeholder={t(copy.placeholder)}
                aria-invalid={errors.passphrase ? true : undefined}
                {...form.register("passphrase")}
              />
              <InputGroupAddon align="inline-end">
                <InputGroupButton
                  size="icon-xs"
                  onClick={() => setVisible((v) => !v)}
                  aria-label={visible ? t("Parolayı gizle") : t("Parolayı göster")}
                >
                  {visible ? <EyeOff /> : <Eye />}
                </InputGroupButton>
              </InputGroupAddon>
            </InputGroup>
            <FieldError errors={[errors.passphrase]} />
            <FieldDescription>{t(copy.help)}</FieldDescription>
          </Field>
        </FieldGroup>
        <Button type="submit" size="lg" className="h-11 text-base" disabled={isSubmitting || (kind === "unknown" && !loginInfoError)}>
          {isSubmitting ? <Spinner data-icon="inline-start" /> : null}
          {t("Giriş yap")}
        </Button>
      </form>
    </section>
  )
}
