"use client"

import { useId, useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"
import { Download, FileCheck, ShieldCheck } from "lucide-react"

import { Writable } from "@/components/app/read-only"
import { PageHeader } from "@/components/page-header"
import { downloadBase64, fileToBase64 } from "@/components/security/file-base64"
import { SettingBadge, SettingRow, SettingsColumn, SettingsSection } from "@/components/settings/settings-layout"
import { Button } from "@/components/ui/button"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { Textarea } from "@/components/ui/textarea"
import { ApiError, errorMessage, post } from "@/lib/api"
import { formatDate } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { CanaryReply, CanaryState } from "@/lib/pa-types"

const stateBadge: Record<CanaryState, { tone: "success" | "warning" | "danger" | "muted"; text: string }> = {
  valid: { tone: "success", text: msg("Geçerli") },
  expiring: { tone: "warning", text: msg("Süresi doluyor") },
  expired: { tone: "danger", text: msg("Yenilenmedi") },
  invalid: { tone: "danger", text: msg("Doğrulanamadı") },
  missing: { tone: "muted", text: msg("none|Yok") },
}

function CanaryBadge({ state }: { state: CanaryState }) {
  const { t } = useI18n()
  const b = stateBadge[state] ?? stateBadge.missing
  return <SettingBadge tone={b.tone}>{t(b.text)}</SettingBadge>
}

const encoder = new TextEncoder()

const signSchema = z.object({
  statement: z
    .string()
    .trim()
    .min(1, msg("Beyan metni gerekli"))
    .refine((s) => encoder.encode(s).length <= 2000, msg("Beyan metni en çok 2000 bayt olmalı")),
  days: z
    .number({ error: msg("Gün sayısı gerekli") })
    .int()
    .min(1, msg("En az 1 gün"))
    .max(90, msg("En çok 90 gün")),
  passphrase: z.string().min(1, msg("Kök anahtar parolası gerekli")).max(1024, msg("Parola çok uzun")),
})

type SignForm = z.infer<typeof signSchema>

/** Ayarlar > Kanarya (ADR-0180, #632): sign and verify the warrant canary. */
export function CanaryView() {
  const { t } = useI18n()
  return (
    <SettingsColumn>
      <PageHeader
        title={t("Kanarya beyanı")}
        description={t(
          "Kanarya, kök anahtarınızla imzaladığınız tarihli bir beyandır. Süresinde yenilemezseniz cihazlar uyarı gösterir. Koordinatör beyanı değiştiremez, yalnızca saklar."
        )}
      />
      <Writable>
        <SignSection />
      </Writable>
      <VerifySection />
    </SettingsColumn>
  )
}

function SignSection() {
  const { t } = useI18n()
  const [signed, setSigned] = useState<CanaryReply | null>(null)
  const form = useForm<SignForm>({ resolver: zodResolver(signSchema), defaultValues: { statement: "", days: 30, passphrase: "" } })
  const { errors, isSubmitting } = form.formState

  async function onSubmit(values: SignForm) {
    try {
      const res = await post<CanaryReply>("/api/g2/canary/sign", values)
      form.setValue("passphrase", "")
      setSigned(res)
      toast.success(t("Kanarya beyanı imzalandı."))
    } catch (err) {
      form.setValue("passphrase", "")
      const message =
        err instanceof ApiError && err.status === 409
          ? t("Kök anahtar dosyası okunamadı; kök anahtar donanım jetonundaysa kanarya henüz panelden imzalanamaz.")
          : errorMessage(err)
      form.setError("passphrase", { message })
    }
  }

  return (
    <SettingsSection
      id="imzala"
      title={t("Beyanı imzala")}
      description={t("İmza bu bilgisayarda atılır; koordinatöre yükleme cihaz servisi tarafından yapılır.")}
    >
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4 py-5">
        <FieldGroup>
          <Field data-invalid={errors.statement ? true : undefined}>
            <FieldLabel htmlFor="canary-statement">{t("Beyan metni (en çok 2000 bayt)")}</FieldLabel>
            <Textarea id="canary-statement" rows={4} maxLength={2000} aria-invalid={errors.statement ? true : undefined} {...form.register("statement")} />
            <FieldError errors={[errors.statement]} />
          </Field>
          <Field data-invalid={errors.days ? true : undefined} className="max-w-40">
            <FieldLabel htmlFor="canary-days">{t("Geçerlilik (gün)")}</FieldLabel>
            <Input
              id="canary-days"
              type="number"
              min={1}
              max={90}
              inputMode="numeric"
              className="tabular-nums"
              aria-invalid={errors.days ? true : undefined}
              {...form.register("days", { valueAsNumber: true })}
            />
            <FieldError errors={[errors.days]} />
          </Field>
          <Field data-invalid={errors.passphrase ? true : undefined}>
            <FieldLabel htmlFor="canary-passphrase">{t("Kök anahtar parolası")}</FieldLabel>
            <Input
              id="canary-passphrase"
              type="password"
              autoComplete="current-password"
              aria-invalid={errors.passphrase ? true : undefined}
              {...form.register("passphrase")}
            />
            <FieldDescription>{t("Parola yalnızca bu imza için kullanılır, saklanmaz.")}</FieldDescription>
            <FieldError errors={[errors.passphrase]} />
          </Field>
        </FieldGroup>
        <div className="flex flex-wrap gap-2">
          <Button type="submit" disabled={isSubmitting}>
            {isSubmitting ? <Spinner data-icon="inline-start" /> : <ShieldCheck data-icon="inline-start" />}
            {t("İmzala")}
          </Button>
          {signed?.canary ? (
            <Button
              type="button"
              variant="outline"
              onClick={() => downloadBase64(signed.canary as string, `kanarya-${new Date().toISOString().slice(0, 10)}.json`)}
            >
              <Download data-icon="inline-start" />
              {t("Dosyayı indir")}
            </Button>
          ) : null}
        </div>
        {signed ? (
          <p role="status" className="text-sm text-muted-foreground">
            {signed.notAfter
              ? t("Sıra {seq}, {date} tarihine kadar geçerli.", { seq: signed.seq ?? 0, date: formatDate(signed.notAfter) })
              : t("Sıra {seq}.", { seq: signed.seq ?? 0 })}
          </p>
        ) : null}
      </form>
    </SettingsSection>
  )
}

function VerifySection() {
  const { t, ts } = useI18n()
  const id = useId()
  const [busy, setBusy] = useState(false)
  const [reply, setReply] = useState<CanaryReply | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  async function onFile(file: File | undefined) {
    if (!file) return
    setBusy(true)
    setFailure(null)
    setReply(null)
    try {
      const canary = await fileToBase64(file)
      setReply(await post<CanaryReply>("/api/g2/canary/verify", { canary }))
    } catch (err) {
      setFailure(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <SettingsSection
      id="dogrula"
      title={t("Beyanı doğrula")}
      description={t("İndirdiğiniz veya bir cihazdan aldığınız kanarya dosyasını denetler.")}
    >
      <SettingRow
        title={t("Kanarya dosyası")}
        badge={reply ? <CanaryBadge state={reply.state} /> : null}
        description={reply ? ts(reply.label) : t("Dosyayı seçin; içerik yalnızca bu bilgisayarda denetlenir.")}
        action={
          <label
            htmlFor={id}
            className="inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-lg border bg-background px-2.5 text-sm font-medium hover:bg-muted focus-within:ring-3 focus-within:ring-ring/50"
          >
            {busy ? <Spinner /> : <FileCheck className="size-4" aria-hidden="true" />}
            {t("Dosya seç")}
            <input
              id={id}
              type="file"
              accept="application/json,.json"
              className="sr-only"
              disabled={busy}
              onChange={(e) => {
                void onFile(e.target.files?.[0])
                e.target.value = ""
              }}
            />
          </label>
        }
      >
        {reply?.statement ? (
          <blockquote className="rounded-lg border bg-muted/40 px-3 py-2 text-sm whitespace-pre-wrap text-pretty">{reply.statement}</blockquote>
        ) : null}
        {failure ? (
          <p role="alert" className="text-sm text-destructive">
            {failure}
          </p>
        ) : null}
      </SettingRow>
    </SettingsSection>
  )
}
