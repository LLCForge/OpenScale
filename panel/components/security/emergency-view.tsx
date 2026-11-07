"use client"

import { useState } from "react"
import useSWR, { useSWRConfig } from "swr"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"
import { OctagonAlert } from "lucide-react"

import { Writable } from "@/components/app/read-only"
import { CodeLine } from "@/components/copy-field"
import { PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { SealedBlobCheck } from "@/components/security/sealed-blob-check"
import { EmptyNote, SettingBadge, SettingRow, SettingsColumn, SettingsSection } from "@/components/settings/settings-layout"
import { destructiveText } from "@/components/sign-change"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { errorMessage, post } from "@/lib/api"
import { fetcher } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import type { EmergencyRecord } from "@/lib/pa-types"

function title(d: EmergencyRecord): string {
  return d.kind === "lockdown" ? tx("Her şeyi kilitle") : tx("Cihazı çıkar: {device}", { device: d.device ?? "?" })
}

function state(d: EmergencyRecord): React.ReactNode {
  if (d.expired) return <SettingBadge tone="danger">{tx("Süresi doldu")}</SettingBadge>
  if (d.stale) return <SettingBadge tone="warning">{tx("Eski: ağ sonradan değişti")}</SettingBadge>
  return <SettingBadge tone="success">{tx("Güncel")}</SettingBadge>
}

/**
 * Ayarlar > Acil durum (ADR-0175, ADR-0180): the pre-signed emergency
 * documents and the panic button. Publishing needs the separate emergency
 * passphrase, never the root key; preparing stays in the CLI because it
 * signs with the root key.
 */
export function EmergencyView() {
  const { t } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<{ documents: EmergencyRecord[] }>("/api/g1/emergency", fetcher)
  const [panic, setPanic] = useState<EmergencyRecord | null>(null)
  const docs = data?.documents ?? []
  const lockdown = docs.find((d) => d.kind === "lockdown" && !d.expired) ?? null

  return (
    <SettingsColumn>
      <PageHeader
        title={t("Acil durum")}
        description={t("Kök anahtarla önceden imzalanıp ayrı bir parolayla mühürlenen belgeler; kök anahtara erişemediğinizde ağı kilitler.")}
      />
      <SettingsSection id="belgeler" title={t("Hazır belgeler")} description={t("Aynı hazırlıktan yalnızca bir belge yayımlanabilir.")}>
        <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
          {data ? (
            docs.length === 0 ? (
              <EmptyNote framed={false}>{t("Hazır acil durum belgesi yok.")}</EmptyNote>
            ) : (
              docs.map((d) => (
                <SettingRow
                  key={`${d.kind}-${d.device ?? ""}-${d.version}`}
                  title={title(d)}
                  badge={state(d)}
                  description={
                    <span className="flex flex-col gap-0.5">
                      <span>
                        {t("Sürüm {version}, taban sürüm {base}, hazırlandı {date}", {
                          version: d.version,
                          base: d.base_version,
                          date: formatDateTime(d.prepared_at),
                        })}
                      </span>
                      {d.needs_approvals ? <span>{t("Hassas cihaz onayları gerekir.")}</span> : null}
                    </span>
                  }
                  action={
                    d.kind === "remove" && !d.expired ? (
                      <Writable>
                        <Button variant="outline" onClick={() => setPanic(d)}>
                          {t("Yayımla")}
                        </Button>
                      </Writable>
                    ) : null
                  }
                />
              ))
            )
          ) : null}
        </QueryState>
      </SettingsSection>
      <div className="flex flex-col gap-1">
        <p className="text-sm text-muted-foreground">{t("Hazırlamak için kök cihazda:")}</p>
        <CodeLine value="openscale admin emergency prepare" />
      </div>

      <SealedBlobCheck />

      <Writable>
        <SettingsSection
          id="panik"
          title={t("Panik")}
          tone="danger"
          description={t("Yalnızca ağın ele geçirildiğinden şüphelendiğinizde kullanın.")}
        >
          <SettingRow
            title={t("Her şeyi kilitle")}
            description={t("Bütün cihazlarda kurallar askıya alınır, davetler geri çekilir. Kök anahtar gerekmez.")}
            action={
              <Button
                variant="destructive"
                size="lg"
                className={destructiveText}
                disabled={!lockdown}
                onClick={() => lockdown && setPanic(lockdown)}
              >
                <OctagonAlert data-icon="inline-start" />
                {t("Panik")}
              </Button>
            }
          >
            {!lockdown ? <p className="text-sm text-muted-foreground">{t("Önce kilit belgesini hazırlayın; hazır belge olmadan düğme çalışmaz.")}</p> : null}
          </SettingRow>
        </SettingsSection>
      </Writable>

      {panic ? <PanicDialog doc={panic} onClose={() => setPanic(null)} /> : null}
    </SettingsColumn>
  )
}

const panicSchema = z.object({
  passphrase: z.string().min(1, msg("Acil durum parolası gerekli")).max(1024, msg("Parola çok uzun")),
  confirm: z.literal("PANIK", { error: msg("Onaylamak için PANIK yazın") }),
})

type PanicForm = z.input<typeof panicSchema>

function PanicDialog({ doc, onClose }: { doc: EmergencyRecord; onClose: () => void }) {
  const { t } = useI18n()
  const { mutate } = useSWRConfig()
  const form = useForm<PanicForm>({ resolver: zodResolver(panicSchema), defaultValues: { passphrase: "", confirm: "" as "PANIK" } })
  const { errors, isSubmitting } = form.formState
  // The word stays PANIK in every language: the server checks it.
  const [confirmBefore = "", confirmAfter = ""] = t("Onaylamak için {word} yazın").split("{word}")

  async function onSubmit(values: PanicForm) {
    try {
      const res = await post<{ version: number }>("/api/g1/emergency/publish", {
        kind: doc.kind,
        device: doc.device ?? "",
        passphrase: values.passphrase,
        confirm: values.confirm,
      })
      form.reset()
      await mutate((key) => typeof key === "string" && key.startsWith("/api/"))
      toast.success(t("Acil durum belgesi yayımlandı (sürüm {version}).", { version: res.version }))
      onClose()
    } catch (err) {
      form.setValue("passphrase", "")
      form.setError("passphrase", { message: errorMessage(err) })
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-destructive">{title(doc)}</DialogTitle>
          <DialogDescription className="text-pretty">
            {doc.kind === "lockdown"
              ? t("Bütün cihazlarda kurallar askıya alınır, davetler geri çekilir. Kök anahtar gerekmez.")
              : t("{device} ağdan çıkarılır. Kök anahtar gerekmez.", { device: doc.device ?? t("Cihaz") })}{" "}
            {t("Bu hazırlıktan başka belge yayımlanamaz.")}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
          <FieldGroup>
            <Field data-invalid={errors.passphrase ? true : undefined}>
              <FieldLabel htmlFor="panic-passphrase">{t("Acil durum parolası")}</FieldLabel>
              <Input
                id="panic-passphrase"
                type="password"
                autoComplete="off"
                autoFocus
                aria-invalid={errors.passphrase ? true : undefined}
                {...form.register("passphrase")}
              />
              <FieldDescription>{t("Hazırlarken belirlediğiniz ayrı parola; kök anahtar parolası değil.")}</FieldDescription>
              <FieldError errors={[errors.passphrase]} />
            </Field>
            <Field data-invalid={errors.confirm ? true : undefined}>
              <FieldLabel htmlFor="panic-confirm">
                {confirmBefore}
                <span className="font-mono font-semibold">PANIK</span>
                {confirmAfter}
              </FieldLabel>
              <Input
                id="panic-confirm"
                autoComplete="off"
                autoCapitalize="characters"
                spellCheck={false}
                className="font-mono"
                maxLength={16}
                aria-invalid={errors.confirm ? true : undefined}
                {...form.register("confirm")}
              />
              <FieldError errors={[errors.confirm]} />
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={isSubmitting}>
              {t("Vazgeç")}
            </Button>
            <Button type="submit" variant="destructive" className={destructiveText} disabled={isSubmitting}>
              {isSubmitting ? <Spinner data-icon="inline-start" /> : <OctagonAlert data-icon="inline-start" />}
              {t("Yayımla")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
