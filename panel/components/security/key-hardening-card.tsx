"use client"

import { useState } from "react"
import useSWR from "swr"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { Printer, ShieldPlus } from "lucide-react"
import { toast } from "sonner"

import { Writable } from "@/components/app/read-only"
import { currentPassphrase, newPassphrase } from "@/components/security/passphrase-schema"
import { SettingRow } from "@/components/settings/settings-layout"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { errorMessage, fetcher, post } from "@/lib/api"
import { msg, useI18n } from "@/lib/i18n/i18n"

interface KDF {
  time: number
  memoryMiB: number
  threads: number
}

const paperSchema = z
  .object({
    current: currentPassphrase,
    backupPassphrase: newPassphrase,
    confirm: z.string(),
    label: z.string().trim().max(64, msg("En fazla 64 karakter")),
  })
  .refine((v) => v.backupPassphrase === v.confirm, { path: ["confirm"], message: msg("Parolalar eşleşmiyor") })
  .refine((v) => v.backupPassphrase !== v.current, { path: ["backupPassphrase"], message: msg("Yedek parolası mevcut paroladan farklı olmalı") })

type PaperForm = z.infer<typeof paperSchema>

const kdfSchema = z.object({ passphrase: currentPassphrase })

/**
 * Paper backup with QR (ADR-0063) and stronger root key encryption
 * (ADR-0060), as two settings rows.
 */
export function KeyHardeningRows() {
  const { t } = useI18n()
  const { data: kdf, mutate } = useSWR<{ current: KDF }>("/api/security/kdf", fetcher)
  const [dialog, setDialog] = useState<"paper" | "kdf" | null>(null)
  return (
    <>
      <SettingRow
        title={t("Kâğıt yedek")}
        description={t("Şifreli kök anahtarı yazdırılabilir bir QR kod ve elle yazılabilir satırlar olarak verir.")}
        action={
          <Writable>
            <Button variant="outline" onClick={() => setDialog("paper")}>
              <Printer data-icon="inline-start" />
              {t("Kâğıt yedek")}
            </Button>
          </Writable>
        }
      />
      <SettingRow
        title={t("Şifreleme gücü")}
        description={
          kdf ? (
            <>
              {t("Argon2id: {time} tur, {memory} MiB bellek, {threads} iş parçacığı", {
                time: kdf.current.time,
                memory: kdf.current.memoryMiB,
                threads: kdf.current.threads,
              })}
            </>
          ) : (
            <Spinner />
          )
        }
        action={
          <Writable>
            <Button variant="outline" onClick={() => setDialog("kdf")}>
              <ShieldPlus data-icon="inline-start" />
              {t("Güçlendir")}
            </Button>
          </Writable>
        }
      />
      <PaperDialog open={dialog === "paper"} onOpenChange={(o) => !o && setDialog(null)} />
      <KDFDialog open={dialog === "kdf"} onOpenChange={(o) => !o && setDialog(null)} onDone={() => mutate()} />
    </>
  )
}

function PaperDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useI18n()
  const [result, setResult] = useState<{ qr: string; lines: string[] } | null>(null)
  const form = useForm<PaperForm>({ resolver: zodResolver(paperSchema), defaultValues: { current: "", backupPassphrase: "", confirm: "", label: "" } })
  const { errors, isSubmitting } = form.formState

  function change(o: boolean) {
    if (!o) {
      form.reset()
      setResult(null)
    }
    onOpenChange(o)
  }

  async function onSubmit(v: PaperForm) {
    try {
      const res = await post<{ qr: string; lines: string[] }>("/api/security/paper-backup", {
        current: v.current,
        backupPassphrase: v.backupPassphrase,
        label: v.label,
      })
      form.reset()
      setResult(res)
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }

  return (
    <Dialog open={open} onOpenChange={change}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("Kâğıt yedek")}</DialogTitle>
          <DialogDescription>
            {t("Yazdırıp güvenli bir yerde sakla. Yedek parolasını kâğıtla aynı yerde tutma. Geri yükleme: {command}.", {
              command: "openscale key paper-restore",
            })}
          </DialogDescription>
        </DialogHeader>
        {result ? (
          <div className="flex flex-col items-center gap-4 print:gap-2">
            {/* eslint-disable-next-line @next/next/no-img-element -- a data URL from the service, not an asset */}
            <img src={result.qr} alt={t("Kök anahtar kâğıt yedeğinin QR kodu")} className="size-64 rounded-md border bg-white p-2" />
            <pre className="w-full overflow-x-auto rounded-md bg-muted p-3 font-mono text-[0.8125rem] leading-relaxed">{result.lines.join("\n")}</pre>
            <DialogFooter className="w-full">
              <Button variant="outline" onClick={() => window.print()}>
                <Printer data-icon="inline-start" />
                {t("Yazdır")}
              </Button>
              <Button onClick={() => change(false)}>{t("Kapat")}</Button>
            </DialogFooter>
          </div>
        ) : (
          <form onSubmit={form.handleSubmit(onSubmit)} noValidate>
            <FieldGroup>
              <Field data-invalid={!!errors.current}>
                <FieldLabel htmlFor="paper-current">{t("Kök anahtar parolası")}</FieldLabel>
                <Input id="paper-current" type="password" autoComplete="current-password" {...form.register("current")} />
                <FieldError errors={[errors.current]} />
              </Field>
              <Field data-invalid={!!errors.backupPassphrase}>
                <FieldLabel htmlFor="paper-pass">{t("Yedek parolası")}</FieldLabel>
                <Input id="paper-pass" type="password" autoComplete="new-password" {...form.register("backupPassphrase")} />
                <FieldDescription>{t("En az 12 karakter; kâğıttaki yedek bu parolayla açılır.")}</FieldDescription>
                <FieldError errors={[errors.backupPassphrase]} />
              </Field>
              <Field data-invalid={!!errors.confirm}>
                <FieldLabel htmlFor="paper-confirm">{t("Yedek parolası (tekrar)")}</FieldLabel>
                <Input id="paper-confirm" type="password" autoComplete="new-password" {...form.register("confirm")} />
                <FieldError errors={[errors.confirm]} />
              </Field>
              <Field data-invalid={!!errors.label}>
                <FieldLabel htmlFor="paper-label">{t("Etiket (isteğe bağlı)")}</FieldLabel>
                <Input id="paper-label" {...form.register("label")} />
                <FieldError errors={[errors.label]} />
              </Field>
            </FieldGroup>
            <DialogFooter className="mt-6">
              <Button type="submit" disabled={isSubmitting}>
                {isSubmitting && <Spinner />}
                {t("Oluştur")}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

function KDFDialog({ open, onOpenChange, onDone }: { open: boolean; onOpenChange: (o: boolean) => void; onDone: () => void }) {
  const { t } = useI18n()
  const form = useForm<{ passphrase: string }>({ resolver: zodResolver(kdfSchema), defaultValues: { passphrase: "" } })
  const { errors, isSubmitting } = form.formState

  async function onSubmit(v: { passphrase: string }) {
    try {
      const res = await post<{ changed: boolean; before: KDF; current: KDF }>("/api/security/kdf", { passphrase: v.passphrase, targetMs: 1000 })
      if (res.changed) {
        toast.success(
          t("Kök anahtar yeniden şifrelendi: {memoryBefore} → {memoryAfter} MiB, {timeBefore} → {timeAfter} tur.", {
            memoryBefore: res.before.memoryMiB,
            memoryAfter: res.current.memoryMiB,
            timeBefore: res.before.time,
            timeAfter: res.current.time,
          })
        )
      } else {
        toast.info(t("Kök anahtar zaten bu bilgisayar için güçlü ayarlarla şifreli."))
      }
      form.reset()
      onDone()
      onOpenChange(false)
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("Şifrelemeyi güçlendir")}</DialogTitle>
          <DialogDescription>
            {t(
              "Bu bilgisayar ölçülür ve kök anahtar, açılması yaklaşık bir saniye sürecek Argon2id ayarlarıyla yeniden şifrelenir. Parola değişmez; mevcut yedekler kendi ayarlarıyla kalır."
            )}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={form.handleSubmit(onSubmit)} noValidate>
          <Field data-invalid={!!errors.passphrase}>
            <FieldLabel htmlFor="kdf-pass">{t("Kök anahtar parolası")}</FieldLabel>
            <Input id="kdf-pass" type="password" autoComplete="current-password" {...form.register("passphrase")} />
            <FieldError errors={[errors.passphrase]} />
          </Field>
          <DialogFooter className="mt-6">
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting && <Spinner />}
              {t("Güçlendir")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
