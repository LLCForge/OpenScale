"use client"

import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"
import { Download } from "lucide-react"

import { currentPassphrase, newPassphrase } from "@/components/security/passphrase-schema"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { errorMessage, postForBlob } from "@/lib/api"
import { msg, useI18n } from "@/lib/i18n/i18n"

const schema = z
  .object({
    current: currentPassphrase,
    backupPassphrase: newPassphrase,
    confirm: z.string(),
    label: z.string().trim().max(64, msg("En fazla 64 karakter")),
  })
  .refine((v) => v.backupPassphrase === v.confirm, { path: ["confirm"], message: msg("Parolalar eşleşmiyor") })
  .refine((v) => v.backupPassphrase !== v.current, { path: ["backupPassphrase"], message: msg("Yedek parolası mevcut paroladan farklı olmalı") })

type BackupForm = z.infer<typeof schema>

interface BackupDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated: () => void
}

export function BackupDialog({ open, onOpenChange, onCreated }: BackupDialogProps) {
  const { t } = useI18n()
  const form = useForm<BackupForm>({
    resolver: zodResolver(schema),
    defaultValues: { current: "", backupPassphrase: "", confirm: "", label: "" },
  })
  const { errors, isSubmitting } = form.formState

  function handleOpenChange(next: boolean) {
    if (!next) form.reset()
    onOpenChange(next)
  }

  async function onSubmit(values: BackupForm) {
    try {
      const { blob, filename } = await postForBlob("/api/security/backup", {
        current: values.current,
        backupPassphrase: values.backupPassphrase,
        label: values.label,
      })
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
      toast.success(t("Yedek indirildi. Dosyayı ve parolasını ayrı yerlerde sakla."))
      onCreated()
      handleOpenChange(false)
    } catch (err) {
      form.setValue("current", "")
      form.setError("current", { message: errorMessage(err) })
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("Kök anahtar yedeği indir")}</DialogTitle>
          <DialogDescription>
            {t("Yedek, belirlediğin yeni parolayla şifrelenmiş bir dosyadır. Geri yüklemek için:")} <code className="font-mono">openscale network restore</code>
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
          <FieldGroup>
            <Field data-invalid={errors.current ? true : undefined}>
              <FieldLabel htmlFor="backup-current">{t("Mevcut kök anahtar parolası")}</FieldLabel>
              <Input id="backup-current" type="password" autoComplete="current-password" {...form.register("current")} />
              <FieldError errors={[errors.current]} />
            </Field>
            <Field data-invalid={errors.backupPassphrase ? true : undefined}>
              <FieldLabel htmlFor="backup-pass">{t("Yedeğin parolası")}</FieldLabel>
              <Input id="backup-pass" type="password" autoComplete="new-password" {...form.register("backupPassphrase")} />
              <FieldDescription>{t("Ana paroladan farklı ve en az 12 karakter olmalı.")}</FieldDescription>
              <FieldError errors={[errors.backupPassphrase]} />
            </Field>
            <Field data-invalid={errors.confirm ? true : undefined}>
              <FieldLabel htmlFor="backup-confirm">{t("Yedeğin parolası (tekrar)")}</FieldLabel>
              <Input id="backup-confirm" type="password" autoComplete="new-password" {...form.register("confirm")} />
              <FieldError errors={[errors.confirm]} />
            </Field>
            <Field data-invalid={errors.label ? true : undefined}>
              <FieldLabel htmlFor="backup-label">{t("Not (isteğe bağlı)")}</FieldLabel>
              <Input id="backup-label" placeholder="usb-1" autoComplete="off" {...form.register("label")} />
              <FieldDescription>{t("Yedeğin nerede olduğunu hatırlaman için; dosyaya değil, bu bilgisayardaki kayda yazılır.")}</FieldDescription>
              <FieldError errors={[errors.label]} />
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting ? <Spinner data-icon="inline-start" /> : <Download data-icon="inline-start" />}
              {t("Yedeği oluştur ve indir")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
