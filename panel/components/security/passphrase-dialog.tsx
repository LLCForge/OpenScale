"use client"

import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"

import { currentPassphrase, newPassphrase } from "@/components/security/passphrase-schema"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { errorMessage, post } from "@/lib/api"
import { msg, useI18n } from "@/lib/i18n/i18n"

const schema = z
  .object({ current: currentPassphrase, next: newPassphrase, confirm: z.string() })
  .refine((v) => v.next === v.confirm, { path: ["confirm"], message: msg("Parolalar eşleşmiyor") })
  .refine((v) => v.next !== v.current, { path: ["next"], message: msg("Yeni parola mevcut paroladan farklı olmalı") })

type PassphraseForm = z.infer<typeof schema>

interface PassphraseDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function PassphraseDialog({ open, onOpenChange }: PassphraseDialogProps) {
  const { t } = useI18n()
  const form = useForm<PassphraseForm>({ resolver: zodResolver(schema), defaultValues: { current: "", next: "", confirm: "" } })
  const { errors, isSubmitting } = form.formState

  function handleOpenChange(next: boolean) {
    if (!next) form.reset()
    onOpenChange(next)
  }

  async function onSubmit(values: PassphraseForm) {
    try {
      await post("/api/security/passphrase", { current: values.current, next: values.next })
      toast.success(t("Kök anahtar parolası değiştirildi."))
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
          <DialogTitle>{t("Kök anahtar parolasını değiştir")}</DialogTitle>
          <DialogDescription>{t("Yeni parolayı unutursan yalnızca yedeklerinle kurtarabilirsin.")}</DialogDescription>
        </DialogHeader>
        <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
          <FieldGroup>
            <Field data-invalid={errors.current ? true : undefined}>
              <FieldLabel htmlFor="pass-current">{t("Mevcut parola")}</FieldLabel>
              <Input id="pass-current" type="password" autoComplete="current-password" {...form.register("current")} />
              <FieldError errors={[errors.current]} />
            </Field>
            <Field data-invalid={errors.next ? true : undefined}>
              <FieldLabel htmlFor="pass-next">{t("Yeni parola")}</FieldLabel>
              <Input id="pass-next" type="password" autoComplete="new-password" {...form.register("next")} />
              <FieldError errors={[errors.next]} />
            </Field>
            <Field data-invalid={errors.confirm ? true : undefined}>
              <FieldLabel htmlFor="pass-confirm">{t("Yeni parola (tekrar)")}</FieldLabel>
              <Input id="pass-confirm" type="password" autoComplete="new-password" {...form.register("confirm")} />
              <FieldError errors={[errors.confirm]} />
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting ? <Spinner data-icon="inline-start" /> : null}
              {t("Parolayı değiştir")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
