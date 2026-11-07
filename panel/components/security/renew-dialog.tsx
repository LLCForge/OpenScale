"use client"

import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"

import { SignChange } from "@/components/sign-change"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { msg, useI18n } from "@/lib/i18n/i18n"

const schema = z.object({
  validityDays: z.number().int().min(1, msg("En az 1 gün")).max(400, msg("En fazla 400 gün")),
})

type RenewForm = z.infer<typeof schema>

interface RenewDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function RenewDialog({ open, onOpenChange }: RenewDialogProps) {
  const { t } = useI18n()
  const [validityDays, setValidityDays] = useState<number | null>(null)
  const form = useForm<RenewForm>({ resolver: zodResolver(schema), defaultValues: { validityDays: 90 } })
  const { errors } = form.formState

  function handleOpenChange(next: boolean) {
    if (!next) {
      setValidityDays(null)
      form.reset()
    }
    onOpenChange(next)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("Belgeyi yenile")}</DialogTitle>
          <DialogDescription>{t("Belgenin içeriği aynı kalır; yalnızca sürüm numarası ve geçerlilik süresi yenilenir.")}</DialogDescription>
        </DialogHeader>
        {open && validityDays === null ? (
          <form onSubmit={form.handleSubmit((v) => setValidityDays(v.validityDays))} noValidate className="flex flex-col gap-4">
            <FieldGroup>
              <Field data-invalid={errors.validityDays ? true : undefined}>
                <FieldLabel htmlFor="renew-days">{t("Geçerlilik süresi (gün)")}</FieldLabel>
                <Input id="renew-days" type="number" inputMode="numeric" min={1} max={400} {...form.register("validityDays", { valueAsNumber: true })} />
                <FieldDescription>{t("Kısa süre daha güvenlidir ama daha sık yenileme gerektirir. Önerilen: 90 gün.")}</FieldDescription>
                <FieldError errors={[errors.validityDays]} />
              </Field>
            </FieldGroup>
            <DialogFooter>
              <Button type="submit">{t("Değişikliği göster")}</Button>
            </DialogFooter>
          </form>
        ) : null}
        {open && validityDays !== null ? (
          <SignChange
            endpoint="/api/network/renew"
            payload={{ validityDays }}
            confirmLabel={t("İmzala ve yenile")}
            onBack={() => setValidityDays(null)}
            onDone={() => handleOpenChange(false)}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  )
}
