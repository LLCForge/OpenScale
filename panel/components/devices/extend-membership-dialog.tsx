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

const extendSchema = z.object({
  lifetimeDays: z
    .number({ error: msg("Gün sayısı gir") })
    .int(msg("Tam sayı gir"))
    .min(1, msg("En az 1 gün"))
    .max(3650, msg("En fazla 3650 gün")),
})

type ExtendForm = z.infer<typeof extendSchema>

const quick = [30, 90, 365]

interface ExtendMembershipDialogProps {
  /** Device to extend; null closes the dialog. */
  name: string | null
  onClose: () => void
}

/** Extends a device's membership (F-111) after a signed dry run. */
export function ExtendMembershipDialog({ name, onClose }: ExtendMembershipDialogProps) {
  const { t } = useI18n()
  const [payload, setPayload] = useState<{ name: string; lifetimeDays: number } | null>(null)

  function handleOpenChange(open: boolean) {
    if (!open) {
      setPayload(null)
      onClose()
    }
  }

  return (
    <Dialog open={name !== null} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("{name} üyeliğini uzat", { name: name ?? "" })}</DialogTitle>
          <DialogDescription className="text-pretty">
            {payload
              ? t("Yeni bitiş tarihini kontrol et ve kök anahtarınla imzala.")
              : t("Süresi dolan cihaz yeni bağlantı kuramaz. Yeni süre imzadan önce değişiklik listesinde tarih olarak görünür.")}
          </DialogDescription>
        </DialogHeader>
        {name !== null && !payload ? <ExtendStep onNext={(days) => setPayload({ name, lifetimeDays: days })} /> : null}
        {name !== null && payload ? (
          <SignChange
            endpoint="/api/devices/extend"
            payload={{ ...payload }}
            confirmLabel={t("İmzala ve uzat")}
            onBack={() => setPayload(null)}
            onDone={() => handleOpenChange(false)}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

function ExtendStep({ onNext }: { onNext: (days: number) => void }) {
  const { t } = useI18n()
  const form = useForm<ExtendForm>({ resolver: zodResolver(extendSchema), defaultValues: { lifetimeDays: 365 } })
  const { errors } = form.formState
  return (
    <form onSubmit={form.handleSubmit((v) => onNext(v.lifetimeDays))} noValidate className="flex flex-col gap-4">
      <FieldGroup>
        <Field data-invalid={errors.lifetimeDays ? true : undefined}>
          <FieldLabel htmlFor="extend-days">{t("Üyelik süresi (gün)")}</FieldLabel>
          <Input
            id="extend-days"
            type="number"
            inputMode="numeric"
            min={1}
            max={3650}
            autoFocus
            aria-invalid={errors.lifetimeDays ? true : undefined}
            {...form.register("lifetimeDays", { valueAsNumber: true })}
          />
          <div className="flex flex-wrap gap-2">
            {quick.map((d) => (
              <Button
                key={d}
                type="button"
                variant="outline"
                size="sm"
                onClick={() => form.setValue("lifetimeDays", d, { shouldValidate: true })}
              >
                {t("{count} gün", { count: d })}
              </Button>
            ))}
          </div>
          <FieldDescription>{t("1 ile 3650 gün arası.")}</FieldDescription>
          <FieldError errors={[errors.lifetimeDays]} />
        </Field>
      </FieldGroup>
      <DialogFooter>
        <Button type="submit">{t("Değişikliği göster")}</Button>
      </DialogFooter>
    </form>
  )
}
