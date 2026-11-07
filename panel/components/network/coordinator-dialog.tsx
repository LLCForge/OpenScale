"use client"

import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { useSWRConfig } from "swr"

import { SignChange } from "@/components/sign-change"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { CoordinatorInfo } from "@/lib/types"

export const coordinatorSchema = z.object({
  endpoint: z
    .string()
    .trim()
    .min(3, msg("Adres gerekli"))
    .max(260, msg("Adres çok uzun"))
    .regex(/^(\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9.-]+):\d{1,5}$/, msg("host:port biçiminde olmalı, ör. vpn.ornek.com:51820 veya 203.0.113.5:51820")),
  wireguardKey: z
    .string()
    .trim()
    .regex(/^[A-Za-z0-9+/]{43}=$/, msg("44 karakterlik base64 WireGuard anahtarı olmalı")),
  fingerprint: z
    .string()
    .trim()
    .regex(/^[A-Za-z2-7]{4}-?[A-Za-z2-7]{4}-?[A-Za-z2-7]{4}-?[A-Za-z2-7]{4}$/, msg("XXXX-XXXX-XXXX-XXXX biçiminde olmalı")),
})

export type CoordinatorValues = z.infer<typeof coordinatorSchema>

/** Form fields shared by the network page dialog and the setup wizard. */
export function CoordinatorForm({
  defaults,
  submitLabel,
  onSubmit,
  inline,
}: {
  defaults?: Partial<CoordinatorValues>
  submitLabel: string
  onSubmit: (values: CoordinatorValues) => void
  /** Plain footer for wizard pages instead of the dialog footer band. */
  inline?: boolean
}) {
  const { t } = useI18n()
  const form = useForm<CoordinatorValues>({
    resolver: zodResolver(coordinatorSchema),
    defaultValues: { endpoint: defaults?.endpoint ?? "", wireguardKey: defaults?.wireguardKey ?? "", fingerprint: "" },
  })
  const { errors } = form.formState
  return (
    <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
      <FieldGroup>
        <Field data-invalid={errors.endpoint ? true : undefined}>
          <FieldLabel htmlFor="coord-endpoint">{t("Genel adres ve port")}</FieldLabel>
          <Input id="coord-endpoint" className="font-mono" placeholder={t("vpn.ornek.com:51820")} autoComplete="off" {...form.register("endpoint")} />
          <FieldDescription>{t("VPS'in IP adresi veya ev sunucun için dinamik DNS adı. UDP portu internete açık olmalı.")}</FieldDescription>
          <FieldError errors={[errors.endpoint]} />
        </Field>
        <Field data-invalid={errors.wireguardKey ? true : undefined}>
          <FieldLabel htmlFor="coord-key">{t("WireGuard açık anahtarı")}</FieldLabel>
          <Input id="coord-key" className="font-mono" spellCheck={false} autoComplete="off" {...form.register("wireguardKey")} />
          <FieldError errors={[errors.wireguardKey]} />
        </Field>
        <Field data-invalid={errors.fingerprint ? true : undefined}>
          <FieldLabel htmlFor="coord-fp">{t("Koordinatör parmak izi")}</FieldLabel>
          <Input id="coord-fp" className="font-mono uppercase" placeholder="XXXX-XXXX-XXXX-XXXX" autoComplete="off" {...form.register("fingerprint")} />
          <FieldDescription>{t("Sunucuda `openscale coordinator keygen` çıktısındakini elle yaz; eşleşmezse kaydedilmez.")}</FieldDescription>
          <FieldError errors={[errors.fingerprint]} />
        </Field>
      </FieldGroup>
      {inline ? (
        <div className="flex justify-end">
          <Button type="submit">{t(submitLabel)}</Button>
        </div>
      ) : (
        <DialogFooter>
          <Button type="submit">{t(submitLabel)}</Button>
        </DialogFooter>
      )}
    </form>
  )
}

interface CoordinatorDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  current: CoordinatorInfo | null
}

export function CoordinatorDialog({ open, onOpenChange, current }: CoordinatorDialogProps) {
  const { t } = useI18n()
  const [payload, setPayload] = useState<CoordinatorValues | null>(null)
  const { mutate } = useSWRConfig()

  function handleOpenChange(next: boolean) {
    if (!next) setPayload(null)
    onOpenChange(next)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{current ? t("Koordinatörü değiştir") : t("Koordinatör ekle")}</DialogTitle>
          <DialogDescription>
            {t("Koordinatör cihazların birbirini bulmasını sağlar; ağ belgesini değiştiremez ve trafiği göremez.")}
          </DialogDescription>
        </DialogHeader>
        {open && !payload ? (
          <CoordinatorForm
            defaults={current ? { endpoint: current.endpoint, wireguardKey: current.wireguardKey } : undefined}
            submitLabel={t("Değişikliği göster")}
            onSubmit={setPayload}
          />
        ) : null}
        {open && payload ? (
          <SignChange
            endpoint="/api/network/coordinator"
            payload={payload}
            confirmLabel={t("İmzala ve kaydet")}
            onBack={() => setPayload(null)}
            onDone={() => {
              void mutate("/api/network")
              handleOpenChange(false)
            }}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  )
}
