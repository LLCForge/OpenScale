"use client"

import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { Pencil, X } from "lucide-react"

import { Writable } from "@/components/app/read-only"
import { SettingRow } from "@/components/settings/settings-layout"
import { SignChange, SignChangeDialog } from "@/components/sign-change"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { msg, useI18n } from "@/lib/i18n/i18n"
import { textWithin } from "@/lib/references"

const nameSchema = z.object({
  displayName: textWithin(64)
    .refine((v) => v.length > 0, msg("Ad gerekli; adı kaldırmak için \"Adı kaldır\" düğmesini kullan"))
    .refine((v) => v === v.trim(), msg("Başta veya sonda boşluk olamaz")),
})

type NameForm = z.infer<typeof nameSchema>

/** The network's display name (F-160) as a settings row; shown in the panel and the apps. */
export function NetworkNameRow({ displayName }: { displayName: string }) {
  const { t } = useI18n()
  const [editing, setEditing] = useState(false)
  const [removing, setRemoving] = useState(false)

  return (
    <SettingRow
      title={t("Ağ adı")}
      description={displayName ? <span className="font-medium text-foreground break-words">{displayName}</span> : t("Ad verilmemiş; panel ve uygulamalar yalnızca ağ kimliğini gösterir.")}
      action={
        <Writable>
          <Button variant="outline" onClick={() => setEditing(true)}>
            <Pencil data-icon="inline-start" />
            {displayName ? t("Değiştir") : t("Ad ver")}
          </Button>
          {displayName ? (
            <Button variant="ghost" size="icon" aria-label={t("Ağ adını kaldır")} onClick={() => setRemoving(true)}>
              <X />
            </Button>
          ) : null}
        </Writable>
      }
    >
      <NetworkNameDialog open={editing} onOpenChange={setEditing} current={displayName} />
      <SignChangeDialog
        open={removing}
        onOpenChange={setRemoving}
        title={t("Ağ adını kaldır")}
        description={t("Ağın görünen adı belgeden kaldırılır; panel ve uygulamalar adı göstermez.")}
        endpoint="/api/network/name"
        payload={{ displayName: "" }}
        confirmLabel={t("İmzala ve kaldır")}
      />
    </SettingRow>
  )
}

function NetworkNameDialog({ open, onOpenChange, current }: { open: boolean; onOpenChange: (open: boolean) => void; current: string }) {
  const { t } = useI18n()
  const [next, setNext] = useState<string | null>(null)

  function handleOpenChange(value: boolean) {
    if (!value) setNext(null)
    onOpenChange(value)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{current ? t("Ağ adını değiştir") : t("Ağa ad ver")}</DialogTitle>
          <DialogDescription>{next !== null ? t("Değişikliği kontrol et ve kök anahtarınla imzala.") : t("Ad ağ belgesine imzalanır.")}</DialogDescription>
        </DialogHeader>
        {open && next === null ? <NameStep current={current} onNext={setNext} /> : null}
        {open && next !== null ? (
          <SignChange
            endpoint="/api/network/name"
            payload={{ displayName: next }}
            confirmLabel={t("İmzala ve kaydet")}
            onBack={() => setNext(null)}
            onDone={() => handleOpenChange(false)}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

function NameStep({ current, onNext }: { current: string; onNext: (name: string) => void }) {
  const { t } = useI18n()
  const form = useForm<NameForm>({ resolver: zodResolver(nameSchema), defaultValues: { displayName: current } })
  const { errors } = form.formState
  return (
    <form
      onSubmit={form.handleSubmit((v) => {
        if (v.displayName === current) {
          form.setError("displayName", { message: t("Ad değişmedi") })
          return
        }
        onNext(v.displayName)
      })}
      noValidate
      className="flex flex-col gap-4"
    >
      <FieldGroup>
        <Field data-invalid={errors.displayName ? true : undefined}>
          <FieldLabel htmlFor="network-display-name">{t("Ağ adı")}</FieldLabel>
          <Input
            id="network-display-name"
            autoComplete="off"
            autoFocus
            placeholder={t("Ev ağı")}
            aria-invalid={errors.displayName ? true : undefined}
            {...form.register("displayName")}
          />
          <FieldDescription>{t("En fazla 64 karakter; Türkçe karakter ve boşluk kullanılabilir.")}</FieldDescription>
          <FieldError errors={[errors.displayName]} />
        </Field>
      </FieldGroup>
      <DialogFooter>
        <Button type="submit">{t("Değişikliği göster")}</Button>
      </DialogFooter>
    </form>
  )
}
