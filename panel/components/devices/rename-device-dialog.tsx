"use client"

import { Fragment, useState } from "react"
import { useRouter } from "next/navigation"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { TriangleAlert } from "lucide-react"

import { SignChange } from "@/components/sign-change"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { msg, useI18n } from "@/lib/i18n/i18n"
import { labelSchema } from "@/lib/references"

function renameSchema(current: string) {
  return z.object({
    newName: labelSchema
      .refine((v) => v !== "coordinator", msg("\"coordinator\" adı koordinatöre ayrılmıştır"))
      .refine((v) => v !== current, msg("Yeni ad eskisiyle aynı")),
  })
}

type RenameForm = z.infer<ReturnType<typeof renameSchema>>

interface RenameDeviceDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  name: string
  dnsDomain: string
}

/** Renames a device; its MagicDNS name changes with it. */
export function RenameDeviceDialog({ open, onOpenChange, name, dnsDomain }: RenameDeviceDialogProps) {
  const { t } = useI18n()
  const router = useRouter()
  const [newName, setNewName] = useState<string | null>(null)

  function handleOpenChange(next: boolean) {
    if (!next) setNewName(null)
    onOpenChange(next)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("{name} cihazını yeniden adlandır", { name })}</DialogTitle>
          <DialogDescription className="text-pretty">
            {newName ? t("Değişikliği kontrol et ve kök anahtarınla imzala.") : t("Cihazın kimliği, adresleri ve anahtarları değişmez; yalnızca adı değişir.")}
          </DialogDescription>
        </DialogHeader>
        {open && newName === null ? <RenameStep name={name} dnsDomain={dnsDomain} onNext={setNewName} /> : null}
        {open && newName !== null ? (
          <SignChange
            endpoint="/api/devices/rename"
            payload={{ name, newName }}
            confirmLabel={t("İmzala ve yeniden adlandır")}
            onBack={() => setNewName(null)}
            onDone={() => {
              handleOpenChange(false)
              router.replace(`/devices/detail?name=${encodeURIComponent(newName)}`)
            }}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

function RenameStep({ name, dnsDomain, onNext }: { name: string; dnsDomain: string; onNext: (newName: string) => void }) {
  const { t } = useI18n()
  const form = useForm<RenameForm>({ resolver: zodResolver(renameSchema(name)), defaultValues: { newName: name } })
  const { errors } = form.formState
  return (
    <form onSubmit={form.handleSubmit((v) => onNext(v.newName))} noValidate className="flex flex-col gap-4">
      <Alert>
        <TriangleAlert />
        <AlertDescription className="text-pretty">
          {t(
            "MagicDNS adı da değişir: {address} artık çözülmez. Eski adı kullanan kayıtlı bağlantılar (ör. Uzak Masaüstü kısayolları, SSH yapılandırmaları) bozulur; onları yeni adla güncelle."
          )
            .split(/(\{address\})/)
            .map((part, i) =>
              part === "{address}" ? (
                <span key={i} className="font-mono text-xs">
                  {name}.{dnsDomain}
                </span>
              ) : (
                <Fragment key={i}>{part}</Fragment>
              )
            )}
        </AlertDescription>
      </Alert>
      <FieldGroup>
        <Field data-invalid={errors.newName ? true : undefined}>
          <FieldLabel htmlFor="rename-new">{t("Yeni ad")}</FieldLabel>
          <Input
            id="rename-new"
            autoComplete="off"
            spellCheck={false}
            autoFocus
            className="font-mono"
            aria-invalid={errors.newName ? true : undefined}
            {...form.register("newName")}
          />
          <FieldDescription>{t("Küçük harf, rakam ve tire; en fazla 63 karakter.")}</FieldDescription>
          <FieldError errors={[errors.newName]} />
        </Field>
      </FieldGroup>
      <DialogFooter>
        <Button type="submit">{t("Değişikliği göster")}</Button>
      </DialogFooter>
    </form>
  )
}
