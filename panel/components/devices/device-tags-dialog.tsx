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
import { MAX_TAGS, parseTagText, sameTags, tagTextSchema } from "@/lib/references"

const tagsSchema = z.object({ tags: tagTextSchema })
type TagsForm = z.infer<typeof tagsSchema>

interface DeviceTagsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  name: string
  tags: string[]
}

/** Replaces a device's tags; rules and groups can refer to them as tag:x. */
export function DeviceTagsDialog({ open, onOpenChange, name, tags }: DeviceTagsDialogProps) {
  const { t } = useI18n()
  const [next, setNext] = useState<string[] | null>(null)

  function handleOpenChange(value: boolean) {
    if (!value) setNext(null)
    onOpenChange(value)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("{name} etiketleri", { name })}</DialogTitle>
          <DialogDescription className="text-pretty">
            {next
              ? t("Değişikliği kontrol et ve kök anahtarınla imzala.")
              : t("Erişim kuralları, gruplar ve çıkış düğümü kullanıcıları cihazlara tag:ad biçiminde etiketle başvurabilir.")}
          </DialogDescription>
        </DialogHeader>
        {open && next === null ? <TagsStep current={tags} onNext={setNext} /> : null}
        {open && next !== null ? (
          <SignChange
            endpoint="/api/devices/tags"
            payload={{ name, tags: next }}
            confirmLabel={t("İmzala ve kaydet")}
            onBack={() => setNext(null)}
            onDone={() => handleOpenChange(false)}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

function TagsStep({ current, onNext }: { current: string[]; onNext: (tags: string[]) => void }) {
  const { t } = useI18n()
  const form = useForm<TagsForm>({ resolver: zodResolver(tagsSchema), defaultValues: { tags: current.join(", ") } })
  const { errors } = form.formState

  function submit(values: TagsForm) {
    const tags = parseTagText(values.tags)
    if (sameTags(tags, current)) {
      form.setError("tags", { message: msg("Etiketler değişmedi") })
      return
    }
    onNext(tags)
  }

  return (
    <form onSubmit={form.handleSubmit(submit)} noValidate className="flex flex-col gap-4">
      <FieldGroup>
        <Field data-invalid={errors.tags ? true : undefined}>
          <FieldLabel htmlFor="device-tags">{t("Etiketler")}</FieldLabel>
          <Input
            id="device-tags"
            autoComplete="off"
            spellCheck={false}
            autoFocus
            className="font-mono"
            placeholder={t("sunucu, ofis")}
            aria-invalid={errors.tags ? true : undefined}
            {...form.register("tags")}
          />
          <FieldDescription>
            {t("Virgül veya boşlukla ayır; \"tag:\" öneki isteğe bağlı. En fazla {max} etiket. Boş bırakırsan bütün etiketler kaldırılır.", { max: MAX_TAGS })}
          </FieldDescription>
          <FieldDescription>
            {t("Güncelleme halkası da etiketle seçilir: ring-canary yeni sürümü ilk kurar, ring-early canary cihazlar sorunsuz çalışınca, etiketsiz cihazlar (main) en son. Durum: Hakkında > Otomatik güncelleme.")}
          </FieldDescription>
          <FieldError errors={[errors.tags]} />
        </Field>
      </FieldGroup>
      <DialogFooter>
        <Button type="submit">{t("Değişikliği göster")}</Button>
      </DialogFooter>
    </form>
  )
}
