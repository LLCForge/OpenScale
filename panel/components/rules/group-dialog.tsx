"use client"

import { useState } from "react"
import { Controller, useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"

import { ReferencePicker, type ReferenceChoices } from "@/components/rules/reference-picker"
import { SignChange } from "@/components/sign-change"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import { labelSchema } from "@/lib/references"
import type { Group } from "@/lib/types"

const MAX_MEMBERS = 256

function groupSchema(existing: string[], editing: boolean) {
  return z.object({
    name: labelSchema.refine((v) => editing || !existing.includes(v), msg("Bu adda bir grup var; değiştirmek için listeden düzenle")),
    members: z
      .array(z.string())
      .min(1, msg("En az bir üye seç"))
      .max(MAX_MEMBERS, { error: () => tx("En fazla {count} üye", { count: MAX_MEMBERS }) }),
  })
}

type GroupForm = z.infer<ReturnType<typeof groupSchema>>

interface GroupDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The group to edit; null creates a new one. */
  group: Group | null
  existing: string[]
  choices: ReferenceChoices
}

/** Creates a group or replaces an existing group's members. */
export function GroupDialog({ open, onOpenChange, group, existing, choices }: GroupDialogProps) {
  const { t } = useI18n()
  const [payload, setPayload] = useState<GroupForm | null>(null)

  function handleOpenChange(next: boolean) {
    if (!next) setPayload(null)
    onOpenChange(next)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{group ? t("group:{name} grubunu düzenle", { name: group.name }) : t("Grup ekle")}</DialogTitle>
          <DialogDescription className="text-pretty">
            {payload
              ? t("Değişikliği kontrol et ve kök anahtarınla imzala.")
              : t("Grup, cihazları ve etiketleri tek adla toplar. Kurallar ve çıkış düğümü kullanıcıları gruba group:ad ile başvurur.")}
          </DialogDescription>
        </DialogHeader>
        {open && !payload ? <GroupStep group={group} existing={existing} choices={choices} onNext={setPayload} /> : null}
        {open && payload ? (
          <SignChange
            endpoint="/api/groups"
            payload={{ name: payload.name, members: payload.members }}
            confirmLabel={t("İmzala ve kaydet")}
            onBack={() => setPayload(null)}
            onDone={() => handleOpenChange(false)}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

interface GroupStepProps {
  group: Group | null
  existing: string[]
  choices: ReferenceChoices
  onNext: (values: GroupForm) => void
}

function GroupStep({ group, existing, choices, onNext }: GroupStepProps) {
  const { t } = useI18n()
  const form = useForm<GroupForm>({
    resolver: zodResolver(groupSchema(existing, group !== null)),
    defaultValues: { name: group?.name ?? "", members: group?.members ?? [] },
  })
  const { errors } = form.formState
  // Groups cannot contain groups or "*".
  const memberChoices: ReferenceChoices = { devices: choices.devices, tags: choices.tags, groups: [] }

  return (
    <form onSubmit={form.handleSubmit(onNext)} noValidate className="flex flex-col gap-4">
      <FieldGroup>
        <Field data-invalid={errors.name ? true : undefined} data-disabled={group ? true : undefined}>
          <FieldLabel htmlFor="group-name">{t("Grup adı")}</FieldLabel>
          <Input
            id="group-name"
            autoComplete="off"
            spellCheck={false}
            className="font-mono"
            placeholder={t("ofis")}
            readOnly={group !== null}
            aria-invalid={errors.name ? true : undefined}
            {...form.register("name")}
          />
          <FieldDescription>
            {group
              ? t("Grup adı değiştirilemez; farklı ad için yeni grup oluştur.")
              : t("Küçük harf, rakam ve tire. Kurallarda group:ad olarak görünür.")}
          </FieldDescription>
          <FieldError errors={[errors.name]} />
        </Field>
        <Controller
          control={form.control}
          name="members"
          render={({ field }) => (
            <ReferencePicker
              legend={t("Üyeler")}
              choices={memberChoices}
              value={field.value}
              onChange={field.onChange}
              max={MAX_MEMBERS}
              description={t("Cihazlar ve etiketler; grup içinde grup veya tüm cihazlar seçilemez.")}
              error={errors.members?.message}
            />
          )}
        />
      </FieldGroup>
      <DialogFooter>
        <Button type="submit">{t("Değişikliği göster")}</Button>
      </DialogFooter>
    </form>
  )
}
