"use client"

import { useState } from "react"
import { Controller, useForm, useWatch } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"

import { ReferencePicker, type ReferenceChoices } from "@/components/rules/reference-picker"
import { SignChange } from "@/components/sign-change"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { FieldDescription, FieldGroup, FieldLegend, FieldSet } from "@/components/ui/field"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { ExitUsers } from "@/lib/types"
import { cn } from "@/lib/utils"

const MAX_USERS = 64

export type ExitUsersMode = "everyone" | "selected" | "nobody"

export function exitUsersMode(exitUsers: ExitUsers): ExitUsersMode {
  if (!exitUsers.restricted) return "everyone"
  return exitUsers.users.length > 0 ? "selected" : "nobody"
}

const exitUsersSchema = z
  .object({
    mode: z.enum(["everyone", "selected", "nobody"]),
    users: z.array(z.string()).max(MAX_USERS, msg("En fazla {max} giriş")),
  })
  .superRefine((v, ctx) => {
    if (v.mode === "selected" && v.users.length === 0) {
      ctx.addIssue({
        code: "custom",
        path: ["users"],
        message: msg("En az bir cihaz, etiket veya grup seç; kimse kullanmasın istiyorsan \"Hiçbir cihaz\" seçeneğini seç"),
      })
    }
  })

type ExitUsersForm = z.infer<typeof exitUsersSchema>

const modes: { value: ExitUsersMode; label: string; hint: string }[] = [
  { value: "everyone", label: msg("Bütün cihazlar"), hint: msg("Her cihaz çıkış düğümlerini kullanabilir (varsayılan).") },
  { value: "selected", label: msg("Yalnızca seçilenler"), hint: msg("Yalnızca seçtiğin cihazlar, etiketler ve gruplar kullanabilir.") },
  { value: "nobody", label: msg("Hiçbir cihaz"), hint: msg("Hiçbir cihaz çıkış düğümü kullanamaz; roller belgede kalır.") },
]

interface ExitUsersDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  current: ExitUsers
  choices: ReferenceChoices
}

/** Who may send internet traffic through exit nodes (ADR-0021). */
export function ExitUsersDialog({ open, onOpenChange, current, choices }: ExitUsersDialogProps) {
  const { t } = useI18n()
  const [payload, setPayload] = useState<ExitUsers | null>(null)

  function handleOpenChange(next: boolean) {
    if (!next) setPayload(null)
    onOpenChange(next)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("Çıkış düğümü kullanıcıları")}</DialogTitle>
          <DialogDescription className="text-pretty">
            {payload
              ? t("Değişikliği kontrol et ve kök anahtarınla imzala.")
              : t("Kimlerin internet trafiğini ağdaki çıkış düğümleri üzerinden çıkarabileceğini seç. Cihazlar arası erişim kuralları bundan etkilenmez.")}
          </DialogDescription>
        </DialogHeader>
        {open && !payload ? <ExitUsersStep current={current} choices={choices} onNext={setPayload} /> : null}
        {open && payload ? (
          <SignChange
            endpoint="/api/network/exit-users"
            payload={{ restricted: payload.restricted, users: payload.users }}
            confirmLabel={t("İmzala ve kaydet")}
            onBack={() => setPayload(null)}
            onDone={() => handleOpenChange(false)}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

interface ExitUsersStepProps {
  current: ExitUsers
  choices: ReferenceChoices
  onNext: (payload: ExitUsers) => void
}

function ExitUsersStep({ current, choices, onNext }: ExitUsersStepProps) {
  const { t } = useI18n()
  const form = useForm<ExitUsersForm>({
    resolver: zodResolver(exitUsersSchema),
    defaultValues: { mode: exitUsersMode(current), users: current.users },
  })
  const { errors } = form.formState
  const mode = useWatch({ control: form.control, name: "mode" })

  function submit(values: ExitUsersForm) {
    if (values.mode === "everyone") onNext({ restricted: false, users: [] })
    else if (values.mode === "nobody") onNext({ restricted: true, users: [] })
    else onNext({ restricted: true, users: values.users })
  }

  return (
    <form onSubmit={form.handleSubmit(submit)} noValidate className="flex flex-col gap-4">
      <FieldGroup>
        <FieldSet>
          <FieldLegend variant="label">{t("Kimler kullanabilir?")}</FieldLegend>
          <div role="radiogroup" aria-label={t("Kimler kullanabilir?")} className="grid gap-2 sm:grid-cols-3">
            {modes.map((m) => (
              <button
                key={m.value}
                type="button"
                role="radio"
                aria-checked={mode === m.value}
                onClick={() => form.setValue("mode", m.value, { shouldValidate: form.formState.isSubmitted })}
                className={cn(
                  "flex flex-col gap-1 rounded-lg border p-3 text-left transition-colors focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
                  mode === m.value ? "border-foreground bg-accent" : "hover:bg-accent/50"
                )}
              >
                <span className="text-sm font-medium">{t(m.label)}</span>
                <span className="text-xs leading-relaxed text-muted-foreground text-pretty">{t(m.hint)}</span>
              </button>
            ))}
          </div>
          {mode === "nobody" ? (
            <FieldDescription className="font-medium text-destructive">
              {t("Kısıtlama boş bir listeyle kaydedilir: ağdaki hiçbir cihaz çıkış düğümü kullanamaz.")}
            </FieldDescription>
          ) : null}
        </FieldSet>
        {mode === "selected" ? (
          <Controller
            control={form.control}
            name="users"
            render={({ field }) => (
              <ReferencePicker
                legend={t("Kullanabilecekler")}
                choices={choices}
                value={field.value}
                onChange={field.onChange}
                allowGroups
                max={MAX_USERS}
                description={t("Cihazlar, etiketler ve gruplar.")}
                error={errors.users?.message ? t(errors.users.message, { max: MAX_USERS }) : undefined}
              />
            )}
          />
        ) : null}
      </FieldGroup>
      <DialogFooter>
        <Button type="submit">{t("Değişikliği göster")}</Button>
      </DialogFooter>
    </form>
  )
}
