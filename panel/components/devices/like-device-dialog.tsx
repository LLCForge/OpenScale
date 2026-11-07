"use client"

import { useState } from "react"
import useSWR from "swr"

import { NativeSelect } from "@/components/native-select"
import { SignChange } from "@/components/sign-change"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { errorMessage, fetcher } from "@/lib/api"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { LikeSuggestion } from "@/lib/p02-types"
import { MAX_TAGS, parseTagText, tagTextSchema } from "@/lib/references"
import type { DevicesResponse } from "@/lib/types"

// "Şu cihaz gibi yap" (#357): the new device gets the tags, groups, rules
// and exit permission of a device the owner picks, as a suggestion. The
// owner unticks what is not wanted and signs everything at once.

type Step = { kind: "pick" } | { kind: "sign"; payload: Record<string, unknown> }

interface LikeDeviceDialogProps {
  /** The device that receives the settings; null closes the dialog. */
  target: string | null
  onClose: () => void
}

export function LikeDeviceDialog({ target, onClose }: LikeDeviceDialogProps) {
  const { t } = useI18n()
  const [step, setStep] = useState<Step>({ kind: "pick" })
  function close(open: boolean) {
    if (open) return
    setStep({ kind: "pick" })
    onClose()
  }
  return (
    <Dialog open={target !== null} onOpenChange={close}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{target ? t("{name} başka bir cihaz gibi olsun", { name: target }) : t("Şu cihaz gibi yap")}</DialogTitle>
          <DialogDescription className="text-pretty">
            {step.kind === "pick"
              ? t("Seçtiğin cihazın etiketlerini, gruplarını, kurallarını ve çıkış iznini öneri olarak getiriyoruz. İstemediklerinin işaretini kaldır; hiçbir şey sen imzalamadan değişmez.")
              : t("Değişikliği kontrol et ve kök anahtarınla imzala.")}
          </DialogDescription>
        </DialogHeader>
        {target && step.kind === "pick" ? (
          <PickStep target={target} onCancel={() => close(false)} onNext={(payload) => setStep({ kind: "sign", payload })} />
        ) : null}
        {target && step.kind === "sign" ? (
          <SignChange
            endpoint="/api/p02/devices/like"
            payload={step.payload}
            confirmLabel={t("İmzala ve uygula")}
            onBack={() => setStep({ kind: "pick" })}
            onCancel={() => close(false)}
            onDone={() => close(false)}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

function PickStep({ target, onCancel, onNext }: { target: string; onCancel: () => void; onNext: (payload: Record<string, unknown>) => void }) {
  const { t } = useI18n()
  const { data: devices } = useSWR<DevicesResponse>("/api/devices", fetcher)
  const [source, setSource] = useState("")
  const candidates = (devices?.devices ?? []).filter((d) => d.name !== target)

  return (
    <div className="flex flex-col gap-5">
      <Field>
        <FieldLabel htmlFor="like-source">{t("Örnek alınacak cihaz")}</FieldLabel>
        <NativeSelect id="like-source" value={source} onChange={(e) => setSource(e.target.value)} disabled={!devices}>
          <option value="">{t("Seç")}</option>
          {candidates.map((d) => (
            <option key={d.name} value={d.name}>
              {d.name}
            </option>
          ))}
        </NativeSelect>
      </Field>
      {source ? (
        <Suggestion key={source} source={source} target={target} onCancel={onCancel} onNext={onNext} />
      ) : (
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onCancel}>
            {t("Vazgeç")}
          </Button>
          <Button type="button" disabled>
            {t("Değişikliği göster")}
          </Button>
        </DialogFooter>
      )}
    </div>
  )
}

interface SuggestionProps {
  source: string
  target: string
  onCancel: () => void
  onNext: (payload: Record<string, unknown>) => void
}

function Suggestion({ source, target, onCancel, onNext }: SuggestionProps) {
  const { t } = useI18n()
  const key = `/api/p02/devices/like?source=${encodeURIComponent(source)}&target=${encodeURIComponent(target)}`
  const { data, error } = useSWR<LikeSuggestion>(key, fetcher, { revalidateOnFocus: false })
  const [tagText, setTagText] = useState<string | null>(null)
  const [groupsOff, setGroupsOff] = useState<Set<string>>(new Set())
  const [rulesOff, setRulesOff] = useState<Set<number>>(new Set())
  const [exitUser, setExitUser] = useState(true)
  const [tagError, setTagError] = useState<string | null>(null)

  if (error) {
    return (
      <>
        <Alert variant="destructive">
          <AlertDescription>{errorMessage(error)}</AlertDescription>
        </Alert>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onCancel}>
            {t("Vazgeç")}
          </Button>
        </DialogFooter>
      </>
    )
  }
  if (!data) {
    return (
      <div className="flex flex-col gap-2" aria-busy="true" aria-label={t("Öneri hazırlanıyor")}>
        <Skeleton className="h-4 w-1/2" />
        <Skeleton className="h-24 w-full" />
      </div>
    )
  }

  const groups = data.groups ?? []
  const rules = data.rules ?? []
  const tags = tagText ?? (data.tags ?? []).join(", ")
  const nothing = groups.length === 0 && rules.length === 0 && (data.tags ?? []).length === 0 && !data.exitUser

  function toggle<T>(set: Set<T>, value: T, on: boolean): Set<T> {
    const next = new Set(set)
    if (on) next.delete(value)
    else next.add(value)
    return next
  }

  function next() {
    const parsed = tagTextSchema.safeParse(tags)
    if (!parsed.success) {
      setTagError(parsed.error.issues[0]?.message ?? msg("Etiketler geçersiz"))
      return
    }
    onNext({
      source,
      target,
      tags: parseTagText(tags),
      groups: groups.filter((g) => !groupsOff.has(g)),
      rules: rules.map((r) => r.index).filter((i) => !rulesOff.has(i)),
      exitUser: data !== undefined && data.exitUser && exitUser,
    })
  }

  return (
    <>
      {nothing ? (
        <p className="rounded-lg border px-4 py-6 text-center text-sm text-muted-foreground text-pretty">
          {t("{name} cihazında aktarılacak etiket, grup, kural veya çıkış izni yok.", { name: source })}
        </p>
      ) : (
        <FieldGroup>
          <Field data-invalid={tagError ? true : undefined}>
            <FieldLabel htmlFor="like-tags">{t("Etiketler")}</FieldLabel>
            <Input
              id="like-tags"
              autoComplete="off"
              spellCheck={false}
              className="font-mono"
              value={tags}
              onChange={(e) => {
                setTagText(e.target.value)
                setTagError(null)
              }}
              aria-invalid={tagError ? true : undefined}
            />
            <FieldDescription>{t("Önerilen etiketler; ekleyip çıkarabilirsin. Virgülle ayır, en fazla {max}.", { max: MAX_TAGS })}</FieldDescription>
            {tagError ? <FieldError>{tagError}</FieldError> : null}
          </Field>
          {groups.length > 0 ? (
            <FieldSet>
              <FieldLegend variant="label">{t("Gruplar")}</FieldLegend>
              {groups.map((g) => (
                <CheckRow key={g} checked={!groupsOff.has(g)} onChange={(on) => setGroupsOff((s) => toggle(s, g, on))}>
                  <span className="font-mono text-[0.8125rem]">{g}</span>
                </CheckRow>
              ))}
            </FieldSet>
          ) : null}
          {rules.length > 0 ? (
            <FieldSet>
              <FieldLegend variant="label">{t("Kurallar")}</FieldLegend>
              <FieldDescription>{t("Kaynak cihazın adı geçen kurallar; yeni cihaz da bu kurallara eklenir.")}</FieldDescription>
              {rules.map((r) => (
                <CheckRow key={r.index} checked={!rulesOff.has(r.index)} onChange={(on) => setRulesOff((s) => toggle(s, r.index, on))}>
                  <span className="flex min-w-0 flex-col">
                    <span className="font-mono text-[0.8125rem] break-all">{r.text}</span>
                    {r.description ? <span className="text-sm text-muted-foreground">{r.description}</span> : null}
                  </span>
                </CheckRow>
              ))}
            </FieldSet>
          ) : null}
          {data.exitUser ? (
            <CheckRow checked={exitUser} onChange={setExitUser}>
              {t("Çıkış düğümü kullanabilsin")}
            </CheckRow>
          ) : null}
        </FieldGroup>
      )}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          {t("Vazgeç")}
        </Button>
        <Button type="button" onClick={next}>
          {t("Değişikliği göster")}
        </Button>
      </DialogFooter>
    </>
  )
}

function CheckRow({ checked, onChange, children }: { checked: boolean; onChange: (on: boolean) => void; children: React.ReactNode }) {
  return (
    <label className="flex items-start gap-2.5 text-sm">
      <Checkbox className="mt-0.5" checked={checked} onCheckedChange={(v) => onChange(v === true)} />
      {children}
    </label>
  )
}
