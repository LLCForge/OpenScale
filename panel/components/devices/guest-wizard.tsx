"use client"

import { useState } from "react"
import useSWR from "swr"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"

import { CodeLine } from "@/components/copy-field"
import { NativeSelect } from "@/components/native-select"
import { radioGroupKeyDown } from "@/components/settings/radio-keys"
import { SignChange, type SignedResponse } from "@/components/sign-change"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { fetcher } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { DevicesResponse } from "@/lib/types"
import { cn } from "@/lib/utils"

// Guest wizard (#368): an invite and a time-limited rule, signed together
// in one version. The guest's device reaches only the chosen device and
// service until the time runs out.

const kinds = [
  { value: "ssh", label: "SSH" },
  { value: "rdesk", label: msg("Uzak masaüstü") },
  { value: "files", label: msg("Dosya gönderme") },
  { value: "port", label: msg("Tek port") },
] as const

type Kind = (typeof kinds)[number]["value"]

const durations = [
  { hours: 2, label: msg("2 saat") },
  { hours: 8, label: msg("8 saat") },
  { hours: 24, label: msg("1 gün") },
  { hours: 72, label: msg("3 gün") },
  { hours: 168, label: msg("7 gün") },
]

const schema = z.object({
  label: z.string().trim().max(60, msg("En fazla 60 karakter")),
  target: z.string().min(1, msg("Hedef cihazı seç")),
  users: z.string().trim().max(200, msg("Çok uzun")),
  protocol: z.enum(["tcp", "udp"]),
  port: z.string().trim(),
  inviteHours: z.number({ message: msg("Sayı gir") }).int().min(1, msg("En az 1 saat")).max(168, msg("En fazla 168 saat")),
})
type Values = z.infer<typeof schema>

type Step = { kind: "form" } | { kind: "sign"; payload: Record<string, unknown> } | { kind: "done"; code: string; expiresAt: string; until: string }

export function GuestWizard({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useI18n()
  const [step, setStep] = useState<Step>({ kind: "form" })
  function close(v: boolean) {
    if (!v) setStep({ kind: "form" })
    onOpenChange(v)
  }
  function signed(res: SignedResponse) {
    const code = typeof res.code === "string" ? res.code : ""
    const expiresAt = typeof res.expiresAt === "string" ? res.expiresAt : ""
    const until = typeof res.ruleUntil === "string" ? res.ruleUntil : ""
    if (code) setStep({ kind: "done", code, expiresAt, until })
    else close(false)
  }
  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{step.kind === "done" ? t("Konuk daveti hazır") : t("Konuk ekle")}</DialogTitle>
          <DialogDescription className="text-pretty">
            {step.kind === "form" && t("Konuğun cihazı yalnızca seçtiğin cihazın seçtiğin hizmetine, seçtiğin süre boyunca erişebilir. Süre dolunca kural çalışmaz.")}
            {step.kind === "sign" && t("Davet ve süreli kural aynı imzayla yayımlanır. Değişikliği kontrol et.")}
            {step.kind === "done" && t("Kodu konuğa ver. Cihazını onaylarken 'geçici' seçili kalsın; cihaz da konuk süresi bitince düşer.")}
          </DialogDescription>
        </DialogHeader>
        {open && step.kind === "form" ? <GuestForm onCancel={() => close(false)} onNext={(payload) => setStep({ kind: "sign", payload })} /> : null}
        {open && step.kind === "sign" ? (
          <SignChange
            endpoint="/api/p02/guest"
            payload={step.payload}
            confirmLabel={t("İmzala ve davet oluştur")}
            onBack={() => setStep({ kind: "form" })}
            onCancel={() => close(false)}
            onSigned={signed}
            onDone={() => undefined}
          />
        ) : null}
        {step.kind === "done" ? (
          <div className="flex flex-col gap-3">
            <CodeLine value={step.code} label={t("Davet kodunu kopyala")} secret />
            <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
              {step.expiresAt ? `${t("Davet {date} tarihine kadar kullanılabilir.", { date: formatDateTime(step.expiresAt) })} ` : ""}
              {step.until ? t("Konuk erişimi {date} tarihinde biter.", { date: formatDateTime(step.until) }) : ""}
            </p>
            <DialogFooter>
              <Button onClick={() => close(false)}>{t("Tamam")}</Button>
            </DialogFooter>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

function GuestForm({ onCancel, onNext }: { onCancel: () => void; onNext: (payload: Record<string, unknown>) => void }) {
  const { t } = useI18n()
  const { data } = useSWR<DevicesResponse>("/api/devices", fetcher)
  const [kind, setKind] = useState<Kind>("ssh")
  const [hours, setHours] = useState(8)
  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: { label: "", target: "", users: "", protocol: "tcp", port: "", inviteHours: 1 },
  })
  const { errors } = form.formState

  function submit(v: Values) {
    if (v.inviteHours > hours) {
      form.setError("inviteHours", { message: msg("Davet, konuk süresinden uzun olamaz") })
      return
    }
    const base = { label: v.label, target: v.target, hours, inviteHours: v.inviteHours }
    if (kind === "port") {
      const port = Number(v.port)
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        form.setError("port", { message: msg("Port 1 ile 65535 arasında olmalı") })
        return
      }
      onNext({ ...base, protocol: v.protocol, port: String(port) })
      return
    }
    const users = v.users
      .split(/[\s,]+/)
      .map((u) => u.trim())
      .filter(Boolean)
    if (kind === "ssh" && users.length === 0) {
      form.setError("users", { message: msg("Konuğun girebileceği en az bir hesap yaz") })
      return
    }
    onNext({ ...base, service: kind, ...(kind === "ssh" ? { users } : {}) })
  }

  return (
    <form onSubmit={form.handleSubmit(submit)} noValidate className="flex flex-col gap-6">
      <FieldGroup>
        <Field data-invalid={errors.label ? true : undefined}>
          <FieldLabel htmlFor="guest-label">{t("Konuk (isteğe bağlı)")}</FieldLabel>
          <Input id="guest-label" autoComplete="off" placeholder={t("Teknik servis")} {...form.register("label")} />
          <FieldDescription>{t("Kuralın açıklamasına yazılır; kimin için açıldığını hatırlatır.")}</FieldDescription>
          <FieldError errors={[errors.label]} />
        </Field>
        <Field data-invalid={errors.target ? true : undefined}>
          <FieldLabel htmlFor="guest-target">{t("Erişeceği cihaz")}</FieldLabel>
          <NativeSelect id="guest-target" aria-invalid={errors.target ? true : undefined} {...form.register("target")}>
            <option value="">{t("Seç")}</option>
            {(data?.devices ?? []).map((d) => (
              <option key={d.name} value={d.name}>
                {d.name}
              </option>
            ))}
          </NativeSelect>
          <FieldError errors={[errors.target]} />
        </Field>
        <Field>
          <FieldLabel id="guest-kind-label">{t("Hizmet")}</FieldLabel>
          <ChoiceGroup labelledBy="guest-kind-label" value={kind} options={kinds} onChange={setKind} />
        </Field>
        {kind === "ssh" ? (
          <Field data-invalid={errors.users ? true : undefined}>
            <FieldLabel htmlFor="guest-users">{t("Hesaplar")}</FieldLabel>
            <Input id="guest-users" autoComplete="off" spellCheck={false} className="font-mono" placeholder={t("destek")} {...form.register("users")} />
            <FieldDescription>{t("Konuğun SSH ile girebileceği hesaplar; virgülle ayır.")}</FieldDescription>
            <FieldError errors={[errors.users]} />
          </Field>
        ) : null}
        {kind === "port" ? (
          <div className="flex gap-3">
            <Field className="w-28">
              <FieldLabel htmlFor="guest-protocol">{t("Protokol")}</FieldLabel>
              <NativeSelect id="guest-protocol" {...form.register("protocol")}>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
              </NativeSelect>
            </Field>
            <Field data-invalid={errors.port ? true : undefined} className="w-32">
              <FieldLabel htmlFor="guest-port">Port</FieldLabel>
              <Input id="guest-port" inputMode="numeric" className="font-mono" placeholder="8080" {...form.register("port")} />
              <FieldError errors={[errors.port]} />
            </Field>
          </div>
        ) : null}
        <Field>
          <FieldLabel id="guest-hours-label">{t("Konuk erişimi süresi")}</FieldLabel>
          <ChoiceGroup
            labelledBy="guest-hours-label"
            value={String(hours)}
            options={durations.map((d) => ({ value: String(d.hours), label: d.label }))}
            onChange={(v) => setHours(Number(v))}
          />
        </Field>
        <Field data-invalid={errors.inviteHours ? true : undefined}>
          <FieldLabel htmlFor="guest-invite-hours">{t("Davet kodu kaç saat geçerli")}</FieldLabel>
          <Input id="guest-invite-hours" type="number" min={1} max={168} className="w-24" {...form.register("inviteHours", { valueAsNumber: true })} />
          <FieldDescription>{t("Konuk kodu bu süre içinde kullanmalı; kısa süre daha güvenli.")}</FieldDescription>
          <FieldError errors={[errors.inviteHours]} />
        </Field>
      </FieldGroup>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          {t("Vazgeç")}
        </Button>
        <Button type="submit">{t("Değişikliği göster")}</Button>
      </DialogFooter>
    </form>
  )
}

interface ChoiceGroupProps<T extends string> {
  labelledBy: string
  value: T
  options: readonly { value: T; label: string }[]
  onChange: (value: T) => void
}

function ChoiceGroup<T extends string>({ labelledBy, value, options, onChange }: ChoiceGroupProps<T>) {
  const { t } = useI18n()
  return (
    <div role="radiogroup" aria-labelledby={labelledBy} onKeyDown={radioGroupKeyDown} className="flex w-fit max-w-full flex-wrap rounded-lg border bg-card p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          tabIndex={value === o.value ? 0 : -1}
          onClick={() => onChange(o.value)}
          className={cn(
            "rounded-md px-3 py-1.5 text-sm transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50",
            value === o.value ? "bg-secondary font-medium text-foreground" : "text-muted-foreground hover:text-foreground"
          )}
        >
          {t(o.label)}
        </button>
      ))}
    </div>
  )
}
