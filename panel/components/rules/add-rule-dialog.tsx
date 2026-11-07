"use client"

import { useState } from "react"
import { Controller, useForm, useWatch } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"

import { ReferencePicker, type ReferenceChoices } from "@/components/rules/reference-picker"
import { radioGroupKeyDown } from "@/components/settings/radio-keys"
import { SignChange } from "@/components/sign-change"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { formatDateTime } from "@/lib/format"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import { textWithin } from "@/lib/references"
import type { Protocol, Rule, RuleAction } from "@/lib/types"

const portPattern = /^([1-9]\d{0,4})(-([1-9]\d{0,4}))?$/

/** Protocol numbers the server only accepts as names. */
const namedNumbers: Record<string, string> = { "1": "icmp", "6": "tcp", "17": "udp", "58": "icmp" }

const MAX_REFS = 64

function validPortEntry(entry: string): boolean {
  const m = portPattern.exec(entry)
  if (!m) return false
  const start = Number(m[1])
  const end = m[3] ? Number(m[3]) : start
  return start >= 1 && end <= 65535 && start <= end
}

function splitPorts(value: string): string[] {
  return value
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p.length > 0)
}

type ProtocolChoice = Protocol | "number"

/** One-time access windows close by themselves after at most 30 days (#104). */
const MAX_WINDOW_MINUTES = 43200

/** An allow rule from every device to every device on every port (#112). */
function isBroadRule(v: { action: string; from: string[]; to: string[]; protocol: string; ports: string }): boolean {
  if (v.action !== "allow" || !v.from.includes("*") || !v.to.includes("*")) return false
  if (v.protocol === "any") return true
  if (v.protocol !== "tcp" && v.protocol !== "udp") return false
  return splitPorts(v.ports).some((p) => p === "1-65535")
}

const ruleSchema = z
  .object({
    action: z.enum(["allow", "deny"]),
    from: z.array(z.string()).min(1, msg("En az bir kaynak seç")).max(MAX_REFS, { error: () => tx("En fazla {count} kaynak", { count: MAX_REFS }) }),
    to: z.array(z.string()).min(1, msg("En az bir hedef seç")).max(MAX_REFS, { error: () => tx("En fazla {count} hedef", { count: MAX_REFS }) }),
    protocol: z.enum(["tcp", "udp", "icmp", "any", "number"]),
    protocolNumber: z.string().max(3, msg("0 ile 255 arası bir sayı gir")),
    ports: z.string().max(400, msg("Çok uzun")),
    description: textWithin(256),
    bidirectional: z.boolean(),
    windowMinutes: z.string().max(5, msg("En fazla 43200 dakika")),
    clearWindow: z.boolean(),
    confirmBroad: z.boolean(),
  })
  .superRefine((v, ctx) => {
    const minutes = v.windowMinutes.trim()
    if (minutes !== "" && (!/^\d{1,5}$/.test(minutes) || Number(minutes) < 1 || Number(minutes) > MAX_WINDOW_MINUTES)) {
      ctx.addIssue({ code: "custom", path: ["windowMinutes"], message: msg("1 ile 43200 dakika (30 gün) arası bir sayı gir") })
    }
    if (isBroadRule(v) && !v.confirmBroad) {
      ctx.addIssue({ code: "custom", path: ["confirmBroad"], message: msg("Herkesten herkese erişim açan kural açık onay ister") })
    }
    if (v.protocol === "number") {
      const n = v.protocolNumber.trim()
      if (!/^\d{1,3}$/.test(n) || Number(n) > 255) {
        ctx.addIssue({ code: "custom", path: ["protocolNumber"], message: msg("0 ile 255 arası bir IANA protokol numarası gir") })
      } else {
        const name = namedNumbers[String(Number(n))]
        if (name) {
          ctx.addIssue({
            code: "custom",
            path: ["protocolNumber"],
            message: tx('{number} numarası yerine "{name}" seçeneğini kullan', { number: Number(n), name: name.toUpperCase() }),
          })
        }
      }
    }
    const ports = splitPorts(v.ports)
    if (v.protocol === "tcp" || v.protocol === "udp") {
      if (ports.length === 0) {
        ctx.addIssue({ code: "custom", path: ["ports"], message: msg("TCP ve UDP için en az bir port gir") })
      } else if (ports.length > 32 || !ports.every(validPortEntry)) {
        ctx.addIssue({ code: "custom", path: ["ports"], message: msg("Portlar 1-65535 arası olmalı, ör. 3389 veya 5900-5910") })
      }
    } else if (ports.length > 0) {
      ctx.addIssue({ code: "custom", path: ["ports"], message: msg("Port yalnızca TCP ve UDP için girilir") })
    }
  })

type RuleForm = z.infer<typeof ruleSchema>

const protocols: { value: ProtocolChoice; label: string }[] = [
  { value: "tcp", label: "TCP" },
  { value: "udp", label: "UDP" },
  { value: "icmp", label: "ICMP" },
  { value: "any", label: msg("Tümü") },
  { value: "number", label: msg("Numara") },
]

const actions: { value: RuleAction; label: string }[] = [
  { value: "allow", label: msg("İzin ver") },
  { value: "deny", label: msg("rule-action|Reddet") },
]

const presets: { label: string; protocol: Protocol; ports: string }[] = [
  { label: msg("Uzak Masaüstü (RDP)"), protocol: "tcp", ports: "3389" },
  { label: "SSH", protocol: "tcp", ports: "22" },
  { label: "VNC", protocol: "tcp", ports: "5900" },
  { label: msg("Dosya paylaşımı (SMB)"), protocol: "tcp", ports: "445" },
]

interface AddRuleDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  choices: ReferenceChoices
  /** A traffic rule to change in place (one signature); omitted to add a new rule. */
  editing?: Rule | null
}

const namedProtocols = new Set(["tcp", "udp", "icmp", "any"])

/** Form values for a new rule, or for an existing traffic rule being edited. */
function initialValues(rule: Rule | null | undefined): RuleForm {
  if (!rule) {
    return {
      action: "allow",
      from: [],
      to: [],
      protocol: "tcp",
      protocolNumber: "",
      ports: "",
      description: "",
      bidirectional: false,
      windowMinutes: "",
      clearWindow: false,
      confirmBroad: false,
    }
  }
  const named = namedProtocols.has(rule.protocol)
  return {
    action: rule.action,
    from: [...rule.from],
    to: [...rule.to],
    protocol: named ? (rule.protocol as Protocol) : "number",
    protocolNumber: named ? "" : rule.protocol,
    ports: rule.ports.join(", "),
    description: rule.description,
    bidirectional: rule.bidirectional ?? false,
    windowMinutes: "",
    clearWindow: false,
    confirmBroad: false,
  }
}

export function AddRuleDialog({ open, onOpenChange, choices, editing }: AddRuleDialogProps) {
  const { t } = useI18n()
  const [payload, setPayload] = useState<Record<string, unknown> | null>(null)

  function handleOpenChange(next: boolean) {
    if (!next) setPayload(null)
    onOpenChange(next)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{editing ? t("Kural {number}: düzenle", { number: editing.index + 1 }) : t("Kural ekle")}</DialogTitle>
          <DialogDescription>
            {payload
              ? t("Değişikliği kontrol et ve kök anahtarınla imzala.")
              : editing
                ? t("Kural yerinde değişir; sırası ve açık/kapalı durumu korunur. Tek imza yeter.")
                : t("Hangi cihazların nereye, hangi porttan bağlanabileceğini seç.")}
          </DialogDescription>
        </DialogHeader>
        {open && !payload ? (
          <RuleFormStep
            key={editing ? `edit-${editing.index}-${editing.text}` : "new"}
            choices={choices}
            editing={editing ?? null}
            onNext={(values) => setPayload(editing ? { ...values, index: editing.index } : values)}
          />
        ) : null}
        {open && payload ? (
          <SignChange
            endpoint={editing ? "/api/rules/edit" : "/api/rules"}
            payload={payload}
            confirmLabel={editing ? t("İmzala ve kaydet") : t("İmzala ve ekle")}
            onBack={() => setPayload(null)}
            onDone={() => handleOpenChange(false)}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

interface RuleFormStepProps {
  choices: ReferenceChoices
  editing: Rule | null
  onNext: (payload: Record<string, unknown>) => void
}

function RuleFormStep({ choices, editing, onNext }: RuleFormStepProps) {
  const { t } = useI18n()
  const form = useForm<RuleForm>({
    resolver: zodResolver(ruleSchema),
    defaultValues: initialValues(editing),
  })
  const { errors } = form.formState
  const protocol = useWatch({ control: form.control, name: "protocol" })
  const action = useWatch({ control: form.control, name: "action" })
  const watched = useWatch({ control: form.control })
  const hasPorts = protocol === "tcp" || protocol === "udp"
  const broad = isBroadRule({
    action: watched.action ?? "allow",
    from: watched.from ?? [],
    to: watched.to ?? [],
    protocol: watched.protocol ?? "tcp",
    ports: watched.ports ?? "",
  })

  function submit(values: RuleForm) {
    const minutes = values.windowMinutes.trim()
    onNext({
      action: values.action,
      from: values.from,
      to: values.to,
      protocol: values.protocol === "number" ? String(Number(values.protocolNumber.trim())) : values.protocol,
      ports: splitPorts(values.ports),
      description: values.description.trim(),
      bidirectional: values.bidirectional,
      windowMinutes: minutes === "" ? 0 : Number(minutes),
      confirmBroad: values.confirmBroad,
      ...(editing ? { clearWindow: values.clearWindow && minutes === "" } : {}),
    })
  }

  function chooseProtocol(value: ProtocolChoice) {
    form.setValue("protocol", value, { shouldValidate: true })
    if (value !== "tcp" && value !== "udp") form.setValue("ports", "", { shouldValidate: true })
    if (value !== "number") form.setValue("protocolNumber", "", { shouldValidate: true })
  }

  return (
    <form onSubmit={form.handleSubmit(submit)} noValidate className="flex flex-col gap-4">
      <FieldGroup>
        <FieldSet>
          <FieldLegend variant="label">{t("Eylem")}</FieldLegend>
          <div role="radiogroup" aria-label={t("Eylem")} className="flex flex-wrap gap-2" onKeyDown={radioGroupKeyDown}>
            {actions.map((a) => (
              <Button
                key={a.value}
                type="button"
                role="radio"
                aria-checked={action === a.value}
                tabIndex={action === a.value ? 0 : -1}
                variant={action === a.value ? (a.value === "deny" ? "destructive" : "default") : "outline"}
                size="sm"
                onClick={() => form.setValue("action", a.value, { shouldValidate: true })}
              >
                {t(a.label)}
              </Button>
            ))}
          </div>
          <FieldDescription className="text-pretty">
            {t(
              "Reddet kuralı her zaman izinden önce gelir: bir izin kuralı aynı trafiği kapsasa da reddedilir. Varsayılan zaten her şeyi reddettiği için reddet kuralı yalnızca geniş bir izinden istisna açmak için gerekir."
            )}
          </FieldDescription>
        </FieldSet>
        <Controller
          control={form.control}
          name="from"
          render={({ field }) => (
            <ReferencePicker
              legend={t("Kaynak (bağlanan)")}
              choices={choices}
              value={field.value}
              onChange={field.onChange}
              allowAll
              allowGroups
              max={MAX_REFS}
              error={errors.from?.message}
            />
          )}
        />
        <Controller
          control={form.control}
          name="to"
          render={({ field }) => (
            <ReferencePicker
              legend={t("Hedef (bağlanılan)")}
              choices={choices}
              value={field.value}
              onChange={field.onChange}
              allowAll
              allowGroups
              max={MAX_REFS}
              error={errors.to?.message}
            />
          )}
        />
        <Field>
          <FieldLabel>{t("Hazır seçimler")}</FieldLabel>
          <div className="flex flex-wrap gap-2">
            {presets.map((p) => (
              <Button
                key={p.label}
                type="button"
                variant="outline"
                size="sm"
                onClick={() => {
                  chooseProtocol(p.protocol)
                  form.setValue("ports", p.ports, { shouldValidate: true })
                  if (!form.getValues("description")) form.setValue("description", t(p.label))
                }}
              >
                {t(p.label)}
              </Button>
            ))}
          </div>
        </Field>
        <FieldSet>
          <FieldLegend variant="label">{t("Protokol")}</FieldLegend>
          <div role="radiogroup" aria-label={t("Protokol")} className="flex flex-wrap gap-2" onKeyDown={radioGroupKeyDown}>
            {protocols.map((p) => (
              <Button
                key={p.value}
                type="button"
                role="radio"
                aria-checked={protocol === p.value}
                tabIndex={protocol === p.value ? 0 : -1}
                variant={protocol === p.value ? "default" : "outline"}
                size="sm"
                onClick={() => chooseProtocol(p.value)}
              >
                {t(p.label)}
              </Button>
            ))}
          </div>
        </FieldSet>
        {protocol === "number" ? (
          <Field data-invalid={errors.protocolNumber ? true : undefined}>
            <FieldLabel htmlFor="rule-proto-number">{t("IANA protokol numarası")}</FieldLabel>
            <Input
              id="rule-proto-number"
              inputMode="numeric"
              className="font-mono"
              placeholder="47"
              autoComplete="off"
              aria-invalid={errors.protocolNumber ? true : undefined}
              {...form.register("protocolNumber")}
            />
            <FieldDescription>{t("0-255 arası, ör. 47 (GRE) veya 50 (ESP). 1, 6, 17 ve 58 için adları (ICMP, TCP, UDP) kullan.")}</FieldDescription>
            <FieldError errors={[errors.protocolNumber]} />
          </Field>
        ) : null}
        <Field data-invalid={errors.ports ? true : undefined} data-disabled={hasPorts ? undefined : true}>
          <FieldLabel htmlFor="rule-ports">{t("Portlar")}</FieldLabel>
          <Input
            id="rule-ports"
            className="font-mono"
            placeholder={hasPorts ? t("3389 veya 5900-5910, 22") : t("Port yalnızca TCP ve UDP için")}
            disabled={!hasPorts}
            aria-invalid={errors.ports ? true : undefined}
            {...form.register("ports")}
          />
          <FieldError errors={[errors.ports]} />
        </Field>
        <Field data-invalid={errors.description ? true : undefined}>
          <FieldLabel htmlFor="rule-description">{t("Açıklama")}</FieldLabel>
          <Input id="rule-description" placeholder={t("Uzak masaüstü")} aria-invalid={errors.description ? true : undefined} {...form.register("description")} />
          <FieldError errors={[errors.description]} />
        </Field>
        <Controller
          control={form.control}
          name="bidirectional"
          render={({ field }) => (
            <Field orientation="horizontal">
              <Checkbox id="rule-bidirectional" checked={field.value} onCheckedChange={(v) => field.onChange(v === true)} />
              <FieldLabel htmlFor="rule-bidirectional">{t("Çift yönlü: hedef de kaynağa aynı protokol ve portla bağlanabilsin")}</FieldLabel>
            </Field>
          )}
        />
        <Field data-invalid={errors.windowMinutes ? true : undefined}>
          <FieldLabel htmlFor="rule-window">{t("Süreli erişim (dakika)")}</FieldLabel>
          <Input
            id="rule-window"
            inputMode="numeric"
            className="font-mono"
            placeholder={t("Boş: süresiz")}
            autoComplete="off"
            aria-invalid={errors.windowMinutes ? true : undefined}
            {...form.register("windowMinutes")}
          />
          <FieldDescription className="text-pretty">
            {editing?.notAfter
              ? t("Bu kural şu an {date} tarihinde kapanıyor. Boş bırakırsan bu bitiş korunur; doldurursan imzadan bu kadar dakika sonra kapanır.", {
                  date: formatDateTime(editing.notAfter),
                })
              : t("Doluysa kural imzadan bu kadar dakika sonra kendiliğinden kapanır (tek seferlik erişim penceresi). Her cihaz kendi saatine göre uygular.")}
          </FieldDescription>
          <FieldError errors={[errors.windowMinutes]} />
        </Field>
        {editing?.notAfter ? (
          <Controller
            control={form.control}
            name="clearWindow"
            render={({ field }) => (
              <Field orientation="horizontal">
                <Checkbox id="rule-clear-window" checked={field.value} onCheckedChange={(v) => field.onChange(v === true)} />
                <FieldLabel htmlFor="rule-clear-window">{t("Süre sınırını kaldır: kural süresiz geçerli olsun")}</FieldLabel>
              </Field>
            )}
          />
        ) : null}
        {editing?.scheduled ? (
          <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
            {t("Bu kuralın saat veya başlangıç sınırı var; burada değişmez. Değiştirmek için metin düzenleyiciyi kullan.")}
          </p>
        ) : null}
        {broad ? (
          <Controller
            control={form.control}
            name="confirmBroad"
            render={({ field }) => (
              <Field orientation="horizontal" data-invalid={errors.confirmBroad ? true : undefined}>
                <Checkbox
                  id="rule-confirm-broad"
                  checked={field.value}
                  aria-invalid={errors.confirmBroad ? true : undefined}
                  onCheckedChange={(v) => field.onChange(v === true)}
                />
                <FieldLabel htmlFor="rule-confirm-broad" className="text-pretty">
                  {t("Bu kuralın bütün cihazlardan bütün cihazlara erişim açtığını ve varsayılan reddet ilkesini fiilen kapattığını anlıyorum")}
                </FieldLabel>
                <FieldError errors={[errors.confirmBroad]} />
              </Field>
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
