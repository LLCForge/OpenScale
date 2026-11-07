"use client"

import { useState } from "react"
import { Controller, useForm, useWatch } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { TriangleAlert } from "lucide-react"
import { z } from "zod"

import { ReferencePicker, type ReferenceChoices } from "@/components/rules/reference-picker"
import { SignChange } from "@/components/sign-change"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import type { RuleService } from "@/lib/apps"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import { referenceLabel, textWithin } from "@/lib/references"
import type { Rule, RuleAction } from "@/lib/types"

const MAX_REFS = 64
const MAX_USERS = 32
const userPattern = /^[a-z_][a-z0-9_.-]{0,31}$/
const folderPattern = /^[a-z0-9][a-z0-9-]{0,62}$/

const services: { value: RuleService; label: string; help: string }[] = [
  {
    value: "ssh",
    label: "SSH",
    help: msg(
      "Kaynak cihazlar hedefe gömülü SSH sunucusuyla (tünel içi port 4022) girebilir. Yalnızca listedeki yerel kullanıcılar; root ayrıca izin ister. Windows hedeflerde servis sistem hesabıyla çalışır: kullanıcı olarak system yazılmadıkça giriş reddedilir."
    ),
  },
  { value: "files", label: msg("Dosya gönderme"), help: msg("Kaynak cihazlar hedefin gelen kutusuna dosya gönderebilir; hedefte kabul edilmesi gerekir.") },
  {
    value: "wake",
    label: msg("Uyandırma"),
    help: msg("Kaynak cihazlar hedefi Wake-on-LAN ile uyandırabilir. İstek, hedefin yerel ağındaki bir aracı cihaza gider; aracı orada magic paketi yayınlar."),
  },
  { value: "speedtest", label: msg("Hız testi"), help: msg("Kaynak cihazlar hedefle tünel içi hız testi yapabilir.") },
  {
    value: "rdesk",
    label: msg("Uzak masaüstü"),
    help: msg("Kaynak cihazlar hedefin ekranını izleyebilir (tünel içi port 4047). Kontrol ve onaysız bağlanma ayrı izinlerdir; hedefte her oturumda gösterge çıkar."),
  },
  {
    value: "sync",
    label: msg("Eşitleme ve yedek"),
    help: msg(
      "Kaynak cihazlar hedefin paylaştığı klasörleri salt okunur çekebilir ve/veya hedefte şifreli yedek tutabilir (tünel içi port 4050). Hedef yedeklerin içeriğini göremez."
    ),
  },
]

const serviceNames: Record<string, string> = Object.fromEntries(services.map((s) => [s.value, s.label]))

/** Table label of a service rule, in the interface language. */
export function serviceRuleLabel(service: string): string {
  const name = serviceNames[service]
  return tx("Servis: {name}", { name: name ? tx(name) : service })
}

/** The permissions of a service rule, spelled out in the interface language. */
export function serviceRuleDetail(r: Rule): string {
  const parts: string[] = []
  if (r.users && r.users.length > 0) parts.push(tx("kullanıcılar: {users}", { users: r.users.join(", ") }))
  if (r.allowRoot) parts.push("root")
  if (r.allowForward) parts.push(tx("port yönlendirme"))
  if (r.via && r.via.length > 0) parts.push(tx("aracı: {via}", { via: r.via.map(referenceLabel).join(", ") }))
  if (r.service === "rdesk" && r.action !== "deny") parts.push(r.allowControl ? tx("izleme ve kontrol") : tx("yalnızca izleme"))
  if (r.allowUnattended) parts.push(tx("gözetimsiz (onaysız)"))
  if (r.folders && r.folders.length > 0) parts.push(tx("klasörler (salt okunur): {folders}", { folders: r.folders.join(", ") }))
  if (r.backup) {
    const quota = r.quota ? Math.round(r.quota / 2 ** 30) : 0
    if (quota > 0) {
      parts.push(r.allowPrune ? tx("şifreli yedek (kota {quota} GiB); silebilir", { quota }) : tx("şifreli yedek (kota {quota} GiB); yalnızca ekleme", { quota }))
    } else {
      parts.push(r.allowPrune ? tx("şifreli yedek; silebilir") : tx("şifreli yedek; yalnızca ekleme"))
    }
  }
  return parts.length > 0 ? parts.join("; ") : "-"
}

function splitUsers(value: string): string[] {
  return value
    .split(",")
    .map((u) => u.trim())
    .filter((u) => u.length > 0)
}

const schema = z
  .object({
    action: z.enum(["allow", "deny"]),
    service: z.enum(["ssh", "files", "wake", "speedtest", "rdesk", "sync"]),
    from: z.array(z.string()).min(1, msg("En az bir kaynak seç")).max(MAX_REFS, { error: () => tx("En fazla {count} kaynak", { count: MAX_REFS }) }),
    to: z.array(z.string()).min(1, msg("En az bir hedef seç")).max(MAX_REFS, { error: () => tx("En fazla {count} hedef", { count: MAX_REFS }) }),
    users: z.string().max(600, msg("Çok uzun")),
    allowRoot: z.boolean(),
    allowForward: z.boolean(),
    via: z.array(z.string()).max(MAX_REFS, { error: () => tx("En fazla {count} aracı", { count: MAX_REFS }) }),
    allowControl: z.boolean(),
    allowUnattended: z.boolean(),
    folders: z.string().max(2000, msg("Çok uzun")),
    backup: z.boolean(),
    quotaGiB: z
      .number({ error: msg("Sayı gir; varsayılan için 0") })
      .int(msg("Tam sayı gir"))
      .min(0, msg("Negatif olamaz"))
      .max(1048576, msg("Çok büyük")),
    allowPrune: z.boolean(),
    description: textWithin(256),
  })
  .superRefine((v, ctx) => {
    if (v.action === "deny") return
    if (v.service === "ssh") {
      const users = splitUsers(v.users)
      if (users.length === 0 && !v.allowRoot) {
        ctx.addIssue({ code: "custom", path: ["users"], message: msg("En az bir kullanıcı yaz veya root iznini aç") })
      } else if (users.length > MAX_USERS) {
        ctx.addIssue({ code: "custom", path: ["users"], message: tx("En fazla {count} kullanıcı", { count: MAX_USERS }) })
      } else if (users.includes("root")) {
        ctx.addIssue({ code: "custom", path: ["users"], message: msg("root yazma; aşağıdaki root iznini aç") })
      } else if (!users.every((u) => userPattern.test(u))) {
        ctx.addIssue({ code: "custom", path: ["users"], message: msg("Kullanıcı adları küçük harf, rakam, _ . - içerebilir (ör. ali, deploy, system)") })
      } else if (new Set(users).size !== users.length) {
        ctx.addIssue({ code: "custom", path: ["users"], message: msg("Bir kullanıcı iki kez yazılmış") })
      }
    }
    if (v.service === "sync") {
      const folders = splitUsers(v.folders)
      if (folders.length === 0 && !v.backup) ctx.addIssue({ code: "custom", path: ["folders"], message: msg("En az bir klasör kimliği yaz veya yedek iznini aç") })
      if (!folders.every((f) => folderPattern.test(f))) {
        ctx.addIssue({ code: "custom", path: ["folders"], message: msg("Kimlikler küçük harf, rakam ve tire içerir (ör. belgeler, foto-2026)") })
      }
    }
    if (v.service === "wake") {
      if (v.via.length === 0) ctx.addIssue({ code: "custom", path: ["via"], message: msg("Hedefin yerel ağındaki en az bir aracı cihaz seç") })
      if (v.via.includes("*")) ctx.addIssue({ code: "custom", path: ["via"], message: msg("Aracı olarak tüm cihazlar seçilemez") })
    }
  })

type ServiceForm = z.infer<typeof schema>

interface AddServiceRuleDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  choices: ReferenceChoices
}

/** Adds an application service rule (ADR-0030, ADR-0031). */
export function AddServiceRuleDialog({ open, onOpenChange, choices }: AddServiceRuleDialogProps) {
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
          <DialogTitle>{t("Servis kuralı ekle")}</DialogTitle>
          <DialogDescription>
            {payload
              ? t("Değişikliği kontrol et ve kök anahtarınla imzala.")
              : t(
                  "SSH, dosya gönderme, uyandırma, hız testi, uzak masaüstü veya eşitleme izni. Servis yalnızca bir kural onu bir cihaza açtığında o cihazda dinler."
                )}
          </DialogDescription>
        </DialogHeader>
        {open && !payload ? <ServiceFormStep choices={choices} onNext={setPayload} /> : null}
        {open && payload ? (
          <SignChange
            endpoint="/api/rules"
            payload={payload}
            confirmLabel={t("İmzala ve ekle")}
            onBack={() => setPayload(null)}
            onDone={() => handleOpenChange(false)}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

function ServiceFormStep({ choices, onNext }: { choices: ReferenceChoices; onNext: (payload: Record<string, unknown>) => void }) {
  const { t } = useI18n()
  const form = useForm<ServiceForm>({
    resolver: zodResolver(schema),
    defaultValues: {
      action: "allow",
      service: "ssh",
      from: [],
      to: [],
      users: "",
      allowRoot: false,
      allowForward: false,
      via: [],
      allowControl: false,
      allowUnattended: false,
      folders: "",
      backup: false,
      quotaGiB: 0,
      allowPrune: false,
      description: "",
    },
  })
  const { errors } = form.formState
  const service = useWatch({ control: form.control, name: "service" })
  const action = useWatch({ control: form.control, name: "action" })
  const users = useWatch({ control: form.control, name: "users" })
  const allowRoot = useWatch({ control: form.control, name: "allowRoot" })
  const allowUnattended = useWatch({ control: form.control, name: "allowUnattended" })
  const backup = useWatch({ control: form.control, name: "backup" })
  const deny = action === "deny"
  const powerful = service === "ssh" && !deny && (allowRoot || splitUsers(users).includes("system"))

  function submit(v: ServiceForm) {
    const base = { action: v.action, service: v.service, from: v.from, to: v.to, description: v.description.trim() }
    if (v.action === "deny") {
      onNext(base)
      return
    }
    if (v.service === "ssh") {
      onNext({ ...base, users: splitUsers(v.users), allowRoot: v.allowRoot, allowForward: v.allowForward })
      return
    }
    if (v.service === "wake") {
      onNext({ ...base, via: v.via })
      return
    }
    if (v.service === "rdesk") {
      onNext({ ...base, allowControl: v.allowControl, allowUnattended: v.allowUnattended })
      return
    }
    if (v.service === "sync") {
      onNext({
        ...base,
        folders: splitUsers(v.folders),
        backup: v.backup,
        quota: v.backup && v.quotaGiB > 0 ? v.quotaGiB * 2 ** 30 : 0,
        allowPrune: v.backup && v.allowPrune,
      })
      return
    }
    onNext(base)
  }

  const actions: { value: RuleAction; label: string }[] = [
    { value: "allow", label: t("İzin ver") },
    { value: "deny", label: t("rule-action|Reddet") },
  ]

  return (
    <form onSubmit={form.handleSubmit(submit)} noValidate className="flex flex-col gap-4">
      <FieldGroup>
        <FieldSet>
          <FieldLegend variant="label">{t("Servis")}</FieldLegend>
          <div role="radiogroup" aria-label={t("Servis")} className="flex flex-wrap gap-2">
            {services.map((s) => (
              <Button
                key={s.value}
                type="button"
                role="radio"
                aria-checked={service === s.value}
                variant={service === s.value ? "default" : "outline"}
                size="sm"
                onClick={() => form.setValue("service", s.value, { shouldValidate: true })}
              >
                {t(s.label)}
              </Button>
            ))}
          </div>
          <FieldDescription className="text-pretty">{t(services.find((s) => s.value === service)?.help ?? "")}</FieldDescription>
        </FieldSet>
        <FieldSet>
          <FieldLegend variant="label">{t("Eylem")}</FieldLegend>
          <div role="radiogroup" aria-label={t("Eylem")} className="flex flex-wrap gap-2">
            {actions.map((a) => (
              <Button
                key={a.value}
                type="button"
                role="radio"
                aria-checked={action === a.value}
                variant={action === a.value ? (a.value === "deny" ? "destructive" : "default") : "outline"}
                size="sm"
                onClick={() => form.setValue("action", a.value, { shouldValidate: true })}
              >
                {a.label}
              </Button>
            ))}
          </div>
          <FieldDescription className="text-pretty">{t("Reddet kuralı bu servisi, izin kuralları ne derse desin kapatır.")}</FieldDescription>
        </FieldSet>
        <Controller
          control={form.control}
          name="from"
          render={({ field }) => (
            <ReferencePicker
              legend={t("Kaynak (isteyen)")}
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
              legend={service === "wake" ? t("Hedef (uyandırılacak)") : t("Hedef (servisi sunan)")}
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
        {service === "ssh" && !deny ? (
          <>
            <Field data-invalid={errors.users ? true : undefined}>
              <FieldLabel htmlFor="svc-users">{t("İzinli yerel kullanıcılar")}</FieldLabel>
              <Input
                id="svc-users"
                className="font-mono"
                placeholder={t("ali, deploy (Windows için: system)")}
                autoComplete="off"
                aria-invalid={errors.users ? true : undefined}
                {...form.register("users")}
              />
              <FieldDescription>{t("Virgülle ayır. Joker yoktur; her hesap açıkça yazılır.")}</FieldDescription>
              <FieldError errors={[errors.users]} />
            </Field>
            <Controller
              control={form.control}
              name="allowRoot"
              render={({ field }) => (
                <Field orientation="horizontal">
                  <Checkbox id="svc-root" checked={field.value} onCheckedChange={(v) => field.onChange(v === true)} />
                  <FieldLabel htmlFor="svc-root">{t("root (uid 0) olarak girişe izin ver")}</FieldLabel>
                </Field>
              )}
            />
            <Controller
              control={form.control}
              name="allowForward"
              render={({ field }) => (
                <Field orientation="horizontal">
                  <Checkbox id="svc-forward" checked={field.value} onCheckedChange={(v) => field.onChange(v === true)} />
                  <FieldLabel htmlFor="svc-forward">{t("Yerel port yönlendirmeye (ssh -L) izin ver")}</FieldLabel>
                </Field>
              )}
            />
            {powerful ? (
              <Alert>
                <TriangleAlert />
                <AlertDescription className="text-pretty">
                  {t("root ve system hesapları hedef cihazda tam yetki verir. Yalnızca gerçekten gereken kaynak cihazlara aç.")}
                </AlertDescription>
              </Alert>
            ) : null}
          </>
        ) : null}
        {service === "rdesk" && !deny ? (
          <>
            <Controller
              control={form.control}
              name="allowControl"
              render={({ field }) => (
                <Field orientation="horizontal">
                  <Checkbox id="svc-control" checked={field.value} onCheckedChange={(v) => field.onChange(v === true)} />
                  <FieldLabel htmlFor="svc-control">{t("Kontrole izin ver (klavye, fare, pano)")}</FieldLabel>
                </Field>
              )}
            />
            <Controller
              control={form.control}
              name="allowUnattended"
              render={({ field }) => (
                <Field orientation="horizontal">
                  <Checkbox id="svc-unattended" checked={field.value} onCheckedChange={(v) => field.onChange(v === true)} />
                  <FieldLabel htmlFor="svc-unattended">{t("Gözetimsiz: hedefteki kişinin onayını bekleme")}</FieldLabel>
                </Field>
              )}
            />
            {allowUnattended ? (
              <Alert>
                <TriangleAlert />
                <AlertDescription className="text-pretty">
                  {t(
                    "Gözetimsiz erişim, hedefte kimse onaylamadan oturum açar. Gösterge yine görünür ve oturum günlüğe yazılır; yalnızca kendi cihazların için kullan."
                  )}
                </AlertDescription>
              </Alert>
            ) : null}
          </>
        ) : null}
        {service === "sync" && !deny ? (
          <>
            <Field data-invalid={errors.folders ? true : undefined}>
              <FieldLabel htmlFor="svc-folders">{t("Okunabilecek klasör kimlikleri")}</FieldLabel>
              <Input id="svc-folders" className="font-mono" placeholder={t("belgeler, foto")} autoComplete="off" {...form.register("folders")} />
              <FieldDescription>
                {t("Hedefin Eşitleme sayfasında paylaştığı klasörlerin kimlikleri; virgülle. Eşitleme yalnızca çekmedir, kaynak hedefe yazamaz.")}
              </FieldDescription>
              <FieldError errors={[errors.folders]} />
            </Field>
            <Controller
              control={form.control}
              name="backup"
              render={({ field }) => (
                <Field orientation="horizontal">
                  <Checkbox id="svc-backup" checked={field.value} onCheckedChange={(v) => field.onChange(v === true)} />
                  <FieldLabel htmlFor="svc-backup">{t("Hedefte kaynaktan şifreli yedek tutulsun")}</FieldLabel>
                </Field>
              )}
            />
            {backup ? (
              <>
                <Field data-invalid={errors.quotaGiB ? true : undefined}>
                  <FieldLabel htmlFor="svc-quota">{t("Kota (GiB, 0: 50 GiB)")}</FieldLabel>
                  <Input id="svc-quota" type="number" min={0} {...form.register("quotaGiB", { valueAsNumber: true })} />
                  <FieldError errors={[errors.quotaGiB]} />
                </Field>
                <Controller
                  control={form.control}
                  name="allowPrune"
                  render={({ field }) => (
                    <Field orientation="horizontal">
                      <Checkbox id="svc-prune" checked={field.value} onCheckedChange={(v) => field.onChange(v === true)} />
                      <FieldLabel htmlFor="svc-prune">{t("Kaynak eski yedeklerini silebilsin (varsayılan: yalnızca ekleme)")}</FieldLabel>
                    </Field>
                  )}
                />
              </>
            ) : null}
          </>
        ) : null}
        {service === "wake" && !deny ? (
          <Controller
            control={form.control}
            name="via"
            render={({ field }) => (
              <ReferencePicker
                legend={t("Aracı (hedefle aynı yerel ağda, açık kalan cihaz)")}
                choices={choices}
                value={field.value}
                onChange={field.onChange}
                allowGroups
                max={MAX_REFS}
                error={errors.via?.message}
              />
            )}
          />
        ) : null}
        <Field data-invalid={errors.description ? true : undefined}>
          <FieldLabel htmlFor="svc-description">{t("Açıklama")}</FieldLabel>
          <Input id="svc-description" placeholder={t("Laptoptan sunucuya SSH")} aria-invalid={errors.description ? true : undefined} {...form.register("description")} />
          <FieldError errors={[errors.description]} />
        </Field>
      </FieldGroup>
      <DialogFooter>
        <Button type="submit">{t("Değişikliği göster")}</Button>
      </DialogFooter>
    </form>
  )
}
