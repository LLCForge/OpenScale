"use client"

import { useState } from "react"
import { Controller, useFieldArray, useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { Plus, Trash2 } from "lucide-react"

import { AddressListInput, isIpAddress } from "@/components/network/address-list-input"
import { DnsNote } from "@/components/network/dns-note"
import { SignChange } from "@/components/sign-change"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import { isLabel } from "@/lib/references"
import type { NetworkDns, ResolverChoice } from "@/lib/types"

const MAX_NAMESERVERS = 4
const MAX_SPLIT = 32
const RESERVED_DOMAIN = "openscale.internal"

function isDomain(value: string): boolean {
  return value.length >= 1 && value.length <= 253 && value.split(".").every(isLabel)
}

/** "a ve b" for the reserved domains (one or two of them). */
function joinDomains(list: string[]): string {
  return list.length === 2 ? tx("{first} ve {second}", { first: list[0], second: list[1] }) : list.join(", ")
}

/** Whether one domain equals or contains the other. */
function overlaps(a: string, b: string): boolean {
  return a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`)
}

// Built during render of DnsStep (it calls useI18n), so tx() gives the current language.
const addressList = (min: number, minMessage: string) =>
  z
    .array(z.string())
    .min(min, minMessage)
    .max(MAX_NAMESERVERS, tx("En fazla {max} çözücü", { max: MAX_NAMESERVERS }))
    .refine((list) => list.every(isIpAddress), msg("Geçersiz adres"))

function dnsSchema(magicDomain: string) {
  const reserved = Array.from(new Set([magicDomain, RESERVED_DOMAIN].filter((d) => d.length > 0)))
  return z
    .object({
      nameservers: addressList(0, ""),
      split: z
        .array(
          z.object({
            domain: z
              .string()
              .trim()
              .min(1, msg("Alan adı gerekli"))
              .max(253, msg("En fazla 253 karakter"))
              .refine(isDomain, msg("Küçük harf, rakam ve tireden oluşan etiketler; nokta ile ayrılır, ör. lan veya ev.lan"))
              .refine(
                (d) => !reserved.some((r) => overlaps(d, r)),
                tx("{domains} ile aynı olamaz veya çakışamaz; bu alanları MagicDNS çözer", { domains: joinDomains(reserved) })
              ),
            nameservers: addressList(1, msg("Bu alan için en az bir çözücü seç")),
          })
        )
        .max(MAX_SPLIT, tx("En fazla {max} alan adı", { max: MAX_SPLIT })),
    })
    .superRefine((v, ctx) => {
      if (v.nameservers.length === 0 && v.split.length === 0) {
        ctx.addIssue({
          code: "custom",
          path: ["nameservers"],
          message: msg("En az bir genel çözücü veya bir alan adı gir. Bölümü kaldırmak için karttaki \"Kaldır\" düğmesini kullan."),
        })
      }
      const seen = new Set<string>()
      v.split.forEach((s, i) => {
        const d = s.domain.trim()
        if (seen.has(d)) {
          ctx.addIssue({ code: "custom", path: ["split", i, "domain"], message: msg("Bu alan adı iki kez yazılmış") })
        }
        seen.add(d)
      })
    })
}

type DnsForm = z.infer<ReturnType<typeof dnsSchema>>

interface DnsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  current: NetworkDns | null
  resolvers: ResolverChoice[]
  dnsDomain: string
}

/** Edits the network-wide DNS section (ADR-0024). */
export function DnsDialog({ open, onOpenChange, current, resolvers, dnsDomain }: DnsDialogProps) {
  const { t } = useI18n()
  const [payload, setPayload] = useState<NetworkDns | null>(null)

  function handleOpenChange(next: boolean) {
    if (!next) setPayload(null)
    onOpenChange(next)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{t("Ağ DNS ayarları")}</DialogTitle>
          <DialogDescription className="text-pretty">
            {payload
              ? t("Değişikliği kontrol et ve kök anahtarınla imzala.")
              : t("Cihazlar, ağdan gelen DNS ayarlarını kabul ediyorsa bu çözücüleri kullanır. MagicDNS adları her zaman çalışmaya devam eder.")}
          </DialogDescription>
        </DialogHeader>
        {open && !payload ? <DnsStep current={current} resolvers={resolvers} dnsDomain={dnsDomain} onNext={setPayload} /> : null}
        {open && payload ? (
          <SignChange
            endpoint="/api/network/dns"
            payload={{ clear: false, nameservers: payload.nameservers, split: payload.split }}
            confirmLabel={t("İmzala ve kaydet")}
            onBack={() => setPayload(null)}
            onDone={() => handleOpenChange(false)}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

interface DnsStepProps {
  current: NetworkDns | null
  resolvers: ResolverChoice[]
  dnsDomain: string
  onNext: (dns: NetworkDns) => void
}

function DnsStep({ current, resolvers, dnsDomain, onNext }: DnsStepProps) {
  const { t } = useI18n()
  const form = useForm<DnsForm>({
    resolver: zodResolver(dnsSchema(dnsDomain)),
    defaultValues: {
      nameservers: current?.nameservers ?? [],
      split: current?.split.map((s) => ({ domain: s.domain, nameservers: s.nameservers })) ?? [],
    },
  })
  const split = useFieldArray({ control: form.control, name: "split" })
  const { errors } = form.formState

  function submit(values: DnsForm) {
    onNext({
      nameservers: values.nameservers,
      split: values.split.map((s) => ({ domain: s.domain.trim(), nameservers: s.nameservers })),
    })
  }

  return (
    <form onSubmit={form.handleSubmit(submit)} noValidate className="flex flex-col gap-4">
      <DnsNote />
      <FieldGroup>
        <Field data-invalid={errors.nameservers ? true : undefined}>
          <FieldLabel htmlFor="dns-global-input">{t("Genel çözücüler")}</FieldLabel>
          <FieldDescription>
            {t("Bütün sorgular bu adreslere gider (en fazla {max}). Boş bırakırsan cihazlar kendi çözücülerini kullanır; yalnızca aşağıdaki alan adları yönlendirilir.", { max: MAX_NAMESERVERS })}
          </FieldDescription>
          <Controller
            control={form.control}
            name="nameservers"
            render={({ field }) => (
              <AddressListInput
                id="dns-global-input"
                value={field.value}
                onChange={field.onChange}
                resolvers={resolvers}
                max={MAX_NAMESERVERS}
                invalid={errors.nameservers ? true : undefined}
              />
            )}
          />
          <FieldError errors={[errors.nameservers]} />
        </Field>

        <FieldSet>
          <FieldLegend variant="label">{t("Alan adına göre yönlendirme")}</FieldLegend>
          <FieldDescription>
            {t("Yalnızca bu alan adlarındaki sorgular (ör. ev ağındaki \"lan\") seçtiğin çözücüye gider. En fazla {maxSplit} alan, her biri için 1-{max} çözücü.", { maxSplit: MAX_SPLIT, max: MAX_NAMESERVERS })}
          </FieldDescription>
          {split.fields.length === 0 ? <p className="text-sm text-muted-foreground">{t("Yönlendirilen alan adı yok.")}</p> : null}
          <ol className="flex flex-col gap-3">
            {split.fields.map((f, i) => {
              const fieldErrors = errors.split?.[i]
              return (
                <li key={f.id} className="flex flex-col gap-3 rounded-lg border p-3">
                  <div className="flex items-start gap-2">
                    <Field data-invalid={fieldErrors?.domain ? true : undefined} className="flex-1">
                      <FieldLabel htmlFor={`dns-split-${f.id}`}>{t("Alan adı")}</FieldLabel>
                      <Input
                        id={`dns-split-${f.id}`}
                        autoComplete="off"
                        spellCheck={false}
                        className="font-mono"
                        placeholder="lan"
                        aria-invalid={fieldErrors?.domain ? true : undefined}
                        {...form.register(`split.${i}.domain`)}
                      />
                      <FieldError errors={[fieldErrors?.domain]} />
                    </Field>
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-sm"
                      className="mt-6"
                      aria-label={t("{number}. alan adını kaldır", { number: i + 1 })}
                      onClick={() => split.remove(i)}
                    >
                      <Trash2 />
                    </Button>
                  </div>
                  <Field data-invalid={fieldErrors?.nameservers ? true : undefined}>
                    <FieldLabel htmlFor={`dns-split-ns-${f.id}`}>{t("Çözücüler")}</FieldLabel>
                    <Controller
                      control={form.control}
                      name={`split.${i}.nameservers`}
                      render={({ field }) => (
                        <AddressListInput
                          id={`dns-split-ns-${f.id}`}
                          value={field.value}
                          onChange={field.onChange}
                          resolvers={resolvers}
                          max={MAX_NAMESERVERS}
                          invalid={fieldErrors?.nameservers ? true : undefined}
                        />
                      )}
                    />
                    <FieldError errors={[fieldErrors?.nameservers]} />
                  </Field>
                </li>
              )
            })}
          </ol>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="w-fit"
            disabled={split.fields.length >= MAX_SPLIT}
            onClick={() => split.append({ domain: "", nameservers: [] })}
          >
            <Plus data-icon="inline-start" />
            {t("Alan adı ekle")}
          </Button>
          {errors.split?.message ? <FieldError>{errors.split.message}</FieldError> : null}
        </FieldSet>
      </FieldGroup>
      <DialogFooter>
        <Button type="submit">{t("Değişikliği göster")}</Button>
      </DialogFooter>
    </form>
  )
}
