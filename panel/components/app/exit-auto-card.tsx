"use client"

import { useState } from "react"
import useSWR from "swr"
import { useForm, useWatch } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { Shuffle } from "lucide-react"
import { toast } from "sonner"

import { useReadOnly } from "@/components/app/read-only"
import { useAppStatus } from "@/components/app/use-app-status"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { ApiError, errorMessage, fetcher, post } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { ExitAutoSettings, ExitAutoState } from "@/lib/wave3-types"

const cidr4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/([1-9]|[12]\d|3[0-2])$/

function splitList(s: string): string[] {
  return s
    .split(",")
    .map((v) => v.trim())
    .filter((v) => v !== "")
}

const schema = z
  .object({
    auto: z.boolean(),
    fastest: z.boolean(),
    untrusted: z.boolean(),
    trustWired: z.boolean(),
    candidates: z
      .string()
      .max(1100)
      .refine((s) => splitList(s).length <= 16, msg("En fazla 16 aday"))
      .refine((s) => splitList(s).every((n) => n.length <= 63), msg("Cihaz adı en fazla 63 karakter")),
    trustedWifi: z
      .string()
      .max(4200)
      .refine((s) => splitList(s).length <= 32, msg("En fazla 32 ağ adı"))
      .refine((s) => splitList(s).every((n) => new TextEncoder().encode(n).length <= 128), msg("Ağ adı en fazla 128 bayt")),
    except: z
      .string()
      .max(1500)
      .refine((s) => splitList(s).length <= 64, msg("En fazla 64 aralık"))
      .refine((s) => splitList(s).every((p) => cidr4.test(p)), msg("IPv4 CIDR aralıkları yaz (ör. 203.0.113.0/24)")),
  })
  .refine((v) => v.untrusted || (v.trustedWifi.trim() === "" && !v.trustWired), {
    message: msg("Güvenilir ağ listesi yalnızca 'güvenilmeyen ağda aç' ile kullanılır"),
    path: ["trustedWifi"],
  })
  .refine((v) => v.auto || v.untrusted || v.candidates.trim() === "", {
    message: msg("Aday listesi yalnızca otomatik seçim açıkken kullanılır"),
    path: ["candidates"],
  })

type Values = z.infer<typeof schema>

function toValues(s: ExitAutoSettings): Values {
  return {
    auto: s.mode !== "",
    fastest: s.mode === "fastest",
    untrusted: s.untrusted,
    trustWired: s.trustWired,
    candidates: s.candidates.join(", "),
    trustedWifi: s.trustedWifi.join(", "),
    except: s.except.join(", "),
  }
}

function toSettings(v: Values): ExitAutoSettings {
  return {
    mode: v.auto || v.untrusted ? (v.fastest ? "fastest" : "failover") : "",
    candidates: splitList(v.candidates),
    untrusted: v.untrusted,
    trustedWifi: v.untrusted ? splitList(v.trustedWifi) : [],
    trustWired: v.untrusted && v.trustWired,
    except: splitList(v.except),
  }
}

/** Automatic exit node of this computer (ADR-0133, #79, #80, #81). */
export function ExitAutoCard() {
  const { status, isApp } = useAppStatus()
  const readOnly = useReadOnly()
  const device = status?.device
  const enabled = isApp && !!device?.name
  const { data, mutate } = useSWR<ExitAutoState>(enabled ? "/api/app/exit-auto" : null, fetcher, {
    refreshInterval: 15_000,
    shouldRetryOnError: (err: unknown) => !(err instanceof ApiError && err.status === 404),
  })
  if (!enabled || !data) return null
  return <ExitAutoForm state={data} readOnly={readOnly} onSaved={(s) => mutate(s, { revalidate: false })} />
}

function ExitAutoForm({ state, readOnly, onSaved }: { state: ExitAutoState; readOnly: boolean; onSaved: (s: ExitAutoState) => void }) {
  const { t, ts } = useI18n()
  const [saving, setSaving] = useState(false)
  const form = useForm<Values>({ resolver: zodResolver(schema), values: toValues(state.settings) })
  const { errors } = form.formState
  const watched = useWatch({ control: form.control })
  const untrusted = watched.untrusted === true
  const running = state.settings.mode !== "" || state.settings.untrusted

  async function onSubmit(v: Values) {
    setSaving(true)
    try {
      const res = await post<ExitAutoState>("/api/app/exit-auto", toSettings(v))
      onSaved(res)
      toast.success(t("Otomatik çıkış ayarları kaydedildi."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  // One sentence per combination, so each reads naturally in both languages.
  function describeRunning(): string {
    const reason = state.reason ? ts(state.reason) : ""
    if (!state.exit) {
      return reason
        ? t("Otomatik seçim açık; şu an çıkış düğümü kullanılmıyor ({reason}).", { reason })
        : t("Otomatik seçim açık; şu an çıkış düğümü kullanılmıyor.")
    }
    const exit = state.exit
    if (state.since) {
      const since = formatDateTime(state.since)
      return reason
        ? t("Şu an {exit} kullanılıyor ({reason}), {since} itibarıyla.", { exit, reason, since })
        : t("Şu an {exit} kullanılıyor, {since} itibarıyla.", { exit, since })
    }
    return reason ? t("Şu an {exit} kullanılıyor ({reason}).", { exit, reason }) : t("Şu an {exit} kullanılıyor.", { exit })
  }

  const sw = (name: "auto" | "fastest" | "untrusted" | "trustWired", label: string, help: string) => (
    <Field orientation="horizontal">
      <Switch
        id={`exit-auto-${name}`}
        checked={watched[name] === true}
        disabled={readOnly}
        onCheckedChange={(on) => form.setValue(name, on, { shouldValidate: true })}
      />
      <div className="flex flex-col gap-1">
        <FieldLabel htmlFor={`exit-auto-${name}`}>{t(label)}</FieldLabel>
        <FieldDescription>{t(help)}</FieldDescription>
      </div>
    </Field>
  )

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Shuffle className="size-4 text-muted-foreground" />
          {t("Otomatik çıkış düğümü")}
        </CardTitle>
        <CardDescription className="text-pretty">
          {running ? describeRunning() : t("Kapalı: çıkış düğümünü elle seçersin.")}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form noValidate onSubmit={form.handleSubmit(onSubmit)} className="flex flex-col gap-6">
          <FieldGroup>
            {sw("auto", msg("Otomatik seç"), msg("Çalışmayan çıkış düğümünden sıradaki adaya geçer. Hiçbiri çalışmazsa trafik tünelde kalır, yerel ağa sızmaz."))}
            {sw("fastest", msg("En hızlıyı seç"), msg("Gecikmesi en az olan adayı kullanır; yalnızca en az %30 daha hızlı bir aday 2 dakika sağlıklı kalınca geçer."))}
            <Field data-invalid={errors.candidates ? true : undefined}>
              <FieldLabel htmlFor="exit-auto-candidates">{t("Aday çıkış düğümleri")}</FieldLabel>
              <Input id="exit-auto-candidates" autoComplete="off" placeholder={t("boş: kullanılabilen hepsi")} disabled={readOnly} {...form.register("candidates")} />
              <FieldDescription>{t("Öncelik sırasıyla, virgülle ayır.")}</FieldDescription>
              <FieldError errors={[errors.candidates]} />
            </Field>
            {sw("untrusted", msg("Güvenilmeyen ağda otomatik aç"), msg("Bağlı ağlardan biri aşağıdaki listede değilse, ağ okunamazsa veya hiç ağ yoksa çıkış düğümü açılır."))}
            {untrusted ? (
              <>
                <Field data-invalid={errors.trustedWifi ? true : undefined}>
                  <FieldLabel htmlFor="exit-auto-wifi">{t("Güvenilir Wi-Fi adları")}</FieldLabel>
                  <Input id="exit-auto-wifi" autoComplete="off" placeholder={t("Ev, Ofis")} disabled={readOnly} {...form.register("trustedWifi")} />
                  <FieldDescription>{t("Büyük-küçük harf duyarlı SSID adları, virgülle ayır.")}</FieldDescription>
                  <FieldError errors={[errors.trustedWifi]} />
                </Field>
                {sw("trustWired", msg("Kablolu ağlara güven"), msg("Varsayılan kapalı: kablolu ağlar da güvenilmez sayılır."))}
              </>
            ) : null}
            <Field data-invalid={errors.except ? true : undefined}>
              <FieldLabel htmlFor="exit-auto-except">{t("Çıkış istisnaları")}</FieldLabel>
              <Input id="exit-auto-except" autoComplete="off" placeholder="203.0.113.0/24" disabled={readOnly} {...form.register("except")} />
              <FieldDescription>{t("Çıkış düğümü dışında tutulan IPv4 aralıkları. Sızıntı kilidi (kill switch) açıkken bu trafik engellenir.")}</FieldDescription>
              <FieldError errors={[errors.except]} />
            </Field>
          </FieldGroup>
          {state.networks.length > 0 ? (
            <p className="text-xs text-muted-foreground text-pretty">{t("Görülen ağlar: {networks}", { networks: state.networks.join(", ") })}</p>
          ) : null}
          {readOnly ? null : (
            <Button type="submit" className="w-fit" disabled={saving}>
              {saving ? <Spinner data-icon="inline-start" /> : null}
              {t("Kaydet")}
            </Button>
          )}
        </form>
      </CardContent>
    </Card>
  )
}
