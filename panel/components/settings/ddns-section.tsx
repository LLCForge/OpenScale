"use client"

import { useState } from "react"
import useSWR from "swr"
import { useForm, Controller } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { RefreshCw, Send } from "lucide-react"
import { toast } from "sonner"

import { useReadOnly } from "@/components/app/read-only"
import { CodeLine } from "@/components/copy-field"
import { NativeSelect } from "@/components/native-select"
import { SettingBadge, SettingDisclosure, SettingRow, SettingsSection } from "@/components/settings/settings-layout"
import { Button } from "@/components/ui/button"
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { ApiError, errorMessage, fetcher, post } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { DDNSCheck, DDNSStatus, DDNSUpdater } from "@/lib/p07-types"

// Dynamic DNS (#448, #449, ADR-0160): whether the coordinator's name still
// points where the tunnel really talks to it, and an RFC 2136 updater for
// the owner's own DNS server. Local to this computer; no signature.

const KEY = "/api/app/ddns"

const checkBadge: Record<DDNSCheck["status"], { text: string; tone: "success" | "warning" | "danger" | "muted" }> = {
  ok: { text: msg("Güncel"), tone: "success" },
  stale: { text: msg("Güncel değil"), tone: "warning" },
  unresolved: { text: msg("Çözülemiyor"), tone: "danger" },
  unknown: { text: msg("Karşılaştırılamadı"), tone: "muted" },
}

const schema = z.object({
  enabled: z.boolean(),
  server: z.string().trim().max(270, msg("Çok uzun")),
  zone: z.string().trim().max(253, msg("Çok uzun")),
  name: z.string().trim().max(253, msg("Çok uzun")),
  ttl: z.string().trim().regex(/^\d{0,6}$/, msg("Saniye olarak sayı yaz")),
  keyName: z.string().trim().max(253, msg("Çok uzun")),
  algorithm: z.enum(["hmac-sha256", "hmac-sha512"]),
  secret: z.string().trim().max(512, msg("Çok uzun")),
})
type Values = z.infer<typeof schema>

export function DDNSSection() {
  const { t, ts } = useI18n()
  const { data, error, mutate } = useSWR<DDNSStatus>(KEY, fetcher, {
    refreshInterval: 60_000,
    shouldRetryOnError: (err: unknown) => !(err instanceof ApiError && err.status === 404),
  })
  const readOnly = useReadOnly()
  const [busy, setBusy] = useState<"check" | "update" | null>(null)

  // Older services and the command line panel have no DDNS: no section.
  if (error instanceof ApiError && error.status === 404) return null
  if (!data) return null

  async function run(kind: "check" | "update") {
    setBusy(kind)
    try {
      const res = await post<DDNSStatus>(`${KEY}/${kind}`, {})
      await mutate(res, { revalidate: false })
      toast.success(kind === "check" ? t("Denetim bitti.") : t("Güncelleme gönderildi."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  const c = data.check
  const u = data.updater
  return (
    <SettingsSection
      id="ddns"
      title={t("Dinamik DNS")}
      description={t("Koordinatörün adı doğru adrese mi çıkıyor, ve ev adresin değişince kendi DNS sunucunun güncellenmesi.")}
    >
      <SettingRow
        title={t("DDNS tutarlılığı")}
        badge={c ? <SettingBadge tone={checkBadge[c.status].tone}>{t(checkBadge[c.status].text)}</SettingBadge> : null}
        description={
          c ? (
            <>
              {ts(c.message)}{" "}
              <span className="whitespace-nowrap">
                {t("Son denetim {time}", { time: formatDateTime(c.at) })}
                {c.host ? (
                  <>
                    {" "}
                    · <span className="font-mono text-[0.8125rem]">{c.host}</span>
                  </>
                ) : null}
              </span>
            </>
          ) : (
            t("Henüz denetlenmedi.")
          )
        }
        action={
          readOnly ? null : (
            <Button variant="outline" disabled={busy !== null} onClick={() => run("check")}>
              {busy === "check" ? <Spinner data-icon="inline-start" /> : <RefreshCw data-icon="inline-start" />}
              {t("Şimdi denetle")}
            </Button>
          )
        }
      />
      <UpdaterRow updater={u} readOnly={readOnly} busy={busy === "update"} onUpdate={() => run("update")} onSaved={(s) => mutate(s, { revalidate: false })} />
      <SettingDisclosure
        title={t("DNS sunucusunda gereken ayar")}
        description={t("Anahtar yalnızca bu adı güncelleyebilmeli; ele geçirilirse başka adlar değişmesin.")}
        openLabel={t("Örneği göster")}
      >
        <CodeLine
          value={`update-policy { grant ${u.key_name || t("<anahtar>")} name ${u.name || t("<ad>")}. A AAAA; };`}
          label={t("Örneği kopyala")}
          nowrap
        />
      </SettingDisclosure>
    </SettingsSection>
  )
}

interface UpdaterRowProps {
  updater: DDNSUpdater
  readOnly: boolean
  busy: boolean
  onUpdate: () => void
  onSaved: (s: DDNSStatus) => void
}

function UpdaterRow({ updater: u, readOnly, busy, onUpdate, onSaved }: UpdaterRowProps) {
  const { t, ts } = useI18n()
  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: {
      enabled: u.enabled,
      server: u.server ?? "",
      zone: u.zone ?? "",
      name: u.name ?? "",
      ttl: u.ttl ? String(u.ttl) : "",
      keyName: u.key_name ?? "",
      algorithm: u.algorithm === "hmac-sha512" ? "hmac-sha512" : "hmac-sha256",
      secret: "",
    },
  })
  const { errors, isSubmitting, isDirty } = form.formState
  const [publishedBefore, publishedAfter = ""] = (
    u.published_at ? t("Son yayın {address} ({time}).", { time: formatDateTime(u.published_at) }) : t("Son yayın {address}.")
  ).split("{address}")

  async function save(v: Values, secret?: string) {
    if (v.enabled) {
      for (const [field, value] of [
        ["server", v.server],
        ["zone", v.zone],
        ["name", v.name],
        ["keyName", v.keyName],
      ] as const) {
        // The service checks the values; here only that none is missing.
        if (!value) {
          form.setError(field, { message: t("Açıkken bu alan gerekli") })
          return
        }
      }
    }
    try {
      const res = await post<DDNSStatus>(KEY, {
        enabled: v.enabled,
        server: v.server,
        zone: v.zone,
        name: v.name,
        ...(v.ttl ? { ttl: Number(v.ttl) } : {}),
        key_name: v.keyName,
        algorithm: v.algorithm,
        // Absent keeps the stored secret; "" removes it.
        ...(secret !== undefined ? { secret } : v.secret ? { secret: v.secret } : {}),
      })
      onSaved(res)
      form.reset({ ...v, secret: "" })
      toast.success(secret === "" ? t("Gizli değer silindi.") : t("DDNS ayarları kaydedildi."))
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }

  return (
    <SettingRow
      title={t("Kendi DNS sunucuma bildir")}
      badge={u.enabled ? <SettingBadge tone="success">{t("Açık")}</SettingBadge> : <SettingBadge>{t("Varsayılan kapalı")}</SettingBadge>}
      description={
        <>
          {t("Ev adresin yalnızca bu sunucuya gönderilir. Özel veya CGNAT adresler hiç yayımlanmaz.")}
          {u.published ? (
            <>
              {" "}
              {publishedBefore}
              <span className="font-mono text-[0.8125rem]">{u.published}</span>
              {publishedAfter}
            </>
          ) : null}
          {u.last_error ? <span className="block text-destructive">{ts(u.last_error)}</span> : null}
        </>
      }
      action={
        readOnly || !u.enabled ? null : (
          <Button variant="outline" disabled={busy} onClick={onUpdate}>
            {busy ? <Spinner data-icon="inline-start" /> : <Send data-icon="inline-start" />}
            {t("Şimdi güncelle")}
          </Button>
        )
      }
    >
      <form onSubmit={form.handleSubmit((v) => save(v))} noValidate className="flex flex-col gap-4">
        <fieldset disabled={readOnly} className="contents">
          <FieldGroup>
            <Controller
              control={form.control}
              name="enabled"
              render={({ field }) => (
                <Field orientation="horizontal">
                  <FieldContent>
                    <FieldLabel htmlFor="ddns-enabled">{t("Güncelleyici açık")}</FieldLabel>
                    <FieldDescription>{t("TSIG ile imzalı RFC 2136 güncellemesi gönderilir.")}</FieldDescription>
                  </FieldContent>
                  <Switch id="ddns-enabled" checked={field.value} onCheckedChange={field.onChange} disabled={readOnly} />
                </Field>
              )}
            />
            <div className="grid gap-4 sm:grid-cols-2">
              <TextField id="ddns-server" label={t("DNS sunucusu (IP:port)")} placeholder={t("VPS adresi:53")} error={errors.server?.message} {...form.register("server")} />
              <TextField id="ddns-zone" label={t("Bölge")} placeholder={t("ornek.com")} error={errors.zone?.message} {...form.register("zone")} />
              <TextField id="ddns-name" label={t("Ad")} placeholder={t("ev.ornek.com")} error={errors.name?.message} {...form.register("name")} />
              <TextField id="ddns-ttl" label={t("TTL (saniye)")} placeholder="300" inputMode="numeric" error={errors.ttl?.message} {...form.register("ttl")} />
              <TextField id="ddns-key-name" label={t("Anahtar adı")} placeholder={t("ev-guncelle")} error={errors.keyName?.message} {...form.register("keyName")} />
              <Field>
                <FieldLabel htmlFor="ddns-algorithm">{t("Algoritma")}</FieldLabel>
                <NativeSelect id="ddns-algorithm" className="sm:w-full" {...form.register("algorithm")}>
                  <option value="hmac-sha256">hmac-sha256</option>
                  <option value="hmac-sha512">hmac-sha512</option>
                </NativeSelect>
              </Field>
            </div>
            <Field data-invalid={errors.secret ? true : undefined}>
              <FieldLabel htmlFor="ddns-secret">{t("Gizli değer (base64)")}</FieldLabel>
              <Input id="ddns-secret" type="password" autoComplete="off" spellCheck={false} className="font-mono" {...form.register("secret")} />
              <FieldDescription>
                {u.key_set ? t("Kayıtlı. Değiştirmek için yeni değeri yaz; boş bırakırsan kayıtlı değer korunur.") : t("Sunucudaki TSIG anahtarının gizli değeri.")}
              </FieldDescription>
              <FieldError errors={[errors.secret]} />
            </Field>
          </FieldGroup>
          {readOnly ? null : (
            <div className="flex flex-wrap gap-2">
              <Button type="submit" disabled={isSubmitting || !isDirty}>
                {isSubmitting ? <Spinner data-icon="inline-start" /> : null}
                {t("Kaydet")}
              </Button>
              {u.key_set ? (
                <Button type="button" variant="ghost" disabled={isSubmitting} onClick={() => save(form.getValues(), "")}>
                  {t("Gizli değeri sil")}
                </Button>
              ) : null}
            </div>
          )}
        </fieldset>
      </form>
    </SettingRow>
  )
}

interface TextFieldProps extends React.ComponentProps<"input"> {
  id: string
  label: string
  error?: string
}

function TextField({ id, label, error, ...input }: TextFieldProps) {
  return (
    <Field data-invalid={error ? true : undefined}>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <Input id={id} autoComplete="off" spellCheck={false} className="font-mono" aria-invalid={error ? true : undefined} {...input} />
      {error ? <FieldError>{error}</FieldError> : null}
    </Field>
  )
}
