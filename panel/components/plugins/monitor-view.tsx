"use client"

import { useState } from "react"
import useSWR from "swr"
import { toast } from "sonner"

import { Writable } from "@/components/app/read-only"
import { PageHeader } from "@/components/page-header"
import { EmptyNote, SettingBadge, SettingRow, SettingsColumn, SettingsSection } from "@/components/settings/settings-layout"
import { Button } from "@/components/ui/button"
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { ApiError, errorMessage, fetcher, post } from "@/lib/api"
import { formatAgo, formatDateTime, formatUptime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"

import { MonitorEventsSection } from "./monitor-events"
import type { MonitorView as MonitorData, NotifyConfig } from "./types"

const stateTone: Record<string, "success" | "warning" | "danger" | "muted"> = { up: "success", down: "danger", unknown: "muted" }
const stateText: Record<string, string> = { up: msg("Çalışıyor"), down: msg("Yanıt yok"), unknown: msg("Bekleniyor") }
const kindText: Record<string, string> = { desktop: msg("Masaüstü"), ntfy: "ntfy", gotify: "Gotify", matrix: "Matrix", smtp: msg("E-posta (SMTP)") }
const dayNames = [msg("Pazar"), msg("Pazartesi"), msg("Salı"), msg("Çarşamba"), msg("Perşembe"), msg("Cuma"), msg("Cumartesi")]

function notWired(err: unknown): boolean {
  return err instanceof ApiError && err.status === 501
}

/** İzleme (ADR-0216, ADR-0220): service and device watch, notification channels, weekly report. */
export function MonitorView() {
  const { t } = useI18n()
  const { data, error, mutate } = useSWR<MonitorData>("/api/g7/monitor", fetcher, { refreshInterval: 15000 })
  return (
    <SettingsColumn>
      <PageHeader
        title={t("İzleme")}
        description={t(
          "Servislerin ayakta olup olmadığını, izlemeye aldığınız cihazların çevrimdışı kalmasını ve disk ile pil uyarılarını izler. Bildirimler yalnızca sizin seçtiğiniz kanallara gider.",
        )}
      />
      {notWired(error) ? (
        <EmptyNote>{t("Bu sürümde izleme masaüstü servisine bağlı değil. Servis güncellenince bu sayfa kendiliğinden dolar.")}</EmptyNote>
      ) : error ? (
        <EmptyNote>
          {t("İzleme durumu alınamadı: {error}", { error: errorMessage(error) })}{" "}
          <Button size="sm" variant="link" onClick={() => mutate()}>
            {t("Tekrar dene")}
          </Button>
        </EmptyNote>
      ) : (
        <>
          <ServicesSection data={data} />
          <DevicesSection data={data} />
          <MonitorEventsSection />
        </>
      )}
      <NotifySection />
      <ReportSection />
    </SettingsColumn>
  )
}

function ServicesSection({ data }: { data?: MonitorData }) {
  const { t, ts } = useI18n()
  const services = data?.services ?? []
  return (
    <SettingsSection title={t("Servisler")} description={t("HTTP ve TCP yoklaması yalnızca tünel adreslerine veya sizin eklediğiniz özel ağlara yapılır.")}>
      {services.length === 0 && <EmptyNote>{t("İzlenen servis yok.")}</EmptyNote>}
      {services.map((s) => (
        <SettingRow
          key={s.name}
          title={s.name}
          description={
            s.state === "down"
              ? s.last_error
                ? t("{since} beri yanıt yok: {error}", { since: formatAgo(s.since), error: ts(s.last_error) })
                : t("{since} beri yanıt yok", { since: formatAgo(s.since) })
              : t("Son yanıt {ms} ms · toplam kesinti {downtime}", { ms: s.last_latency_ms, downtime: formatUptime(s.downtime_sec) })
          }
          badge={<SettingBadge tone={stateTone[s.state] ?? "muted"}>{stateText[s.state] ? t(stateText[s.state]) : s.state}</SettingBadge>}
        />
      ))}
    </SettingsSection>
  )
}

function DevicesSection({ data }: { data?: MonitorData }) {
  const { t, ts } = useI18n()
  const devices = data?.devices ?? []
  return (
    <SettingsSection title={t("Cihazlar")} description={t("Yalnızca izlemeye aldığınız cihazlar çevrimdışı olunca bildirim üretir.")}>
      {devices.length === 0 && <EmptyNote>{t("Henüz cihaz bilgisi yok.")}</EmptyNote>}
      {devices.map((d) => (
        <SettingRow
          key={d.name}
          title={d.name}
          description={
            d.warnings.length > 0
              ? d.warnings.map((w) => ts(w)).join(" · ")
              : d.last_seen
                ? t("Son görülme {at}", { at: formatDateTime(d.last_seen) })
                : d.watched
                  ? t("İzleniyor")
                  : t("İzlenmiyor")
          }
          badge={
            <SettingBadge tone={d.online ? "success" : d.watched ? "danger" : "muted"}>{d.online ? t("Çevrimiçi") : t("Çevrimdışı")}</SettingBadge>
          }
        />
      ))}
    </SettingsSection>
  )
}

function NotifySection() {
  const { t } = useI18n()
  const { data, error, mutate } = useSWR<NotifyConfig>("/api/g7/notify", fetcher)
  const [busy, setBusy] = useState<string | null>(null)
  const [quietStart, setQuietStart] = useState<string | null>(null)
  const [quietEnd, setQuietEnd] = useState<string | null>(null)

  async function test(label: string) {
    setBusy(label)
    try {
      await post("/api/g7/notify/test", { label })
      toast.success(t("{label} kanalına deneme bildirimi gönderildi.", { label }))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }
  async function saveQuiet() {
    if (!data) return
    setBusy("quiet")
    try {
      await post("/api/g7/notify", { ...data, quiet_start: quietStart ?? data.quiet_start ?? "", quiet_end: quietEnd ?? data.quiet_end ?? "" })
      await mutate()
      toast.success(t("Sessiz saatler kaydedildi."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  return (
    <SettingsSection
      title={t("Bildirim kanalları")}
      description={t("Masaüstü, ntfy, Gotify, Matrix ve e-posta. Gömülü bir sunucu yoktur; adresleri siz verirsiniz. Belirteç ve parolalar burada gösterilmez.")}
    >
      {notWired(error) && <EmptyNote>{t("Bildirim ayarları masaüstü servisine bağlanınca burada görünür.")}</EmptyNote>}
      {data && data.channels.length === 0 && <EmptyNote>{t("Kanal yok. Kanal eklemek için: openscale notify (servis sürümüyle gelir).")}</EmptyNote>}
      {data?.channels.map((c) => (
        <SettingRow
          key={c.label}
          title={c.label}
          description={[
            kindText[c.kind] ? t(kindText[c.kind]) : c.kind,
            c.min_priority ? t("en az {priority} önem", { priority: c.min_priority }) : "",
            c.max_per_hour ? t("saatte en çok {count}", { count: c.max_per_hour }) : "",
          ]
            .filter(Boolean)
            .join(" · ")}
          action={
            <Writable>
              <Button size="sm" variant="outline" disabled={busy !== null} onClick={() => test(c.label)}>
                {t("Deneme gönder")}
              </Button>
            </Writable>
          }
        />
      ))}
      {data && (
        <Writable>
          <FieldGroup className="py-3">
            <div className="flex flex-col gap-3 sm:flex-row">
              <Field>
                <FieldLabel htmlFor="quiet-start">{t("Sessiz saat başlangıcı")}</FieldLabel>
                <Input id="quiet-start" type="time" value={quietStart ?? data.quiet_start ?? ""} onChange={(e) => setQuietStart(e.target.value)} />
              </Field>
              <Field>
                <FieldLabel htmlFor="quiet-end">{t("Bitişi")}</FieldLabel>
                <Input id="quiet-end" type="time" value={quietEnd ?? data.quiet_end ?? ""} onChange={(e) => setQuietEnd(e.target.value)} />
              </Field>
            </div>
            <FieldDescription>{t("Bu aralıkta yalnızca acil öncelikli bildirimler gönderilir. İki değer aynıysa sessiz saat kapalıdır.")}</FieldDescription>
            <div className="flex justify-end">
              <Button variant="outline" onClick={saveQuiet} disabled={busy !== null}>
                {t("Kaydet")}
              </Button>
            </div>
          </FieldGroup>
        </Writable>
      )}
    </SettingsSection>
  )
}

function ReportSection() {
  const { t, ts } = useI18n()
  const { data, mutate } = useSWR<NotifyConfig>("/api/g7/notify", fetcher)
  const { data: preview, error } = useSWR<{ subject: string; text: string }>("/api/g7/notify/report", fetcher)
  const [busy, setBusy] = useState(false)

  async function toggle(on: boolean) {
    if (!data) return
    setBusy(true)
    try {
      await post("/api/g7/notify", { ...data, weekly_report: on })
      await mutate()
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <SettingsSection title={t("Haftalık rapor")} description={t("Kullanım, engellenen sorgu sayısı ve güncelleme bekleyen cihazlar. Raporda adres, MAC veya alan adı bulunmaz.")}>
      <SettingRow
        title={t("Haftalık raporu gönder")}
        description={
          data
            ? t("{day} günü saat {hour}:00", { day: t(dayNames[data.report_day ?? 0] ?? dayNames[0]), hour: String(data.report_hour ?? 9).padStart(2, "0") })
            : t("Servis bağlanınca ayarlanabilir.")
        }
        htmlFor="weekly"
        action={
          <Writable>
            <Switch id="weekly" checked={data?.weekly_report ?? false} disabled={!data || busy} onCheckedChange={toggle} />
          </Writable>
        }
      />
      {preview && (
        <SettingRow title={ts(preview.subject)} description={t("Önizleme")}>
          <pre className="max-h-64 overflow-auto rounded-md bg-muted p-3 text-xs leading-relaxed whitespace-pre-wrap">{preview.text}</pre>
        </SettingRow>
      )}
      {error && !notWired(error) && <EmptyNote>{t("Önizleme alınamadı: {error}", { error: errorMessage(error) })}</EmptyNote>}
    </SettingsSection>
  )
}
