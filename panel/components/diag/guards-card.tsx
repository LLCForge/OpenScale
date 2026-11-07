"use client"

import { useState } from "react"
import useSWR from "swr"
import { toast } from "sonner"

import { useReadOnly } from "@/components/app/read-only"
import { DetailSection } from "@/components/devices/detail-card"
import { DnsEnforceSwitch } from "@/components/diag/dns-enforce-switch"
import { headCell, ListTable, RowMenu } from "@/components/settings/list-table"
import { EmptyNote, SettingBadge } from "@/components/settings/settings-layout"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { DropdownMenuItem } from "@/components/ui/dropdown-menu"
import { Field, FieldContent, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { errorMessage, fetcher, post } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { tx, useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"
import { threatKindText, type DoHFinding, type GuardSettings, type GuardStatus } from "@/lib/wave2"

/** Threat detection, DNSSEC and the exit node resolver (ADR-0102, ADR-0110), as the "Tehditler" section. */
export function GuardsCard() {
  const { data, mutate } = useSWR<GuardStatus>("/api/app/guards", fetcher, { refreshInterval: 10000 })
  const readOnly = useReadOnly()
  const { t } = useI18n()
  const [doh, setDoh] = useState<DoHFinding[] | null>(null)
  const [scanning, setScanning] = useState(false)
  if (!data) return null

  async function unblock(peer: string) {
    try {
      await mutate(await post<GuardStatus>("/api/app/guards/unblock", { device: peer }), { revalidate: false })
      toast.success(t("{peer} cihazının engeli kaldırıldı.", { peer }))
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }

  async function scan() {
    setScanning(true)
    try {
      const res = await fetcher<{ findings: DoHFinding[] }>("/api/app/guards/doh")
      setDoh(res.findings)
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setScanning(false)
    }
  }

  const threats = data.threats.slice().reverse()
  return (
    <DetailSection
      id="tehditler"
      title={t("Tehditler")}
      description={t("Port taraması ve tuzak algılamaları yalnızca bu cihazda tutulur. DNSSEC sayaçları, çıkış düğümü recursive-dnssec çözücüsü kullanırken dolar.")}
      framed={false}
      action={
        <Button variant="outline" onClick={scan} disabled={scanning}>
          {scanning ? <Spinner data-icon="inline-start" /> : null}
          {t("Tarayıcı DNS ayarlarını denetle")}
        </Button>
      }
    >
      {doh ? (
        doh.some((f) => f.bypass) ? (
          <Alert variant="destructive">
            <AlertDescription>
              {t("{list} DNS'i kendi DoH sunucusuna gönderiyor; MagicDNS adları ve çıkış düğümü çözücüsü atlanır. Tarayıcının güvenli DNS ayarını kapat.", {
                list: doh
                  .filter((f) => f.bypass)
                  .map((f) => `${f.browser} (${f.profile})${f.resolver ? `: ${f.resolver}` : ""}`)
                  .join(", "),
              })}
            </AlertDescription>
          </Alert>
        ) : (
          <p className="text-sm text-muted-foreground">{t("Tarayıcılarda sistem çözücüsünü atlayan DoH ayarı bulunmadı.")}</p>
        )
      ) : null}
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="text-muted-foreground">DNSSEC</span>
        <SettingBadge>{t("güvenli {n}", { n: data.dnssec.secure })}</SettingBadge>
        <SettingBadge>{t("imzasız {n}", { n: data.dnssec.insecure })}</SettingBadge>
        <SettingBadge tone={data.dnssec.bogus > 0 ? "danger" : "muted"}>{t("reddedilen {n}", { n: data.dnssec.bogus })}</SettingBadge>
      </div>
      {data.blocked.length > 0 ? (
        <ListTable label={t("Engellenen cihazlar")}>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className={headCell}>{t("Engellenen cihaz")}</TableHead>
              <TableHead className={headCell}>{t("Engel bitişi")}</TableHead>
              <TableHead className="w-12">
                <span className="sr-only">{t("İşlemler")}</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.blocked.map((b) => (
              <TableRow key={b.peer}>
                <TableCell className="font-medium">{b.peer}</TableCell>
                <TableCell className="text-sm text-muted-foreground">{formatDateTime(b.until)}</TableCell>
                <TableCell className="text-right">
                  {readOnly ? null : (
                    <RowMenu label={t("{peer} engeli için işlemler", { peer: b.peer })} className="w-44">
                      <DropdownMenuItem onClick={() => unblock(b.peer)}>{t("Engeli kaldır")}</DropdownMenuItem>
                    </RowMenu>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </ListTable>
      ) : null}
      {threats.length === 0 ? (
        <EmptyNote>{data.running ? t("Algılama yok.") : t("Tünel çalışmıyor.")}</EmptyNote>
      ) : (
        <ListTable label={t("Algılamalar")} className="max-h-[28rem] overflow-y-auto">
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className={headCell}>{t("Zaman")}</TableHead>
              <TableHead className={headCell}>{t("Algılama")}</TableHead>
              <TableHead className={cn(headCell, "hidden sm:table-cell")}>{t("Ayrıntı")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {threats.map((th, i) => (
              <TableRow key={`${th.at}-${i}`}>
                <TableCell className="text-sm text-muted-foreground">{formatDateTime(th.at)}</TableCell>
                <TableCell>
                  <span className="flex flex-col gap-0.5">
                    <span className="text-sm font-medium">{threatKindText[th.kind] ? t(threatKindText[th.kind]) : th.kind}</span>
                    <span className="text-sm text-muted-foreground sm:hidden">{threatDetail(th)}</span>
                  </span>
                </TableCell>
                <TableCell className="hidden text-sm text-muted-foreground sm:table-cell">{threatDetail(th)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </ListTable>
      )}
      <div className="flex flex-col gap-3 pt-2">
        <h3 className="text-sm font-medium">{t("Algılama ve çözücü ayarları")}</h3>
        <div className="border-y py-5">
          <GuardSettingsForm key={JSON.stringify(data.settings)} settings={data.settings} onSaved={(s) => mutate(s, { revalidate: false })} />
        </div>
      </div>
    </DetailSection>
  )
}

function threatDetail(th: { peer?: string; count?: number; port?: number }): string {
  return [th.peer, th.count ? tx("{count} hedef", { count: th.count }) : "", th.port ? tx("port {port}", { port: th.port }) : ""].filter(Boolean).join(" · ") || "-"
}

function GuardSettingsForm({ settings, onSaved }: { settings: GuardSettings; onSaved: (s: GuardStatus) => void }) {
  const readOnly = useReadOnly()
  const { t } = useI18n()
  const [v, setV] = useState(settings)
  const [busy, setBusy] = useState(false)
  const dirty = JSON.stringify(v) !== JSON.stringify(settings)

  async function save() {
    setBusy(true)
    try {
      onSaved(
        await post<GuardStatus>("/api/app/guards", {
          exitDnsUpstream: v.exitDnsUpstream.trim(),
          exitDnsBlocklist: v.exitDnsBlocklist.trim(),
          dnssecTrustAnchors: v.dnssecTrustAnchors.trim(),
          threatScan: v.threatScan,
          threatBlock: v.threatBlock,
        }),
      )
      toast.success(t("Kaydedildi; tünel kısa süreliğine yeniden başlatılıyor."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <FieldGroup>
      <DnsEnforceSwitch />
      <Field orientation="horizontal">
        <FieldContent>
          <FieldLabel htmlFor="g-scan">{t("Port taramasını algıla")}</FieldLabel>
        </FieldContent>
        <Switch id="g-scan" checked={v.threatScan} disabled={readOnly} onCheckedChange={(c) => setV((s) => ({ ...s, threatScan: c }))} />
      </Field>
      <Field orientation="horizontal">
        <FieldContent>
          <FieldLabel htmlFor="g-block">{t("Tarayan cihazı geçici olarak engelle")}</FieldLabel>
          <FieldDescription>{t("Yanlış alarmda engel buradan veya \"openscale threats unblock\" ile kaldırılır.")}</FieldDescription>
        </FieldContent>
        <Switch id="g-block" checked={v.threatBlock} disabled={readOnly} onCheckedChange={(c) => setV((s) => ({ ...s, threatBlock: c }))} />
      </Field>
      <Field>
        <FieldLabel htmlFor="g-up">{t("Çıkış düğümü üst çözücüsü")}</FieldLabel>
        <Input
          id="g-up"
          placeholder={t("boş: sistem çözücüsü; recursive-dnssec, tls://…, https://…")}
          value={v.exitDnsUpstream}
          maxLength={255}
          disabled={readOnly}
          onChange={(e) => setV((s) => ({ ...s, exitDnsUpstream: e.target.value }))}
        />
        <FieldDescription>{t("Yalnızca bu bilgisayar çıkış düğümüyken üyelerin DNS sorgularına uygulanır.")}</FieldDescription>
      </Field>
      <Field>
        <FieldLabel htmlFor="g-block-list">{t("Engel listesi dosyası")}</FieldLabel>
        <Input
          id="g-block-list"
          placeholder={t("C:\\OpenScale\\engel.txt")}
          value={v.exitDnsBlocklist}
          maxLength={1024}
          disabled={readOnly}
          onChange={(e) => setV((s) => ({ ...s, exitDnsBlocklist: e.target.value }))}
        />
        <FieldDescription>{t("Yerel dosya; hiçbir liste indirilmez.")}</FieldDescription>
      </Field>
      {dirty ? (
        <Button className="self-start" onClick={save} disabled={busy || readOnly}>
          {busy ? <Spinner /> : null}
          {t("Kaydet")}
        </Button>
      ) : null}
    </FieldGroup>
  )
}
