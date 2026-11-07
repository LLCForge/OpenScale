"use client"

import { useState } from "react"
import { RefreshCw } from "lucide-react"
import { toast } from "sonner"

import { DetailGroup, DetailItem, DetailSection } from "@/components/devices/detail-card"
import { EmptyNote, SettingBadge } from "@/components/settings/settings-layout"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { errorMessage, fetcher } from "@/lib/api"
import { nsToMs, type NetReport } from "@/lib/diag"
import { formatDateTime } from "@/lib/format"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"

const natLabels: Record<string, string> = {
  // i18n-ignore: anahtarlar sunucunun NAT türü kodları (yok, kolay, zor), görünen metin değil
  yok: msg("NAT yok"),
  kolay: msg("Kolay NAT"),
  zor: msg("Zor (simetrik) NAT"),
  bilinmiyor: msg("Henüz bilinmiyor"),
}

function yesNo(b: boolean): string {
  return b ? tx("Evet") : tx("Hayır")
}

/**
 * Network check (F-015): measured only against the owner's coordinator and
 * peers. It sends one control request, so it runs on demand only.
 */
export function NetcheckCard() {
  const { t, ts } = useI18n()
  const [report, setReport] = useState<NetReport | null>(null)
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    try {
      setReport(await fetcher<NetReport>("/api/app/diag/netcheck"))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const rows: { label: string; value: React.ReactNode }[] = report
    ? [
        {
          label: t("Koordinatör (UDP)"),
          value: report.coordinator_reachable ? (
            <span>
              {t("Ulaşılıyor")} · {nsToMs(report.coordinator_rtt)}
              {report.coordinator_over_ipv6 ? " · IPv6" : ""}
            </span>
          ) : (
            <span className="text-destructive">
              {t("Ulaşılamıyor")}
              {report.coordinator_error ? ` · ${ts(report.coordinator_error)}` : ""}
            </span>
          ),
        },
        { label: t("NAT türü"), value: natLabels[report.nat] ? t(natLabels[report.nat]) : report.nat },
        { label: t("Dış adres"), value: <span className="font-mono">{report.mapped_endpoint || "-"}</span> },
        { label: t("Yerel port"), value: t("{port} · korunuyor: {kept}", { port: report.local_port, kept: yesNo(report.port_preserved) }) },
        { label: "IPv4 / IPv6", value: `${yesNo(report.have_ipv4)} / ${yesNo(report.have_ipv6)}` },
        {
          label: t("Eşler"),
          value: t("{direct} doğrudan · {relayed} aktarıcı · {ipv6} IPv6", { direct: report.direct_peers, relayed: report.relayed_peers, ipv6: report.ipv6_peers }),
        },
        { label: t("Son bir saatte adres değişimi"), value: String(report.mapping_changes) },
      ]
    : []

  return (
    <DetailSection
      id="ag-denetimi"
      title={t("Ağ denetimi")}
      description={t("Koordinatöre UDP ile ulaşılabildiğini, NAT türünü ve IPv4/IPv6 durumunu ölçer. Yalnızca kendi koordinatörün ve eşlerin kullanılır; istek üzerine çalışır.")}
      framed={false}
      action={
        <Button variant="outline" onClick={run} disabled={busy}>
          {busy ? <Spinner data-icon="inline-start" /> : <RefreshCw data-icon="inline-start" />}
          {t("Denetle")}
        </Button>
      }
    >
      {report ? (
        <div className="flex flex-col gap-4 border-y py-5">
          <DetailGroup>
            {rows.map((r) => (
              <DetailItem key={r.label} label={r.label}>
                {r.value}
              </DetailItem>
            ))}
          </DetailGroup>
          {report.captive_portal.detected ? <SettingBadge tone="danger">{t("Giriş sayfası algılandı")}</SettingBadge> : null}
          {report.notes && report.notes.length > 0 ? (
            <ul className="flex list-disc flex-col gap-1 pl-5 text-sm leading-relaxed text-muted-foreground">
              {report.notes.map((n) => (
                <li key={n} className="text-pretty">
                  {ts(n)}
                </li>
              ))}
            </ul>
          ) : null}
          <p className="text-sm text-muted-foreground">{t("Ölçüm: {at}", { at: formatDateTime(report.at) })}</p>
        </div>
      ) : (
        <EmptyNote>{t("Sonuç görmek için “Denetle”ye bas.")}</EmptyNote>
      )}
    </DetailSection>
  )
}
