"use client"

import useSWR from "swr"
import { Download } from "lucide-react"

import { SettingDisclosure, SettingRow, SettingsSection } from "@/components/settings/settings-layout"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { errorMessage, fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { NetworkReport } from "@/lib/p12-types"

// Readable network report (#553): devices, groups, rules as sentences, DNS
// and coordinators, for a printout or a colleague. It holds no key,
// fingerprint, signature or invite code. The HTML version is only
// downloaded, never shown inside the panel's origin.

const REPORT = "/api/network/report"

export function NetworkReportSection() {
  const { t } = useI18n()
  return (
    <SettingsSection
      id="okunur-rapor"
      title={t("Okunur rapor")}
      description={t("Ağın cihazlarını, kurallarını ve adlarını düz metin olarak indir.")}
    >
      <SettingRow
        title={t("Raporu indir")}
        description={t("Rapor anahtar, parmak izi veya davet kodu içermez; ağa giriş sağlamaz. Cihaz adlarını, tünel adreslerini, kuralları ve koordinatör adresini içerir; kimle paylaştığına dikkat et.")}
        action={
          <>
            <Button variant="outline" nativeButton={false} render={<a href={`${REPORT}?format=md`} download />}>
              <Download data-icon="inline-start" />
              {t("Markdown indir")}
            </Button>
            <Button variant="outline" nativeButton={false} render={<a href={`${REPORT}?format=html`} download />}>
              <Download data-icon="inline-start" />
              {t("HTML indir")}
            </Button>
          </>
        }
      />
      <SettingDisclosure title={t("Kurallar cümle olarak")} description={t("Raporun kural bölümünün önizlemesi.")} openLabel={t("Önizle")}>
        <RulePreview />
      </SettingDisclosure>
    </SettingsSection>
  )
}

function RulePreview() {
  const { t, ts } = useI18n()
  const { data, error } = useSWR<NetworkReport>(`${REPORT}?format=json`, fetcher, { revalidateOnFocus: false })
  if (error) return <p className="text-sm text-destructive">{errorMessage(error)}</p>
  if (!data) return <Skeleton className="h-24 w-full" />
  if (data.rules.length === 0) return <p className="text-sm text-muted-foreground">{t("Ağda kural yok; hiçbir cihaz başka cihaza ulaşamaz.")}</p>
  return (
    <ol className="flex flex-col divide-y border-y text-sm">
      {data.rules.map((r) => (
        <li key={r.number} className="flex gap-3 py-2">
          <span className="w-6 shrink-0 text-right text-muted-foreground tabular-nums">{r.number}</span>
          <span className={r.disabled ? "text-muted-foreground line-through text-pretty" : "text-pretty"}>
            {ts(r.sentence)}
            {r.disabled ? <span className="sr-only"> {t("(kapalı)")}</span> : null}
          </span>
        </li>
      ))}
    </ol>
  )
}
