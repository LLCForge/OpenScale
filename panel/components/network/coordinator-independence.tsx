"use client"

import useSWR from "swr"

import { CodeLine } from "@/components/copy-field"
import { CoordinatorObservation } from "@/components/network/coordinator-observation"
import { MembersOnlyCard } from "@/components/network/members-only-card"
import { QueryState } from "@/components/query-state"
import { SettingBadge, SettingRow, SettingsSection } from "@/components/settings/settings-layout"
import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { IndependenceReply } from "@/lib/pa-types"
import { cn } from "@/lib/utils"

function severityTone(s: string): string {
  if (s === "critical") return "bg-destructive/10 text-destructive"
  if (s === "warning") return "bg-warning/15 text-warning-foreground dark:text-warning"
  return "bg-secondary text-muted-foreground"
}

/**
 * Ağ > Koordinatörler (ADR-0183, #631): whether the coordinators are
 * independent enough for devices to check documents against each other,
 * plus where the server-side hardening lives (ADR-0181, ADR-0185).
 */
export function CoordinatorIndependence() {
  const { t, ts } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<IndependenceReply>("/api/g2/coordinators/independence", fetcher)
  const coordinators = data?.coordinators ?? []
  const findings = data?.findings ?? []
  return (
    <>
      <SettingsSection
        id="bagimsizlik"
        title={t("Çapraz denetim")}
        description={t("Cihazlar belgeyi birden fazla koordinatörden alıp karşılaştırır; farklı sağlayıcı ve bölgeler bir koordinatörün yalan söylemesini görünür kılar.")}
      >
        <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
          {data ? (
            <>
              {coordinators.map((c) => (
                <SettingRow
                  key={c.label}
                  title={<span className="font-mono">{c.label}</span>}
                  action={<SettingBadge>{c.region || t("Bölge bilinmiyor")}</SettingBadge>}
                />
              ))}
              {findings.length === 0 ? (
                <SettingRow title={t("Durum")} description={t("Koordinatörler farklı bölgelerde; cihazlar belgeleri birbirine karşı denetleyebilir.")} />
              ) : (
                <div data-slot="setting-row" className="flex flex-col gap-2 py-5">
                  {findings.map((f, i) => (
                    <p key={`${f.kind}-${i}`} role={f.severity === "critical" ? "alert" : undefined} className={cn("rounded-lg px-3 py-2 text-sm text-pretty", severityTone(f.severity))}>
                      {ts(f.message)}
                    </p>
                  ))}
                </div>
              )}
            </>
          ) : null}
        </QueryState>
      </SettingsSection>
      <CoordinatorObservation />
      <MembersOnlyCard />
      <SettingsSection
        id="sertlestirme"
        title={t("Sunucu sertleştirmesi")}
        description={t("Koordinatör sertleştirmesi sunucuda 'openscale coordinator harden' ile açılır: port gizleme, kayıt tutmama, yalnızca RAM, kör koordinatör, klon karantinası.")}
      >
        <SettingRow title={t("Sunucuda çalıştırın")} description={t("Panel koordinatörde çalışmadığı için bu ayarlar buradan değiştirilmez.")}>
          <CodeLine value="openscale coordinator harden --state-dir /var/lib/openscale-coordinator --spa on --no-metadata on" />
        </SettingRow>
      </SettingsSection>
    </>
  )
}
