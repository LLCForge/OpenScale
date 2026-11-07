"use client"

import { HealthAlerts } from "@/components/app/health-alerts"
import { useAppStatus } from "@/components/app/use-app-status"
import { useRemoteSession } from "@/components/auth/session"
import { AuditCard } from "@/components/diag/audit-card"
import { DeniedCard } from "@/components/diag/denied-card"
import { DiagErrorsProvider } from "@/components/diag/diag-errors"
import { EventsCard } from "@/components/diag/events-card"
import { FlightRecorderCard } from "@/components/diag/flight-recorder-card"
import { GuardsCard } from "@/components/diag/guards-card"
import { LiveUpdates } from "@/components/diag/live-updates"
import { NetcheckCard } from "@/components/diag/netcheck-card"
import { ObserveSettingsCard } from "@/components/diag/observe-settings-card"
import { PathsCard } from "@/components/diag/paths-card"
import { ResourcesCard } from "@/components/diag/resources-card"
import { TroubleshootWizard } from "@/components/diag/troubleshoot-wizard"
import { PageHeader } from "@/components/page-header"
import { EmptyNote, SettingsColumn } from "@/components/settings/settings-layout"
import { useI18n } from "@/lib/i18n/i18n"

/**
 * Günlükler > Tanı: this computer's connection, network check, events,
 * refused connections, the audit log, threats and notifications, each as a
 * section with its one action at the right of the section title.
 */
export function DiagView() {
  const { t } = useI18n()
  const { status, isApp } = useAppStatus()
  const remote = useRemoteSession()
  const running = status?.device?.running ?? false
  // Until the status arrives the live sections stay, as before.
  const live = !status || running

  return (
    <SettingsColumn className="max-w-5xl">
      <PageHeader title={t("Tanı")} description={t("Bağlantı sorunlarını bulmak için ağ denetimi, eş yolları, olaylar ve güvenlik kayıtları.")} />
      {remote ? (
        <EmptyNote>{t("Tanı bilgileri yalnızca o bilgisayarın kendi panelinde görünür; uzak panel bunları göstermez.")}</EmptyNote>
      ) : !isApp ? (
        <EmptyNote>
          {t("Tanı bilgileri bu bilgisayarın tünelinden gelir ve yalnızca masaüstü uygulamasında görünür. Komut satırında:")}{" "}
          <code className="font-mono text-[0.8125rem]">openscale status</code>, <code className="font-mono text-[0.8125rem]">openscale netcheck</code>.
        </EmptyNote>
      ) : (
        <DiagErrorsProvider>
          <LiveUpdates />
          <HealthAlerts />
          <TroubleshootWizard />
          {status && !running ? (
            <section aria-labelledby="baglanti-baslik" className="flex flex-col gap-3">
              <h2 id="baglanti-baslik" className="text-base font-semibold">
                {t("Bağlantı")}
              </h2>
              <EmptyNote>{t("Tünel çalışmıyor. Bağlantıyı açınca eş yolları ve ağ denetimi burada görünür.")}</EmptyNote>
            </section>
          ) : (
            <>
              <PathsCard />
              <NetcheckCard />
            </>
          )}
          <EventsCard />
          <FlightRecorderCard />
          {live ? <DeniedCard /> : null}
          <AuditCard />
          {live ? <GuardsCard /> : null}
          <ResourcesCard />
          <ObserveSettingsCard />
        </DiagErrorsProvider>
      )}
    </SettingsColumn>
  )
}
