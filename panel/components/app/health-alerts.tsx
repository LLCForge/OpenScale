"use client"

import { Info, ShieldAlert, TriangleAlert } from "lucide-react"

import { useAppStatus } from "@/components/app/use-app-status"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import type { AlertLevel, HealthAlert } from "@/lib/types"

const levelIcon: Record<AlertLevel, React.ReactNode> = {
  danger: <ShieldAlert />,
  warning: <TriangleAlert />,
  info: <Info />,
}

/** Title of an alert code the panel does not know yet. */
const fallbackTitle = msg("Uyarı")

/** Short titles of the service's alert codes (F-193). */
const titles: Record<string, string> = {
  tunnel_down: msg("Tünel çalışmıyor"),
  tunnel_paused: msg("Bağlantı kapalı"),
  device_removed: msg("Bu bilgisayar ağdan çıkarılmış"),
  coordinator_unreachable: msg("Koordinatöre ulaşılamıyor"),
  coordinator_failed: msg("Koordinatör çalışmıyor"),
  dns_not_applied: msg("MagicDNS ayarlanamadı"),
  dns_network_failed: msg("Ağ DNS ayarları uygulanamadı"),
  dns_overwritten: msg("DNS ayarları başka bir programca değiştirildi"),
  dns_group_policy: msg("Grup İlkesi DNS kuralları"),
  dns_resolver_unreachable: msg("Ağın DNS çözücüsüne ulaşılamıyor"),
  exit_unreachable: msg("Çıkış düğümü kullanılamıyor"),
  killswitch_failed: msg("Sızıntı kilidi (kill switch) sorunu"),
  membership_expiring: msg("Üyelik süresi"),
  document_expiring: msg("Ağ belgesinin süresi"),
  clock_skew: msg("Saat yanlış görünüyor"),
  join_failed: msg("Ağa katılım başarısız"),
  captive_portal: msg("Giriş sayfası (captive portal)"),
}

/**
 * The service's health alerts for this computer. `only` limits them to some
 * codes (for example on the exit node card); `skip` leaves codes out that a
 * page already shows in its own way.
 */
export function HealthAlerts({ only, skip, label = msg("Bu bilgisayarın durumu") }: { only?: string[]; skip?: string[]; label?: string }) {
  const { t } = useI18n()
  const { status } = useAppStatus()
  const alerts = (status?.health ?? []).filter((a) => (!only || only.includes(a.code)) && !(skip ?? []).includes(a.code))
  if (alerts.length === 0) return null
  return (
    <section aria-label={t(label)} className="flex flex-col gap-2">
      {alerts.map((a) => (
        <HealthAlertRow key={`${a.code}-${a.message}`} alert={a} />
      ))}
    </section>
  )
}

/** Short title of a health alert code, in the current language. */
export function healthTitle(code: string): string {
  return tx(titles[code] ?? fallbackTitle)
}

function HealthAlertRow({ alert }: { alert: HealthAlert }) {
  const { t, ts } = useI18n()
  return (
    <Alert variant={alert.level === "danger" ? "destructive" : "default"} data-code={alert.code}>
      {levelIcon[alert.level]}
      <AlertTitle>{t(titles[alert.code] ?? fallbackTitle)}</AlertTitle>
      <AlertDescription className="text-pretty">{ts(alert.message)}</AlertDescription>
    </Alert>
  )
}
