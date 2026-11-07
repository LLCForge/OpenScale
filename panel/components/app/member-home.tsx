"use client"

import { ChevronDown } from "lucide-react"

import { ConnectionRow } from "@/components/app/connection-card"
import { ExitAutoCard } from "@/components/app/exit-auto-card"
import { ExitNodeCard } from "@/components/app/exit-node-card"
import { HealthAlerts } from "@/components/app/health-alerts"
import { PinButton } from "@/components/app/pin-button"
import { PostQuantumBadge } from "@/components/app/post-quantum-badge"
import { RemovedCard } from "@/components/app/removed-card"
import { CodeLine, CopyButton } from "@/components/copy-field"
import { CopyLink, DetailGroup, DetailItem } from "@/components/devices/detail-card"
import { DeviceStatus } from "@/components/devices/device-status"
import { LeaveRow } from "@/components/membership/leave-card"
import { PageHeader } from "@/components/page-header"
import { AdvancedCard } from "@/components/security/advanced-card"
import { LocalSecurityCard } from "@/components/security/local-security-card"
import { headCell, ListTable } from "@/components/settings/list-table"
import { EmptyNote, SettingBadge, SettingRow, SettingsColumn, SettingsSection } from "@/components/settings/settings-layout"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { formatDateTime } from "@/lib/format"
import { tx, useI18n } from "@/lib/i18n/i18n"
import type { AppStatus, DeviceStatus as DeviceState, PeerInfo } from "@/lib/types"
import { cn } from "@/lib/utils"

/** Alerts shown inside their own cards instead of the list at the top. */
const alertsShownElsewhere = ["device_removed", "killswitch_failed", "exit_unreachable", "tunnel_paused"]

/**
 * Home screen of a computer that joined the network but holds no root
 * key. A member sees four things: the connection, the devices it can
 * reach, the exit node and leaving the network. Everything else that only
 * tunes this computer sits behind the closed "Gelişmiş" disclosure.
 */
export function MemberHome({ status }: { status: AppStatus }) {
  const { t, ts } = useI18n()
  const device = status.device
  const peers = device?.peers ?? []

  return (
    <SettingsColumn>
      <PageHeader
        title={device?.name ? device.name : t("Bu bilgisayar")}
        description={t("Bu bilgisayar ağa üye. Cihazları ve erişim kurallarını ağın yöneticisi değiştirir.")}
      />
      {device?.removed || healthHasAlerts(status) ? (
        <div className="flex flex-col gap-2">
          {device?.removed ? <RemovedCard onReset={() => window.location.reload()} /> : null}
          <HealthAlerts skip={alertsShownElsewhere} />
        </div>
      ) : null}

      <SettingsSection id="baglanti" title={t("Bağlantı")} description={syncLine(device)}>
        <ConnectionRow />
        {device ? <TunnelProblem device={device} /> : null}
      </SettingsSection>

      {device && !device.removed ? <Addresses device={device} /> : null}

      {/* i18n-ignore: sayfa içi bağlantı kimliği */}
      <section id="cihazlar" aria-labelledby="cihazlar-baslik" className="flex scroll-mt-24 flex-col gap-3">
        <div className="flex flex-col gap-1">
          {/* i18n-ignore: sayfa içi bağlantı kimliği */}
          <h2 id="cihazlar-baslik" className="text-base font-semibold">
            {t("Ulaşabildiğin cihazlar")}
          </h2>
          <p className="text-sm text-pretty text-muted-foreground">
            {t("Erişim kuralları bu bilgisayarın hangi cihazlarla konuşabileceğini belirler.")}
          </p>
        </div>
        {peers.length === 0 ? (
          <EmptyNote>{t("Görünen cihaz yok. Yönetici bir erişim kuralı eklediğinde cihazlar burada listelenir.")}</EmptyNote>
        ) : (
          <PeerTable peers={peers} />
        )}
        <details className="group/req rounded-lg border">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-sm font-medium outline-none hover:bg-muted/40 focus-visible:ring-3 focus-visible:ring-ring/50 [&::-webkit-details-marker]:hidden">
            {t("Başka bir cihaza erişim iste")}
            <ChevronDown className="size-4 shrink-0 text-muted-foreground transition-transform group-open/req:rotate-180" aria-hidden="true" />
          </summary>
          <div className="flex flex-col gap-2 border-t px-4 py-3">
            <p className="text-sm text-pretty text-muted-foreground">
              {t(
                "Bu bilgisayarda komutu çalıştır ve çıkan satırı ağ yöneticisine ilet. İstek bu bilgisayarın anahtarıyla imzalanır; yönetici onaylarsa erişim istediğin süre kadar açılır ve kendiliğinden kapanır.",
              )}
            </p>
            <CodeLine
              value={t("openscale access request --to <cihaz> --service ssh --users <hesap> --hours 8")}
              label={t("Komutu kopyala")}
            />
          </div>
        </details>
      </section>

      <SettingsSection id="cikis" title={t("Çıkış düğümü")} description={t("Bu bilgisayarın internet trafiğinin nereden çıkacağı.")}>
        <ExitNodeCard />
        <ExitAutoCard />
      </SettingsSection>

      {status.coordinator ? (
        <SettingsSection id="koordinator" title={t("Koordinatör")} description={t("Bu bilgisayar ağın koordinatörünü de çalıştırıyor.")}>
          <SettingRow
            title={t("Koordinatör bu bilgisayarda")}
            badge={
              status.coordinator.running ? (
                <SettingBadge tone="success">{t("Çalışıyor")}</SettingBadge>
              ) : (
                <SettingBadge tone="danger">{t("Çalışmıyor")}</SettingBadge>
              )
            }
            description={
              <>
                {status.coordinator.running
                  ? status.coordinator.endpoint
                  : status.coordinator.error
                    ? ts(status.coordinator.error)
                    : t("Koordinatör durdu.")}
                {status.coordinator.tcpAddr ? ` · ${t("TCP yedek taşıma: {addr}", { addr: status.coordinator.tcpAddr })}` : ""}
              </>
            }
            action={status.coordinator.running ? <CopyLink value={status.coordinator.endpoint} label={t("Koordinatör adresini")} /> : null}
          />
        </SettingsSection>
      ) : null}

      {device && !device.removed ? <AdvancedDisclosure /> : null}

      {device && !device.removed ? (
        <SettingsSection id="tehlikeli-bolge" title={t("Tehlikeli bölge")} tone="danger">
          <LeaveRow />
        </SettingsSection>
      ) : null}
    </SettingsColumn>
  )
}

function syncLine(device: DeviceState | null): string {
  if (!device) return tx("Bu bilgisayarın özel ağa bağlı olup olmadığı.")
  return device.lastSync
    ? tx("Ağ bilgisi en son {time} tarihinde eşitlendi.", { time: formatDateTime(device.lastSync) })
    : tx("Ağ bilgisi henüz eşitlenmedi.")
}

/**
 * The connection row already says "Bağlı"; a second badge only appears
 * when the tunnel is down or the coordinator cannot be reached.
 */
function TunnelProblem({ device }: { device: DeviceState }) {
  const { t, ts } = useI18n()
  if (device.removed || !device.connected) return null
  if (!device.running) {
    return (
      <SettingRow
        title={t("Tünel kapalı")}
        badge={<SettingBadge tone="danger">{t("Çalışmıyor")}</SettingBadge>}
        description={
          device.error
            ? ts(device.error)
            : t("OpenScale servisi tüneli açamadı. Bilgisayarı yeniden başlatmayı dene; sürerse yöneticiye haber ver.")
        }
      />
    )
  }
  if (device.lastSyncError || device.error) {
    return (
      <SettingRow
        title={t("Koordinatöre ulaşılamıyor")}
        badge={<SettingBadge tone="warning">{t("Eşitlenemiyor")}</SettingBadge>}
        description={
          <>
            {ts(device.lastSyncError || device.error || "")}{" "}
            {t("Mevcut cihazlarla bağlantı sürer; yeni cihazlar ve kural değişiklikleri koordinatöre ulaşınca gelir.")}
          </>
        }
      />
    )
  }
  return null
}

/** This computer's own addresses, each with a copy action. */
function Addresses({ device }: { device: DeviceState }) {
  const { t } = useI18n()
  return (
    <section id="adresler" aria-labelledby="adresler-baslik" className="flex scroll-mt-24 flex-col gap-3">
      <h2 id="adresler-baslik" className="text-base font-semibold">
        {t("Bu bilgisayarın adresleri")}
      </h2>
      <div className="flex flex-col gap-4 border-y py-5">
        <DetailGroup>
          <DetailItem label={t("Özel IP")} copy={device.ipv4 || undefined}>
            <span className="font-mono">{device.ipv4 || "-"}</span>
          </DetailItem>
          <DetailItem label={t("DNS adı")} copy={device.fqdn || undefined}>
            <span className="font-mono break-all">{device.fqdn || "-"}</span>
          </DetailItem>
          {device.ipv6 ? (
            <DetailItem label="IPv6" copy={device.ipv6}>
              <span className="font-mono break-all">{device.ipv6}</span>
            </DetailItem>
          ) : null}
        </DetailGroup>
        {device.coordinatorOverTcp ? (
          <p className="text-sm text-pretty text-muted-foreground">
            {t("Bu ağ UDP'yi engelliyor; denetim trafiği TCP yedek taşımasından geçiyor. Bağlantı çalışır, biraz daha yavaş olabilir.")}
          </p>
        ) : null}
      </div>
    </section>
  )
}

function PeerTable({ peers }: { peers: PeerInfo[] }) {
  const { t } = useI18n()
  return (
    <ListTable label={t("Ulaşabildiğin cihazlar")}>
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className={headCell}>{t("Cihaz")}</TableHead>
          <TableHead className={cn(headCell, "hidden sm:table-cell")}>{t("Adres")}</TableHead>
          <TableHead className="w-10">
            <span className="sr-only">{t("Sabitle")}</span>
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {peers.map((p) => (
          <TableRow key={p.name}>
            <TableCell className="whitespace-normal">
              <div className="flex min-w-0 flex-col gap-1">
                <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="font-medium break-all">{p.name}</span>
                  <DeviceStatus status={p.online ? "online" : "offline"} lastSeen={null} className="text-sm" />
                  <PostQuantumBadge state={p.postQuantum} />
                </span>
                <span className="font-mono text-[0.8125rem] break-all text-muted-foreground">{p.fqdn}</span>
                <span className="flex items-center gap-1 sm:hidden">
                  <span className="font-mono text-sm">{p.ipv4}</span>
                  <CopyButton value={p.ipv4} label={t("{name} IP adresini kopyala", { name: p.name })} />
                </span>
              </div>
            </TableCell>
            <TableCell className="hidden align-top sm:table-cell">
              <span className="flex items-center gap-1">
                <span className="font-mono text-sm">{p.ipv4}</span>
                <CopyButton value={p.ipv4} label={t("{name} IP adresini kopyala", { name: p.name })} />
              </span>
            </TableCell>
            <TableCell className="text-right align-top">
              <PinButton name={p.name} pinned={p.pinned} />
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </ListTable>
  )
}

/**
 * Settings that only tune this computer (incoming connections, MTU,
 * post-quantum keys, keepalive, TCP fallback). Closed by default; a member
 * rarely needs them and the owner's panel shows the same controls.
 */
function AdvancedDisclosure() {
  const { t } = useI18n()
  return (
    <section id="gelismis" aria-labelledby="gelismis-baslik" className="scroll-mt-24">
      <details className="group/adv border-y">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-4 rounded-lg py-4 outline-none focus-visible:ring-3 focus-visible:ring-ring/50 [&::-webkit-details-marker]:hidden">
          <span className="flex min-w-0 flex-col gap-1">
            <h2 id="gelismis-baslik" className="text-base font-semibold">
              {t("Gelişmiş")}
            </h2>
            <span className="text-sm text-pretty text-muted-foreground">
              {t("Gelen bağlantılar ve tünel ayarları. Yalnızca bu bilgisayarda geçerli; ağ belgesini değiştirmez.")}
            </span>
          </span>
          <ChevronDown aria-hidden="true" className="size-4 shrink-0 text-muted-foreground transition-transform group-open/adv:rotate-180" />
        </summary>
        <div className="flex flex-col gap-4 pb-5">
          <LocalSecurityCard />
          <AdvancedCard />
        </div>
      </details>
    </section>
  )
}

function healthHasAlerts(status: AppStatus): boolean {
  return status.health.some((a) => !alertsShownElsewhere.includes(a.code))
}
