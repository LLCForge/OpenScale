"use client"

import { useRef, useState } from "react"
import Link from "next/link"
import { useSearchParams } from "next/navigation"
import useSWR from "swr"
import { ArrowDownLeft, ArrowUpRight, ChevronDown, ListTree, Settings, SmartphoneNfc } from "lucide-react"

import { HealthAlerts } from "@/components/app/health-alerts"
import { PostQuantumBadge } from "@/components/app/post-quantum-badge"
import { useReadOnly } from "@/components/app/read-only"
import { useAppStatus } from "@/components/app/use-app-status"
import { RemoteActionsCard } from "@/components/apps/remote-actions-card"
import { ConnectionCardDialog } from "@/components/devices/connection-card-dialog"
import { CopyLink, DetailGroup, DetailItem, DetailSection, shortKey } from "@/components/devices/detail-card"
import { LastSeen } from "@/components/devices/device-status"
import { DeviceIconDialog, DeviceTypeIcon } from "@/components/devices/device-icon" // #233, ADR-0232
import { DeviceTagsDialog } from "@/components/devices/device-tags-dialog"
import { ExitAccessNote } from "@/components/devices/exit-access-note"
import { ExtendMembershipDialog } from "@/components/devices/extend-membership-dialog"
import { HardwareSections } from "@/components/devices/hardware-sections"
import { KeyRotationDialog } from "@/components/devices/key-rotation-dialog"
import { LikeDeviceDialog } from "@/components/devices/like-device-dialog"
import { ListeningServicesCard } from "@/components/devices/listening-services-card"
import { LostDeviceDialog } from "@/components/devices/lost-device-dialog"
import { RDeskSessionsCard } from "@/components/devices/rdesk-sessions-card"
import { RenameDeviceDialog } from "@/components/devices/rename-device-dialog"
import { NetworkDriveCard, QualityHistoryCard, SpeedTestCard, WakeOnLanCard } from "@/components/plugins/device-cards"
import { RemoteSessionActions } from "@/components/devices/remote-session-actions"
import { Flag, UsageBar, countryName } from "@/components/devices/system-bits"
import { TrafficHistorySection } from "@/components/devices/traffic-history"
import { UpstreamSummary, upstreamKindText } from "@/components/devices/upstream-status"
import { MaskIcon, OsIcon, osDisplayName } from "@/components/os-icon"
import { QueryState } from "@/components/query-state"
import { EmptyNote, SettingBadge, SettingRow, SettingsSection } from "@/components/settings/settings-layout"
import { SignChangeDialog } from "@/components/sign-change"
import { SupportToolsSection } from "@/components/support/support-tools" // #852, ADR-0232
import { TagList } from "@/components/tag-list"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty"
import { ApiError, fetcher } from "@/lib/api"
import { daysLabel, formatAgo, formatBytes, formatDate, formatDateTime, formatUptime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { RoutesStatus } from "@/lib/routes-types"
import type { DeviceDetail, PostureState, Rule } from "@/lib/types"

type Dialog = "rename" | "extend" | "tags" | "icon" | "rotate" | "expire" | "revoke" | "exit-on" | "exit-off" | "like" | "card" | "lost" | null

export function DeviceDetailView() {
  const name = useSearchParams().get("name") ?? ""
  const key = name ? `/api/devices/detail?name=${encodeURIComponent(name)}` : null
  const { data, error, isLoading, mutate } = useSWR<DeviceDetail>(key, fetcher, { refreshInterval: 5_000 })
  const { t } = useI18n()
  const [dialog, setDialog] = useState<Dialog>(null)
  const sectionsRef = useRef<HTMLDivElement>(null)
  const close = (open: boolean) => {
    if (!open) setDialog(null)
  }

  const notFound = !name || (error instanceof ApiError && error.status === 404)

  return (
    <>
      <nav aria-label={t("Konum")}>
        <ol className="flex min-w-0 items-center gap-1.5 text-sm text-muted-foreground">
          <li className="shrink-0">
            <Link href="/devices" className="hover:text-foreground hover:underline">
              {t("Tüm cihazlar")}
            </Link>
          </li>
          <li aria-hidden="true">/</li>
          <li aria-current="page" className="min-w-0 truncate text-foreground">
            {data?.name ?? name}
          </li>
        </ol>
      </nav>
      {notFound ? (
        <Empty className="border">
          <EmptyHeader>
            <EmptyTitle>{t("Cihaz bulunamadı")}</EmptyTitle>
            <EmptyDescription>{t("Cihaz kaldırılmış veya adı değişmiş olabilir.")}</EmptyDescription>
          </EmptyHeader>
          <EmptyContent>
            <Button nativeButton={false} render={<Link href="/devices" />}>
              {t("Cihaz listesine dön")}
            </Button>
          </EmptyContent>
        </Empty>
      ) : (
        <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
          {data ? (
            <div ref={sectionsRef} className="flex flex-col gap-10">
              <div className="flex flex-col gap-4">
                <Header device={data} onAction={setDialog} sectionsRef={sectionsRef} />
                {data.thisComputer ? <HealthAlerts /> : null}
              </div>
              <DetailsSection device={data} />
              <HardwareSections device={data} />
              <SubnetsSection device={data} />
              <ExitSection device={data} onChange={(on) => setDialog(on ? "exit-on" : "exit-off")} />
              <AccessSection device={data} />
              <ListeningServicesCard device={data.name} />
              {data.thisComputer ? null : <TrafficHistorySection device={data.name} />}
              {data.thisComputer ? null : (
                <>
                  <DetailSection
                    id="uzak-erisim"
                    title={t("Uzak erişim")}
                    description={t("Bu bilgisayardan {name} cihazına tünel içinden yapılabilecekler; karşı cihaz her isteği kurallara göre denetler.", {
                      name: data.name,
                    })}
                  >
                    <RemoteSessionActions device={data.name} os={data.system?.os ?? ""} />
                    <RemoteActionsCard device={data.name} bare />
                  </DetailSection>
                  <DetailSection
                    id="uzak-masaustu"
                    title={t("Uzak masaüstü oturumları")}
                    description={t("Bu cihazın bu bilgisayarda açtığı oturumlar; doğrulama kodu karşı ekrandakiyle aynı olmalı.")}
                  >
                    <RDeskSessionsCard device={data.name} bare />
                  </DetailSection>
                  <DetailSection
                    id="araclar"
                    title={t("Araçlar")}
                    description={t("Bu bilgisayardan cihaza hız testi, bağlantı kalitesi, uyandırma ve ağ sürücüsü.")}
                    framed={false}
                  >
                    <div className="grid gap-4 md:grid-cols-2">
                      <SpeedTestCard device={data.name} />
                      <QualityHistoryCard device={data.name} />
                      <WakeOnLanCard device={data.name} />
                      <NetworkDriveCard name={data.name} />
                    </div>
                  </DetailSection>
                  <SupportToolsSection device={data.name} />
                </>
              )}
              <PostureSection device={data} />
              <DangerSection device={data} onLost={() => setDialog("lost")} />
            </div>
          ) : null}
        </QueryState>
      )}

      <SignChangeDialog
        open={dialog === "exit-on" || dialog === "exit-off"}
        onOpenChange={close}
        title={dialog === "exit-on" ? t("{name} çıkış düğümü olsun", { name }) : t("{name} çıkış düğümü olmasın", { name })}
        description={
          dialog === "exit-on"
            ? t(
                "Cihaza çıkış düğümü rolü verilir ve ağ belgesi yeniden imzalanır. Diğer cihazlar internet trafiğini yalnızca bu rolü taşıyan cihazlardan geçirebilir.",
              )
            : t("Çıkış düğümü rolü kaldırılır; bu cihaz artık başkalarının internet trafiğini taşıyamaz.")
        }
        endpoint="/api/devices/exit-node"
        payload={{ name, exitNode: dialog === "exit-on" }}
        confirmLabel={t("İmzala ve kaydet")}
      />
      <SignChangeDialog
        open={dialog === "revoke"}
        onOpenChange={close}
        title={t("{name} cihazını ağdan kalıcı olarak çıkar", { name })}
        description={t(
          "Bu işlem geri alınamaz: cihazın anahtarları kalıcı olarak iptal edilir. Yalnızca çıkış düğümü rolünü kaldırmak istiyorsan bunu kullanma. Cihaz geri gelmek isterse kendini sıfırlayıp yeni davetle katılması gerekir.",
        )}
        endpoint="/api/devices/revoke"
        payload={{ name }}
        confirmLabel={t("İmzala ve kaldır")}
        destructive
        confirmText={name}
      />
      <SignChangeDialog
        open={dialog === "expire"}
        onOpenChange={close}
        title={t("{name} üyeliğini hemen bitir", { name })}
        description={t(
          "Üyelik şimdi sona erer ve cihaz yeni bağlantı kuramaz. Cihaz belgede kalır, anahtarları iptal edilmez; üyeliği sonradan uzatarak geri açabilirsin. Cihazı kalıcı olarak çıkarmak istiyorsan bunun yerine ağdan çıkar.",
        )}
        endpoint="/api/devices/expire"
        payload={{ name }}
        confirmLabel={t("İmzala ve üyeliği bitir")}
        destructive
      />
      {data ? (
        <>
          <RenameDeviceDialog open={dialog === "rename"} onOpenChange={close} name={data.name} dnsDomain={data.dnsDomain} />
          <DeviceTagsDialog open={dialog === "tags"} onOpenChange={close} name={data.name} tags={data.tags} />
          <DeviceIconDialog open={dialog === "icon"} onOpenChange={close} name={data.name} current={data.icon} />
        </>
      ) : null}
      <ExtendMembershipDialog name={dialog === "extend" ? name : null} onClose={() => setDialog(null)} />
      <LikeDeviceDialog target={dialog === "like" ? name : null} onClose={() => setDialog(null)} />
      <ConnectionCardDialog name={dialog === "card" ? name : null} onClose={() => setDialog(null)} />
      <LostDeviceDialog name={dialog === "lost" ? name : null} onClose={() => setDialog(null)} />
      <KeyRotationDialog open={dialog === "rotate"} onOpenChange={close} expectedName={name} />
    </>
  )
}

interface HeaderProps {
  device: DeviceDetail
  onAction: (d: Dialog) => void
  sectionsRef: React.RefObject<HTMLDivElement | null>
}

function Header({ device, onAction, sectionsRef }: HeaderProps) {
  const { t } = useI18n()
  const readOnly = useReadOnly()
  const s = device.system
  const connected = device.status === "online" || device.status === "this"
  const canRemove = !readOnly && !device.thisComputer
  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div className="flex min-w-0 flex-col gap-2">
        <div className="flex min-w-0 items-center gap-3">
          <DeviceTypeIcon icon={device.icon} className="size-5" />
          <h1 className="truncate text-xl leading-tight font-semibold">{device.name}</h1>
          <span
            role="img"
            aria-label={connected ? t("Bağlı") : t("Bağlı değil")}
            className={connected ? "size-2.5 shrink-0 rounded-full bg-success" : "size-2.5 shrink-0 rounded-full bg-muted-foreground/50"}
          />
        </div>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 text-sm text-muted-foreground">
          {s ? (
            <span className="flex items-center gap-1.5">
              <OsIcon os={s.os} osName={s.osName} />
              {osDisplayName(s.os, s.osLabel || s.osName)}
            </span>
          ) : null}
          <span className="flex flex-wrap items-center gap-1">
            {device.admin ? <SettingBadge>{t("Yönetici")}</SettingBadge> : null}
            {device.exitNode ? <SettingBadge>{t("Çıkış düğümü")}</SettingBadge> : null}
            {device.daysLeft <= 0 ? (
              <SettingBadge tone="danger">{t("Süresi doldu {date}", { date: formatDate(device.expiresAt) })}</SettingBadge>
            ) : null}
            <TagList tags={device.tags} />
          </span>
        </div>
      </div>
      <div className="flex shrink-0 flex-wrap items-center gap-2 self-start">
      <SectionJump sectionsRef={sectionsRef} />
      <DropdownMenu>
        <DropdownMenuTrigger render={<Button variant="outline" />}>
          <Settings data-icon="inline-start" />
          {t("Cihaz ayarları")}
          <ChevronDown data-icon="inline-end" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-60">
          {readOnly ? null : (
            <>
              <DropdownMenuItem onClick={() => onAction("rename")}>{t("Adı düzenle…")}</DropdownMenuItem>
              <DropdownMenuItem onClick={() => onAction("extend")}>{t("Üyeliği uzat…")}</DropdownMenuItem>
            </>
          )}
          <DropdownMenuItem onClick={() => onAction("card")}>{t("Bağlantı kartı…")}</DropdownMenuItem>
          <DropdownMenuItem render={<Link href="/activity" />}>{t("Son etkinlik")}</DropdownMenuItem>
          <DropdownMenuItem render={<Link href="/routes" />}>{t("Rota ayarları…")}</DropdownMenuItem>
          {readOnly ? null : (
            <>
              <DropdownMenuItem onClick={() => onAction("tags")}>{t("Etiketler…")}</DropdownMenuItem>
              <DropdownMenuItem onClick={() => onAction("icon")}>{t("Simge…")}</DropdownMenuItem>
              <DropdownMenuItem onClick={() => onAction("like")}>
                <span className="flex flex-col">
                  <span>{t("Şu cihaz gibi yap…")}</span>
                  <span className="text-sm text-muted-foreground">{t("Başka cihazın etiket ve kurallarını öner")}</span>
                </span>
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => onAction("rotate")}>{t("Anahtar yenileme isteği…")}</DropdownMenuItem>
            </>
          )}
          {canRemove && device.daysLeft > 0 ? (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => onAction("expire")}>
                <span className="flex flex-col">
                  <span>{t("Üyeliği hemen bitir…")}</span>
                  <span className="text-sm text-muted-foreground">{t("Geri açılabilir; cihaz belgede kalır")}</span>
                </span>
              </DropdownMenuItem>
            </>
          ) : null}
          {canRemove ? (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuItem variant="destructive" onClick={() => onAction("revoke")}>
                <span className="flex flex-col">
                  <span>{t("Ağdan çıkar…")}</span>
                  <span className="text-sm text-muted-foreground">{t("Kalıcı; anahtarlar iptal edilir")}</span>
                </span>
              </DropdownMenuItem>
            </>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>
      </div>
    </div>
  )
}

interface JumpTarget {
  id: string
  title: string
}

/**
 * Jump list for the long detail page. Built from the sections actually on
 * screen when the menu opens, so app-only and empty sections never show.
 */
function SectionJump({ sectionsRef }: { sectionsRef: React.RefObject<HTMLDivElement | null> }) {
  const { t } = useI18n()
  const [targets, setTargets] = useState<JumpTarget[]>([])

  function collect() {
    const root = sectionsRef.current
    if (!root) return
    const found: JumpTarget[] = []
    root.querySelectorAll<HTMLElement>("section[id]").forEach((el) => {
      // Nested sections (the rule columns) belong to their parent.
      if (el.parentElement?.closest("section[id]")) return
      if (el.getClientRects().length === 0) return
      const heading = el.querySelector("h2")
      const title = heading?.textContent?.trim()
      if (title) found.push({ id: el.id, title })
    })
    setTargets(found)
  }

  function jump(id: string) {
    const el = document.getElementById(id)
    if (!el) return
    el.scrollIntoView({ block: "start" })
    const heading = el.querySelector<HTMLElement>("h2")
    if (heading) {
      heading.tabIndex = -1
      heading.focus({ preventScroll: true })
    }
    history.replaceState(null, "", `#${id}`)
  }

  return (
    <DropdownMenu onOpenChange={(open) => (open ? collect() : undefined)}>
      <DropdownMenuTrigger render={<Button variant="ghost" />}>
        <ListTree data-icon="inline-start" />
        {t("Bölümler")}
        <ChevronDown data-icon="inline-end" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="max-h-96 w-60">
        <DropdownMenuGroup>
          <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">{t("Bu sayfada")}</DropdownMenuLabel>
          {targets.map((target) => (
            <DropdownMenuItem key={target.id} onClick={() => jump(target.id)}>
              {target.title}
            </DropdownMenuItem>
          ))}
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/** The machine details: identity and attributes on the left, addresses, connection and system on the right. */
function DetailsSection({ device }: { device: DeviceDetail }) {
  const { t } = useI18n()
  const s = device.system
  return (
    <DetailSection
      id="ayrintilar"
      title={t("Cihaz ayrıntıları")}
      description={t("İmzalı ağ belgesindeki kimlik ve cihazın kendi gönderdiği sistem raporu.")}
      framed={false}
    >
      <div className="grid rounded-lg border md:grid-cols-2">
        {s ? null : (
          <p className="border-b px-4 py-3 text-sm text-pretty text-muted-foreground md:col-span-2 md:px-6">
            {device.liveAvailable
              ? t("Bu cihaz henüz sistem raporu göndermedi; işletim sistemi, sürüm ve donanım bilgisi rapor gelince görünür.")
              : t("Sistem raporu masaüstü uygulamasında görünür; bu panel yalnızca imzalı belgedeki bilgileri gösteriyor.")}
          </p>
        )}
        <div className="flex min-w-0 flex-col gap-8 p-4 md:p-6">
          <DetailGroup>
            <DetailItem label={t("Ad")} copy={device.name}>
              <span className="font-medium">{device.name}</span>
            </DetailItem>
            {s ? (
              <>
                <DetailItem label={t("İşletim sistemi")}>
                  <span className="flex min-w-0 items-center gap-1.5">
                    <OsIcon os={s.os} osName={s.osName} className="text-foreground" />
                    <span className="break-words">{osDisplayName(s.os, s.osLabel || s.osName)}</span>
                    <span className="text-muted-foreground">({s.arch})</span>
                  </span>
                </DetailItem>
                <DetailItem label={t("OpenScale sürümü")}>
                  <span className="font-mono">{s.version}</span>
                  {s.outdated ? <SettingBadge tone="warning">{t("Güncel: {version}", { version: s.latest ?? "-" })}</SettingBadge> : null}
                </DetailItem>
              </>
            ) : null}
            <DetailItem label={t("Anahtar parmak izi")} copy={device.fingerprint}>
              <span className="font-mono" title={device.fingerprint}>
                {shortKey(device.fingerprint, 12, 6)}
              </span>
            </DetailItem>
            <DetailItem label={t("WireGuard anahtarı")} copy={device.wireguardKey}>
              <span className="font-mono" title={device.wireguardKey}>
                {shortKey(device.wireguardKey)}
              </span>
            </DetailItem>
            <DetailItem label={t("İmza anahtarı")} copy={device.signingKey}>
              <span className="font-mono" title={device.signingKey}>
                {shortKey(device.signingKey)}
              </span>
            </DetailItem>
            <DetailItem label={t("Cihaz kimliği")} copy={device.id}>
              <span className="font-mono" title={device.id}>
                {shortKey(device.id)}
              </span>
            </DetailItem>
            <DetailItem label={t("Eklenme")}>{formatDate(device.addedAt)}</DetailItem>
            <DetailItem label={t("Son görülme")}>
              <LastSeen status={device.status} lastSeen={device.lastSeen} />
            </DetailItem>
            <DetailItem label={t("Üyelik bitişi")}>
              {formatDate(device.expiresAt)}
              <span className={device.daysLeft <= 30 ? "text-warning-foreground dark:text-warning" : "text-muted-foreground"}>
                ({daysLabel(device.daysLeft)})
              </span>
            </DetailItem>
          </DetailGroup>
          <DetailGroup title={t("Öznitelikler")}>
            <DetailItem label={t("Etiketler")}>
              <TagList tags={device.tags} empty={t("none|Yok")} />
            </DetailItem>
            <DetailItem label={t("Roller")}>
              {device.admin || device.exitNode ? (
                <span className="flex flex-wrap gap-1">
                  {device.admin ? <SettingBadge>{t("Yönetici")}</SettingBadge> : null}
                  {device.exitNode ? <SettingBadge>{t("Çıkış düğümü")}</SettingBadge> : null}
                </span>
              ) : (
                <span className="text-muted-foreground">{t("Cihaz")}</span>
              )}
            </DetailItem>
            {s?.virt || s?.model || s?.install ? (
              <DetailItem label={t("Ortam")}>
                <span className="flex items-center gap-1.5">
                  {s.virt === "docker" ? <MaskIcon name="docker" aria-hidden={true} /> : null}
                  {[s.virt, s.model, s.install].filter(Boolean).join(" · ")}
                </span>
              </DetailItem>
            ) : null}
          </DetailGroup>
        </div>
        <div className="flex min-w-0 flex-col gap-8 border-t p-4 md:border-t-0 md:border-l md:p-6">
          <DetailGroup title={t("Adresler")}>
            <DetailItem label="IPv4" copy={device.ipv4}>
              <span className="font-mono">{device.ipv4}</span>
            </DetailItem>
            <DetailItem label="IPv6" copy={device.ipv6}>
              <span className="font-mono break-all">{device.ipv6}</span>
            </DetailItem>
            <DetailItem label={t("Kısa ad")} copy={device.name}>
              <span className="font-mono">{device.name}</span>
            </DetailItem>
            <DetailItem label={t("Tam ad")} copy={device.fqdn}>
              <span className="font-mono break-all">{device.fqdn}</span>
            </DetailItem>
            <Endpoints device={device} />
          </DetailGroup>
          <ConnectionGroup device={device} />
          <SystemGroup device={device} />
        </div>
      </div>
    </DetailSection>
  )
}

function Endpoints({ device }: { device: DeviceDetail }) {
  const { t } = useI18n()
  const s = device.system
  const items: { label: string; value: string; publicIp?: boolean }[] = []
  if (device.direct && !device.direct.relayed && device.direct.endpoint) items.push({ label: msg("doğrudan"), value: device.direct.endpoint })
  if (device.coordinator?.endpoint) items.push({ label: msg("koordinatörün gördüğü"), value: device.coordinator.endpoint })
  if (s?.publicIp && !items.some((i) => i.value.startsWith(s.publicIp))) items.push({ label: msg("genel IP"), value: s.publicIp, publicIp: true })
  // Nothing known yet: the row is left out instead of saying "Bilinmiyor".
  if (items.length === 0) return null
  return (
    <DetailItem label={t("Uç noktalar")}>
      <ul className="flex flex-col gap-1">
        {items.map((i) => (
          <li key={i.label} className="flex flex-wrap items-center gap-x-2">
            {i.publicIp && s?.country ? <Flag country={s.country} /> : null}
            <span className="font-mono break-all">{i.value}</span>
            <span className="text-sm text-muted-foreground">{t(i.label)}</span>
            <CopyLink value={i.value} label={t("Uç nokta {label}", { label: t(i.label) })} />
          </li>
        ))}
      </ul>
    </DetailItem>
  )
}

function ConnectionGroup({ device }: { device: DeviceDetail }) {
  const { t } = useI18n()
  const { status } = useAppStatus()
  const peer = status?.device?.peers.find((p) => p.name === device.name)
  if (!device.liveAvailable) {
    return (
      <DetailGroup title={t("Bağlantı")}>
        <DetailItem label={t("Durum")}>
          <span className="text-muted-foreground">{t("Canlı bilgi masaüstü uygulamasında görünür")}</span>
        </DetailItem>
      </DetailGroup>
    )
  }
  if (device.thisComputer) {
    return (
      <DetailGroup title={t("Bağlantı")}>
        <DetailItem label={t("Durum")}>{t("Bu panelin çalıştığı bilgisayar")}</DetailItem>
      </DetailGroup>
    )
  }
  const d = device.direct
  return (
    <DetailGroup title={t("Bağlantı")}>
      {d ? (
        <>
          <DetailItem label={t("Yol")}>{d.relayed ? t("Aktarıcı üzerinden (uçtan uca şifreli)") : t("Doğrudan")}</DetailItem>
          <DetailItem label={t("Son el sıkışma")}>
            {d.lastHandshake ? <span title={formatDateTime(d.lastHandshake)}>{formatAgo(d.lastHandshake)}</span> : t("Henüz yok")}
          </DetailItem>
          <DetailItem label={t("Trafik")}>
            {t("{rx} alındı, {tx} gönderildi", { rx: formatBytes(d.rxBytes), tx: formatBytes(d.txBytes) })}
          </DetailItem>
        </>
      ) : (
        <DetailItem label={t("Yol")}>
          <span className="text-muted-foreground text-pretty">
            {/* No live stats does not mean the rules forbid it: only the peer list says that. */}
            {peer
              ? t("Kurallar izin veriyor; tünel bu cihazla henüz el sıkışmadı.")
              : status?.device
                ? t("Kurallar bu bilgisayarın bu cihaza ulaşmasına izin vermiyor.")
                : t("Canlı bağlantı bilgisi henüz yok.")}
          </span>
        </DetailItem>
      )}
      {device.coordinator ? (
        <DetailItem label={t("Koordinatörle temas")}>
          {device.coordinator.lastHandshake ? formatAgo(device.coordinator.lastHandshake) : t("Henüz yok")}
        </DetailItem>
      ) : null}
      {peer?.postQuantum ? (
        <DetailItem label={t("Şifreleme")}>
          <PostQuantumBadge state={peer.postQuantum} />
        </DetailItem>
      ) : null}
    </DetailGroup>
  )
}

function SystemGroup({ device }: { device: DeviceDetail }) {
  const { t } = useI18n()
  const s = device.system
  // The missing report is said once, above the details.
  if (!s) return null
  return (
    <DetailGroup title={t("Sistem")}>
      <DetailItem label={t("İşlemci")}>
        {s.cpu ? t("{cpu} ({count} çekirdek)", { cpu: s.cpu, count: s.cores }) : t("{count} çekirdek", { count: s.cores })}
      </DetailItem>
      <DetailItem label={t("Bellek")}>
        <UsageBar label="RAM" used={s.memTotal - s.memFree} total={s.memTotal} />
      </DetailItem>
      <DetailItem label={t("Disk")}>
        <UsageBar label={t("Disk")} used={s.diskTotal - s.diskFree} total={s.diskTotal} />
      </DetailItem>
      <DetailItem label={t("Çalışma süresi")}>{formatUptime(s.uptime)}</DetailItem>
      {s.country ? (
        <DetailItem label={t("Konum")}>
          <span className="flex items-center gap-1.5">
            <Flag country={s.country} />
            {countryName(s.country)}
          </span>
        </DetailItem>
      ) : null}
      <DetailItem label={t("Rapor")}>
        <span className={s.stale ? "text-warning-foreground dark:text-warning" : undefined}>
          {s.stale ? t("{ago}, cihaz şu an yanıt vermiyor", { ago: formatAgo(s.reportedAt) }) : formatAgo(s.reportedAt)}
        </span>
      </DetailItem>
    </DetailGroup>
  )
}

/** Subnet routes this device announces (ADR-0133). */
function SubnetsSection({ device }: { device: DeviceDetail }) {
  const { t } = useI18n()
  const { data } = useSWR<RoutesStatus>("/api/routes", fetcher)
  const mine = data?.devices.find((d) => d.name === device.name)
  const routes = mine?.routes ?? []
  return (
    <DetailSection
      id="alt-aglar"
      title={t("Alt ağlar")}
      description={t("Bu cihazın ağa ilan ettiği yerel ağ aralıkları.")}
      framed={false}
      action={
        <Button variant="link" size="sm" className="px-0" nativeButton={false} render={<Link href="/routes" />}>
          {t("Rotaları düzenle")}
        </Button>
      }
    >
      {routes.length === 0 ? (
        <EmptyNote>{t("Bu cihaz rota ilan etmiyor.")}</EmptyNote>
      ) : (
        <ul className="flex flex-col divide-y rounded-lg border">
          {routes.map((r) => (
            <li key={r} className="flex flex-col gap-0.5 px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
              <span className="font-mono text-sm">{r}</span>
              <span className="text-sm text-muted-foreground">
                {mine && mine.clients.length > 0 ? t("Erişebilen: {names}", { names: mine.clients.join(", ") }) : t("Erişim kuralı yok")}
              </span>
            </li>
          ))}
        </ul>
      )}
    </DetailSection>
  )
}

function ExitSection({ device, onChange }: { device: DeviceDetail; onChange: (on: boolean) => void }) {
  const { t } = useI18n()
  const readOnly = useReadOnly()
  const upstream = device.system?.upstream
  return (
    <DetailSection
      id="yonlendirme"
      title={t("Yönlendirme ayarları")}
      description={t("Bu cihazın diğer cihazların internet trafiğini taşıması.")}
    >
      <div className="flex flex-col gap-3 py-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-col gap-0.5">
          <span className="text-sm font-medium">{t("Çıkış düğümü")}</span>
          <span className="text-sm text-muted-foreground text-pretty">
            {t("Linux sunucular iletim ve NAT'ı kendisi açar; Windows çıkış düğümü henüz desteklenmiyor.")}
          </span>
        </div>
        <div className="flex shrink-0 items-center gap-3">
          {device.exitNode ? <SettingBadge tone="success">{t("İzinli")}</SettingBadge> : <SettingBadge>{t("İzin yok")}</SettingBadge>}
          {readOnly ? null : (
            <Button variant="link" size="sm" className="px-0" onClick={() => onChange(!device.exitNode)}>
              {t("Düzenle")}
            </Button>
          )}
        </div>
      </div>
      {upstream ? (
        <div className="flex flex-col gap-1.5 py-3 sm:flex-row sm:items-start sm:justify-between sm:gap-6">
          <div className="flex shrink-0 flex-col gap-0.5">
            <span className="text-sm font-medium">{t("Üst çıkış")}</span>
            <span className="text-sm text-muted-foreground">{upstreamKindText(upstream.kind)}</span>
          </div>
          <div className="min-w-0 sm:max-w-md sm:text-right sm:[&>span]:items-end">
            <UpstreamSummary upstream={upstream} detailed />
          </div>
        </div>
      ) : null}
      <div className="flex flex-col gap-1 py-3">
        <div className="flex items-center justify-between gap-3">
          <span className="text-sm font-medium">{t("Çıkış düğümü kullanımı")}</span>
          {device.mayUseExitNode ? <SettingBadge>{t("Kullanabilir")}</SettingBadge> : <SettingBadge tone="warning">{t("Kullanamaz")}</SettingBadge>}
        </div>
        <ExitAccessNote device={device} />
      </div>
    </DetailSection>
  )
}

function RuleList({ rules, empty }: { rules: Rule[]; empty: string }) {
  if (rules.length === 0) {
    return <p className="text-sm text-muted-foreground">{empty}</p>
  }
  return (
    <ul className="flex flex-col gap-1.5">
      {rules.map((r) => (
        <li key={r.index} className="flex flex-col">
          <span className="font-mono text-[0.8125rem] break-all">{r.text}</span>
          {r.description ? <span className="text-sm text-muted-foreground">{r.description}</span> : null}
        </li>
      ))}
    </ul>
  )
}

function AccessSection({ device }: { device: DeviceDetail }) {
  const { t } = useI18n()
  return (
    <DetailSection
      id="erisim"
      title={t("Erişim kuralları")}
      description={t("Kurala uymayan her bağlantı iki uçta da reddedilir.")}
      framed={false}
      action={
        <Button variant="link" size="sm" className="px-0" nativeButton={false} render={<Link href="/rules" />}>
          {t("Kuralları düzenle")}
        </Button>
      }
    >
      <div className="grid rounded-lg border md:grid-cols-3 md:divide-x">
        <section className="flex flex-col gap-2 p-4">
          <h3 className="flex items-center gap-1.5 text-xs font-medium tracking-wide text-muted-foreground uppercase">
            <ArrowUpRight className="size-3.5" />
            {t("Giden")}
          </h3>
          <RuleList rules={device.outgoing} empty={t("Bu cihaz başka cihaza bağlantı başlatamaz.")} />
        </section>
        <section className="flex flex-col gap-2 border-t p-4 md:border-t-0">
          <h3 className="flex items-center gap-1.5 text-xs font-medium tracking-wide text-muted-foreground uppercase">
            <ArrowDownLeft className="size-3.5" />
            {t("Gelen")}
          </h3>
          <RuleList rules={device.incoming} empty={t("Hiçbir cihaz bu cihaza bağlanamaz.")} />
        </section>
        <section className="flex flex-col gap-2 border-t p-4 md:border-t-0">
          <h3 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
            {t("Görebildiği cihazlar ({count})", { count: device.peers.length })}
          </h3>
          {device.peers.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t("none|Yok")}</p>
          ) : (
            <ul className="flex flex-col gap-1">
              {device.peers.map((p) => (
                <li key={p.name}>
                  <Link
                    href={`/devices/detail?name=${encodeURIComponent(p.name)}`}
                    className="flex items-center justify-between gap-3 text-sm hover:underline"
                  >
                    <span>{p.name}</span>
                    <span className="font-mono text-[0.8125rem] text-muted-foreground">{p.ipv4}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </DetailSection>
  )
}

/**
 * Danger zone at the bottom of the page (DESIGN.md): the lost device flow,
 * which shows what the device could reach before removing it.
 */
function DangerSection({ device, onLost }: { device: DeviceDetail; onLost: () => void }) {
  const { t } = useI18n()
  const readOnly = useReadOnly()
  if (readOnly || device.thisComputer) return null
  return (
    <SettingsSection id="tehlikeli-bolge" title={t("Tehlikeli bölge")} tone="danger">
      <SettingRow
        title={t("Bu cihazı kaybettim")}
        description={t("Cihazın ağda neye ulaşabildiğini ve değiştirilmesi gereken parolaları gösterir, sonra cihazı ağdan çıkarır.")}
        action={
          <Button variant="destructive" onClick={onLost}>
            <SmartphoneNfc data-icon="inline-start" />
            {t("Bu cihazı kaybettim")}
          </Button>
        }
      />
    </SettingsSection>
  )
}

const postureText: Record<PostureState, { text: string; tone: "success" | "danger" | "muted" }> = {
  on: { text: msg("Açık"), tone: "success" },
  off: { text: msg("Kapalı"), tone: "danger" },
  unknown: { text: msg("Bilinmiyor"), tone: "muted" },
}

/** The device's own security posture statement (ADR-0109); never proof of security. */
function PostureSection({ device }: { device: DeviceDetail }) {
  const { t } = useI18n()
  const p = device.system?.posture
  return (
    <DetailSection
      id="durus"
      title={t("Cihaz duruşu")}
      description={t("Cihazın kendi beyanı: disk şifreleme ve güvenlik duvarı. Güvenliğin kanıtı değildir.")}
      framed={false}
    >
      {!p ? (
        <EmptyNote>{t("Bu cihaz duruş bilgisi göndermedi.")}</EmptyNote>
      ) : (
        <ul className="flex flex-col divide-y rounded-lg border">
          <PostureRow label={t("Disk şifreleme")} state={p.diskEncryption} />
          <PostureRow label={t("Güvenlik duvarı")} state={p.firewall} />
          {p.windowsBuild ? (
            <li className="flex items-center justify-between gap-4 px-4 py-3 text-sm">
              <span>{t("Windows derlemesi")}</span>
              <span className="font-mono">{p.windowsBuild}</span>
            </li>
          ) : null}
        </ul>
      )}
    </DetailSection>
  )
}

function PostureRow({ label, state }: { label: string; state: PostureState }) {
  const { t } = useI18n()
  const posture = postureText[state]
  return (
    <li className="flex items-center justify-between gap-4 px-4 py-3 text-sm">
      <span>{label}</span>
      <SettingBadge tone={posture.tone}>{t(posture.text)}</SettingBadge>
    </li>
  )
}
