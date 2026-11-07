"use client"

import { useEffect, useMemo, useRef, useState } from "react"
import Link from "next/link"
import useSWR from "swr"
import { ChevronDown, CirclePlus, Copy, KeyRound, Laptop, MoreHorizontal, RefreshCw, Rocket, Search, UserPlus, UserRoundPlus } from "lucide-react"
import { toast } from "sonner"

import { PinButton, pinnedFirst, usePinned } from "@/components/app/pin-button"
import { useReadOnly, Writable } from "@/components/app/read-only"
import { AddDeviceDialog } from "@/components/devices/add-device-dialog"
import { LastSeen } from "@/components/devices/device-status"
import { ExtendMembershipDialog } from "@/components/devices/extend-membership-dialog"
import { GuestWizard } from "@/components/devices/guest-wizard"
import { KeyRotationDialog } from "@/components/devices/key-rotation-dialog"
import { RetireDeviceDialog } from "@/components/devices/retire-device-dialog"
import { Flag } from "@/components/devices/system-bits"
import { UpstreamBadge, upstreamName } from "@/components/devices/upstream-status"
import { InvitesPanel } from "@/components/invites/invites-panel"
import { MembershipPanel } from "@/components/membership/membership-panel"
import { SegmentedRadio } from "@/components/devices/segmented-radio"
import { OsIcon, osDisplayName } from "@/components/os-icon"
import { DeviceTypeIcon } from "@/components/devices/device-icon" // #233, ADR-0232
import { CountBadge, PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { FlatCards, SettingBadge } from "@/components/settings/settings-layout"
import { SignChangeDialog } from "@/components/sign-change"
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
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group"
import { Kbd } from "@/components/ui/kbd"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { fetcher } from "@/lib/api"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import { formatDate, formatShortDate } from "@/lib/format"
import type { CoordinatorLive, Device, DevicesResponse, SystemInfo } from "@/lib/types"
import { devicesStreamKeys, useStreamRefresh } from "@/lib/use-event-stream"
import { cn } from "@/lib/utils"

type Filter = "all" | "exit" | "expiring"

const filters: { value: Filter; label: string }[] = [
  { value: "all", label: msg("Tümü") },
  { value: "exit", label: msg("Çıkış düğümleri") },
  { value: "expiring", label: msg("Süresi yaklaşan") },
]

export function DevicesView() {
  const { t } = useI18n()
  useStreamRefresh(devicesStreamKeys) // #328
  const { data, error, isLoading, isValidating, mutate } = useSWR<DevicesResponse>("/api/devices", fetcher)
  const [adding, setAdding] = useState(false)
  const [inviting, setInviting] = useState(false)
  const [revoking, setRevoking] = useState<Device | null>(null)
  const [exitTarget, setExitTarget] = useState<Device | null>(null)
  const [extending, setExtending] = useState<string | null>(null)
  const [retiring, setRetiring] = useState<string | null>(null)
  const [rotating, setRotating] = useState(false)
  const [guesting, setGuesting] = useState(false)
  const [query, setQuery] = useState("")
  const [filter, setFilter] = useState<Filter>("all")
  const searchRef = useRef<HTMLInputElement>(null)
  const { pinned } = usePinned()
  const readOnly = useReadOnly()

  // Ctrl K belongs to the panel-wide command palette; "/" jumps to this
  // page's search, unless the owner is already typing somewhere.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return
      const t = e.target
      if (t instanceof HTMLElement && (t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName))) return
      e.preventDefault()
      searchRef.current?.focus()
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    const matching = (data?.devices ?? []).filter((d) => {
      if (filter === "exit" && !d.exitNode) return false
      if (filter === "expiring" && d.daysLeft > 30) return false
      if (!q) return true
      return [d.name, d.fqdn, d.ipv4, d.ipv6, d.system?.osName ?? "", ...d.tags.map((t) => `tag:${t}`)].some((v) => v.toLowerCase().includes(q))
    })
    // Pinned devices (a local setting of this computer) come first.
    return pinnedFirst(matching, pinned, (d) => d.name)
  }, [data, query, filter, pinned])

  const count = data?.devices.length ?? 0

  return (
    <>
      <PageHeader
        title={msg("Cihazlar")}
        badge={data ? <CountBadge>{t("{count} cihaz", { count })}</CountBadge> : null}
        description={msg("Ağına kayıtlı bilgisayarlar, telefonlar ve sunucular.")}
        actions={
          <Writable>
            <Button variant="ghost" className="text-muted-foreground" onClick={() => setRotating(true)}>
              <KeyRound data-icon="inline-start" />
              {t("Anahtar yenileme isteği")}
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger render={<Button />}>
                <CirclePlus data-icon="inline-start" />
                {t("Cihaz ekle")}
                <ChevronDown data-icon="inline-end" />
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-72">
                <DropdownMenuItem onClick={() => setInviting(true)}>
                  <UserPlus />
                  <span className="flex flex-col">
                    <span>{t("Davet kodu oluştur")}</span>
                    <span className="text-sm text-muted-foreground">{t("Yeni bilgisayarda kodu yapıştır, kısa kodu onayla")}</span>
                  </span>
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setGuesting(true)}>
                  <UserRoundPlus />
                  <span className="flex flex-col">
                    <span>{t("Konuk ekle")}</span>
                    <span className="text-sm text-muted-foreground">{t("Tek cihaza, süreli erişimle davet")}</span>
                  </span>
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setAdding(true)}>
                  <Laptop />
                  <span className="flex flex-col">
                    <span>{t("Kayıt isteğiyle ekle")}</span>
                    <span className="text-sm text-muted-foreground">{t("openscale keygen çıktısını yapıştır")}</span>
                  </span>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem render={<Link href="/setup" />}>
                  <Rocket />
                  <span className="flex flex-col">
                    <span>{t("Kurulum sihirbazı")}</span>
                    <span className="text-sm text-muted-foreground">{t("Adım adım kurulum ve bağlantı testi")}</span>
                  </span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </Writable>
        }
      />
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {data ? (
          <div className="flex flex-col gap-8">
            <Writable>
              <InvitesPanel inviting={inviting} onInvitingChange={setInviting} />
            </Writable>

            <div className="flex flex-col gap-3">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                <InputGroup className="h-9 sm:w-80">
                  <InputGroupAddon>
                    <Search />
                  </InputGroupAddon>
                  <InputGroupInput
                    ref={searchRef}
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder={t("Ad, IP, DNS adı, sistem veya etiket")}
                    aria-label={t("Cihaz ara")}
                  />
                  <InputGroupAddon align="inline-end" className="hidden sm:flex">
                    <Kbd aria-label={t("Kısayol: eğik çizgi")}>/</Kbd>
                  </InputGroupAddon>
                </InputGroup>
                <div className="flex min-w-0 items-center gap-2">
                  <SegmentedRadio label={msg("Filtre")} value={filter} options={filters} onChange={setFilter} className="min-w-0" />
                  <Button variant="ghost" size="icon" className="shrink-0" onClick={() => mutate()} aria-label={t("Listeyi yenile")}>
                    <RefreshCw className={cn(isValidating && "animate-spin")} />
                  </Button>
                </div>
              </div>

              {count === 0 ? (
                <Empty className="border">
                  <EmptyHeader>
                    <EmptyMedia variant="icon">
                      <Laptop />
                    </EmptyMedia>
                    <EmptyTitle>{t("Henüz cihaz yok")}</EmptyTitle>
                    <EmptyDescription>{t("Kurulum sihirbazı ilk cihazını eklemen için gereken komutları adım adım gösterir.")}</EmptyDescription>
                  </EmptyHeader>
                  <EmptyContent>
                    <Button nativeButton={false} render={<Link href="/setup" />}>
                      <Rocket data-icon="inline-start" />
                      {t("Kurulum sihirbazını aç")}
                    </Button>
                  </EmptyContent>
                </Empty>
              ) : (
                <DeviceTable
                  devices={visible}
                  dnsDomain={data.dnsDomain}
                  coordinator={filter === "all" && query.trim() === "" ? data.coordinator : null}
                  onRevoke={setRevoking}
                  onExitNode={setExitTarget}
                  onExtend={(d) => setExtending(d.name)}
                  onRetire={(d) => setRetiring(d.name)}
                  pinned={pinned}
                  readOnly={readOnly}
                />
              )}
            </div>

            {data.revoked.length > 0 ? (
              <section aria-labelledby="revoked-title" className="flex flex-col gap-2">
                <h2 id="revoked-title" className="text-base font-semibold">
                  {t("İptal edilmiş cihazlar ({count})", { count: data.revoked.length })}
                </h2>
                <ul className="flex flex-col divide-y border-y text-sm">
                  {data.revoked.map((r) => (
                    <li key={`${r.name}-${r.revokedAt}`} className="flex justify-between gap-4 py-2.5">
                      <span className="font-mono text-xs">{r.name}</span>
                      <span className="text-muted-foreground">{formatDate(r.revokedAt)}</span>
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}

            <Writable>
              <section id="uyelik-bakimi" aria-label={t("Üyelik bakımı")} className="scroll-mt-24">
                <FlatCards titles="section">
                  <MembershipPanel />
                </FlatCards>
              </section>
            </Writable>
          </div>
        ) : null}
      </QueryState>

      <AddDeviceDialog open={adding} onOpenChange={setAdding} />
      <KeyRotationDialog open={rotating} onOpenChange={setRotating} />
      <GuestWizard open={guesting} onOpenChange={setGuesting} />
      <ExtendMembershipDialog name={extending} onClose={() => setExtending(null)} />
      <RetireDeviceDialog name={retiring} onClose={() => setRetiring(null)} />
      <SignChangeDialog
        open={revoking !== null}
        onOpenChange={(open) => {
          if (!open) setRevoking(null)
        }}
        title={t("{name} cihazını ağdan çıkar", { name: revoking?.name ?? "" })}
        description={t(
          "Bu işlem geri alınamaz: cihazın anahtarları kalıcı olarak iptal edilir. Yalnızca çıkış düğümü rolünü kaldırmak istiyorsan bunu kullanma. Cihaz geri gelmek isterse kendini sıfırlayıp yeni davetle katılması gerekir."
        )}
        endpoint="/api/devices/revoke"
        payload={{ name: revoking?.name ?? "" }}
        confirmLabel={t("İmzala ve çıkar")}
        destructive
        confirmText={revoking?.name}
      />
      <SignChangeDialog
        open={exitTarget !== null}
        onOpenChange={(open) => {
          if (!open) setExitTarget(null)
        }}
        title={
          exitTarget?.exitNode
            ? t("{name} çıkış düğümü olmasın", { name: exitTarget.name })
            : t("{name} çıkış düğümü olsun", { name: exitTarget?.name ?? "" })
        }
        description={t("Rol ağ belgesine imzalanır. Linux cihazlar (sunucular) iletim ve NAT'ı kendisi açar; Windows çıkış düğümü henüz desteklenmiyor.")}
        endpoint="/api/devices/exit-node"
        payload={{ name: exitTarget?.name ?? "", exitNode: !exitTarget?.exitNode }}
        confirmLabel={t("İmzala ve kaydet")}
      />
    </>
  )
}

export function deviceHref(name: string): string {
  return `/devices/detail?name=${encodeURIComponent(name)}`
}

async function copy(value: string, what: string) {
  try {
    await navigator.clipboard.writeText(value)
    toast.success(tx("{what} kopyalandı.", { what }))
  } catch {
    toast.error(tx("Panoya kopyalanamadı."))
  }
}

const head = "h-10 text-xs font-medium tracking-wide text-muted-foreground uppercase"

interface DeviceTableProps {
  devices: Device[]
  dnsDomain: string
  coordinator: CoordinatorLive | null
  onRevoke: (d: Device) => void
  onExitNode: (d: Device) => void
  onExtend: (d: Device) => void
  onRetire: (d: Device) => void
  pinned: string[]
  readOnly: boolean
}

function DeviceTable({ devices, dnsDomain, coordinator, onRevoke, onExitNode, onExtend, onRetire, pinned, readOnly }: DeviceTableProps) {
  const { t } = useI18n()
  if (devices.length === 0 && !coordinator) {
    return (
      <Empty className="border">
        <EmptyHeader>
          <EmptyTitle>{t("Eşleşen cihaz yok")}</EmptyTitle>
          <EmptyDescription>{t("Aramayı veya filtreyi değiştir.")}</EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }
  return (
    <div className="-mx-4 overflow-x-auto border-y md:mx-0">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className={cn(head, "pl-4 md:pl-2")}>{t("Cihaz")}</TableHead>
            <TableHead className={cn(head, "hidden sm:table-cell")}>{t("Adresler")}</TableHead>
            <TableHead className={cn(head, "hidden md:table-cell")}>{t("Sürüm")}</TableHead>
            <TableHead className={cn(head, "hidden lg:table-cell")}>{t("Son görülme")}</TableHead>
            <TableHead className="w-12 pr-4 md:pr-2">
              <span className="sr-only">{t("İşlemler")}</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {coordinator ? <CoordinatorRow c={coordinator} /> : null}
          {devices.map((d) => (
            <TableRow key={d.id} className="group/row">
              <TableCell className="py-3 pl-4 align-top md:pl-2">
                <div className="flex min-w-0 flex-col gap-1">
                  <span className="flex items-center gap-1">
                    <DeviceTypeIcon icon={d.icon} />
                    <Link href={deviceHref(d.name)} className="truncate font-semibold hover:underline">
                      {d.name}
                    </Link>
                    <PinButton name={d.name} pinned={pinned.includes(d.name)} className="size-6 shrink-0" />
                  </span>
                  <DeviceBadges device={d} />
                  <LastSeen status={d.status} lastSeen={d.lastSeen} className="text-xs lg:hidden" />
                </div>
              </TableCell>
              <TableCell className="hidden py-3 align-top sm:table-cell">
                <span className="flex flex-col gap-0.5">
                  <AddressMenu device={d} dnsDomain={dnsDomain} />
                  {/* Same layout as the coordinator row: the address the coordinator sees. */}
                  <span className="flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
                    {d.system?.country ? <Flag country={d.system.country} /> : null}
                    {d.system?.publicIp || "-"}
                  </span>
                </span>
              </TableCell>
              <TableCell className="hidden py-3 align-top md:table-cell">
                <VersionCell system={d.system} />
              </TableCell>
              <TableCell className="hidden py-3 align-top lg:table-cell">
                <LastSeen status={d.status} lastSeen={d.lastSeen} />
              </TableCell>
              <TableCell className="py-3 pr-4 text-right align-top md:pr-2">
                <DropdownMenu>
                  <DropdownMenuTrigger render={<Button variant="ghost" size="icon-sm" aria-label={t("{name} için işlemler", { name: d.name })} />}>
                    <MoreHorizontal />
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="w-56">
                    <DropdownMenuItem render={<Link href={deviceHref(d.name)} />}>{t("Ayrıntılar")}</DropdownMenuItem>
                    {d.thisComputer ? null : (
                      <DropdownMenuItem render={<Link href={`${deviceHref(d.name)}#uzak-erisim`} />}>{t("Uzak erişim")}</DropdownMenuItem>
                    )}
                    {readOnly ? null : (
                      <>
                        <DropdownMenuItem onClick={() => onExitNode(d)}>
                          {d.exitNode ? t("Çıkış düğümü olmasın") : t("Çıkış düğümü yap")}
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => onExtend(d)}>{t("Üyeliği uzat…")}</DropdownMenuItem>
                      </>
                    )}
                    <DropdownMenuSeparator />
                    <DropdownMenuItem onClick={() => copy(d.ipv4, t("IPv4 adresi"))}>{t("IPv4 adresini kopyala")}</DropdownMenuItem>
                    <DropdownMenuItem onClick={() => copy(d.fqdn, t("DNS adı"))}>{t("DNS adını kopyala")}</DropdownMenuItem>
                    {d.thisComputer || readOnly ? null : (
                      <>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem variant="destructive" onClick={() => onRetire(d)}>
                          <span className="flex flex-col">
                            <span>{t("Emekliye ayır…")}</span>
                            <span className="text-sm text-muted-foreground">{t("Önce bütün başvurularını gösterir")}</span>
                          </span>
                        </DropdownMenuItem>
                        <DropdownMenuItem variant="destructive" onClick={() => onRevoke(d)}>
                          <span className="flex flex-col">
                            <span>{t("Ağdan çıkar…")}</span>
                            <span className="text-sm text-muted-foreground">{t("Kalıcı; anahtarlar iptal edilir")}</span>
                          </span>
                        </DropdownMenuItem>
                      </>
                    )}
                  </DropdownMenuContent>
                </DropdownMenu>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

/** Roles, tags and the membership expiry under a device name. */
function DeviceBadges({ device }: { device: Device }) {
  const { t } = useI18n()
  const expired = device.daysLeft <= 0
  const expiring = !expired && device.daysLeft <= 30
  if (!device.admin && !device.exitNode && device.tags.length === 0 && !expired && !expiring) return null
  return (
    <span className="flex flex-wrap items-center gap-1">
      {device.admin ? <SettingBadge>{t("Yönetici")}</SettingBadge> : null}
      {device.exitNode ? <SettingBadge>{t("Çıkış düğümü")}</SettingBadge> : null}
      {device.exitNode && device.system?.upstream ? (
        <span className="flex items-center gap-1 text-xs">
          <span className="font-medium">{upstreamName(device.system.upstream)}</span>
          <UpstreamBadge mode={device.system.upstream.mode} kind={device.system.upstream.kind} />
        </span>
      ) : null}
      {expired ? <SettingBadge tone="danger">{t("Süresi doldu {date}", { date: formatShortDate(device.expiresAt) })}</SettingBadge> : null}
      {expiring ? <SettingBadge tone="warning">{t("Süresi doluyor {date}", { date: formatShortDate(device.expiresAt) })}</SettingBadge> : null}
      <TagList tags={device.tags} />
    </span>
  )
}

/** OpenScale version, then the detailed OS name with its logo. */
function VersionCell({ system }: { system: SystemInfo | null }) {
  const { t } = useI18n()
  if (!system) {
    return <span className="text-sm text-muted-foreground">{t("Bilgi yok")}</span>
  }
  const os = osDisplayName(system.os, system.osLabel || system.osName)
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <span className="flex items-center gap-1.5 text-sm">
        <span className="font-mono">{system.version}</span>
        {system.outdated ? (
          <SettingBadge tone="warning">
            <span title={t("Yönetici bilgisayardaki sürüm {version}; bu cihazı güncelleyin.", { version: system.latest ?? "" })}>{t("Eski sürüm")}</span>
          </SettingBadge>
        ) : null}
      </span>
      <span className="flex max-w-64 items-center gap-1.5 text-xs text-muted-foreground" title={os}>
        <OsIcon os={system.os} osName={system.osName} className="size-3.5" />
        <span className="truncate">{os}</span>
      </span>
    </div>
  )
}

/** Primary IPv4 with a small menu of every address, each copied on click. */
function AddressMenu({ device, dnsDomain }: { device: Device; dnsDomain: string }) {
  const { t } = useI18n()
  const rows = [
    { label: t("Kısa ad"), value: device.name },
    { label: "MagicDNS", value: device.fqdn },
    { label: "IPv6", value: device.ipv6 },
    { label: "IPv4", value: device.ipv4 },
    ...(device.system?.publicIp ? [{ label: t("Genel IP"), value: device.system.publicIp }] : []),
  ]
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <button
            type="button"
            className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 -ml-1.5 font-mono text-sm hover:bg-muted focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
            aria-label={t("{name} adresleri: {ip}", { name: device.name, ip: device.ipv4 })}
          />
        }
      >
        {device.ipv4}
        <ChevronDown className="size-3.5 text-muted-foreground" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-auto min-w-80">
        <DropdownMenuGroup>
          <DropdownMenuLabel className="flex items-center gap-1.5 text-xs font-normal text-muted-foreground">
            {device.system?.country ? <Flag country={device.system.country} /> : null}
            {t("Adlar yalnızca ağ içinde .{domain} altında çözülür", { domain: dnsDomain })}
          </DropdownMenuLabel>
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        {rows.map((r) => (
          <DropdownMenuItem key={r.label} onClick={() => copy(r.value, r.label)} className="flex items-center gap-3">
            <span className="w-20 shrink-0 text-xs text-muted-foreground">{r.label}</span>
            <span className="min-w-0 flex-1 truncate font-mono text-xs">{r.value}</span>
            <Copy className="size-3.5 text-muted-foreground" aria-hidden="true" />
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function CoordinatorRow({ c }: { c: CoordinatorLive }) {
  const { t } = useI18n()
  const host = c.endpoint.replace(/:\d+$/, "")
  return (
    <TableRow className="bg-muted/30">
      <TableCell className="py-3 pl-4 align-top md:pl-2">
        <div className="flex min-w-0 flex-col gap-1">
          <Link href="/network/coordinators" className="truncate font-semibold hover:underline">
            {host}
          </Link>
          <span className="flex flex-wrap gap-1">
            <SettingBadge>{t("Koordinatör")}</SettingBadge>
          </span>
          <LastSeen status={c.status} lastSeen={null} className="text-xs lg:hidden" />
        </div>
      </TableCell>
      <TableCell className="hidden py-3 align-top sm:table-cell">
        <span className="flex flex-col gap-0.5">
          <span className="font-mono text-sm">{c.ipv4}</span>
          <span className="flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
            {c.country ? <Flag country={c.country} /> : null}
            {c.publicIp || "-"}
          </span>
        </span>
      </TableCell>
      <TableCell className="hidden py-3 align-top md:table-cell">
        <VersionCell system={c.system} />
      </TableCell>
      <TableCell className="hidden py-3 align-top lg:table-cell">
        <LastSeen status={c.status} lastSeen={null} />
      </TableCell>
      <TableCell className="py-3 pr-4 md:pr-2" />
    </TableRow>
  )
}
