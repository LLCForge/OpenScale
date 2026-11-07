"use client"

import { useState } from "react"
import Link from "next/link"
import useSWR from "swr"
import { toast } from "sonner"
import { ChevronDown, CircleCheck, Info, ShieldAlert, TriangleAlert } from "lucide-react"

import { ConnectionRow } from "@/components/app/connection-card"
import { useReadOnly } from "@/components/app/read-only"
import { healthTitle } from "@/components/app/health-alerts"
import { useAppStatus } from "@/components/app/use-app-status"
import { ControlCenter } from "@/components/control-center/control-center"
import { DetailSection } from "@/components/devices/detail-card"
import { diffSummary } from "@/components/history/diff-lines"
import { PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { RowList } from "@/components/settings/list-table"
import { EmptyNote, SettingRow, SettingsColumn, SettingsSection } from "@/components/settings/settings-layout"
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
import { Spinner } from "@/components/ui/spinner"
import { errorMessage, fetcher, post } from "@/lib/api"
import { daysLabel, formatAgo, formatDateTime } from "@/lib/format"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import type { MembershipResponse } from "@/lib/membership-types"
import type { AppStatus, DevicesResponse, HistoryReport, InvitesResponse, Overview, Warning } from "@/lib/types"
import { controlCenterStreamKeys, useLiveInterval, useStreamRefresh } from "@/lib/use-event-stream"
import { cn } from "@/lib/utils"

type Level = "danger" | "warning" | "info"

interface AttentionItem {
  key: string
  level: Level
  title: string
  detail?: string
  href?: string
  action?: string
}

const levelIcon: Record<Level, { icon: typeof Info; className: string }> = {
  danger: { icon: ShieldAlert, className: "text-destructive" },
  warning: { icon: TriangleAlert, className: "text-warning" },
  info: { icon: Info, className: "text-muted-foreground" },
}

const levelOrder: Record<Level, number> = { danger: 0, warning: 1, info: 2 }

/**
 * Where each coded overview warning is fixed: the section its button opens
 * and the verb the button shows. Codes not listed have no fix link.
 */
const warningFix: Record<string, { href: string; action: string }> = {
  no_backup: { href: "/settings#kok-anahtar", action: msg("Yedek al") }, // i18n-ignore: sayfa içi bağlantı kimliği
  document_expiring: { href: "/settings#ag-belgesi", action: msg("Belgeyi yenile") }, // i18n-ignore: sayfa içi bağlantı kimliği
  unused_tag: { href: "/rules", action: msg("Kurallara git") },
  no_rules: { href: "/rules", action: msg("Kural ekle") },
  dns_resolver_blocked: { href: "/network/dns#ad-sunuculari", action: msg("DNS ayarına git") }, // i18n-ignore: sayfa içi bağlantı kimliği
  key_age_overdue: { href: "/devices", action: msg("Cihazlara git") },
  limit_near: { href: "/devices", action: msg("Cihazlara git") },
  ledger_broken: { href: "/activity#belge-gecmisi", action: msg("Geçmişi incele") }, // i18n-ignore: sayfa içi bağlantı kimliği
  foreign_signer: { href: "/activity#belge-gecmisi", action: msg("Geçmişi incele") }, // i18n-ignore: sayfa içi bağlantı kimliği
}

/** Overview warnings the attention list already shows in another form. */
const coveredWarnings = new Set(["membership_expiring"])

function warningItem(w: Warning, i: number, ts: (text: string) => string): AttentionItem {
  const fix = warningFix[w.code]
  return { key: `w-${w.code}-${i}`, level: w.level, title: ts(w.message), href: fix?.href, action: fix?.action }
}

/** Names for a short list: "a, b, c ve 2 cihaz daha". */
function someNames(names: string[], max = 3): string {
  if (names.length <= max) return names.join(", ")
  return tx("{names} ve {count} cihaz daha", { names: names.slice(0, max).join(", "), count: names.length - max })
}

/**
 * The owner's calm summary: one status line, what needs attention, this
 * computer's connection, the latest document changes and the access map.
 */
export function ControlCenterOverview() {
  const { t } = useI18n()
  const overview = useSWR<Overview>("/api/overview", fetcher)
  useStreamRefresh(controlCenterStreamKeys) // #328
  const devices = useSWR<DevicesResponse>("/api/devices", fetcher, { refreshInterval: useLiveInterval(30_000) })

  return (
    <SettingsColumn className="max-w-4xl">
      <PageHeader title={t("Kontrol Merkezi")} description={t("Ağının durumu, ilgilenmen gerekenler ve son değişiklikler.")} />
      <QueryState
        error={overview.error ?? devices.error}
        isLoading={overview.isLoading || devices.isLoading}
        onRetry={() => {
          overview.mutate()
          devices.mutate()
        }}
      >
        {overview.data && devices.data ? (
          <>
            <StatusLine overview={overview.data} devices={devices.data} />
            <Attention overview={overview.data} devices={devices.data} />
            <SettingsSection
              id="bu-bilgisayar" // i18n-ignore: sayfa içi bağlantı kimliği
              title={t("Bu bilgisayar")}
              description={t("Yalnızca bu bilgisayarda geçerli; ağ belgesini değiştirmez.")}
            >
              <ConnectionRow />
              <ExitSummaryRow />
            </SettingsSection>
            <RecentActivity />
            <DetailSection
              id="erisim-haritasi"
              title={t("Erişim haritası")}
              description={t("Seçili cihazın imzalı kurallarla hangi cihazlara ulaşabildiği; kural dışı her şey reddedilir.")}
              framed={false}
            >
              <ControlCenter />
            </DetailSection>
          </>
        ) : null}
      </QueryState>
    </SettingsColumn>
  )
}

function StatusLine({ overview, devices }: { overview: Overview; devices: DevicesResponse }) {
  const { t } = useI18n()
  const { status } = useAppStatus()
  const list = devices.devices
  const online = list.filter((d) => d.status === "online" || d.status === "this").length
  const offline = list.filter((d) => d.status === "offline").length
  // With no live data every device reads "unknown"; an empty network is simply 0.
  const known = list.length === 0 || online + offline > 0
  const device = status?.device
  const wanted = device?.exitNodeWanted ?? ""

  let exit: string
  if (device?.name) {
    exit = wanted ? (device.exitNode === wanted ? wanted : t("{name} (bağlanıyor)", { name: wanted })) : t("Kullanılmıyor")
  } else {
    exit = overview.exitNodeCount > 0 ? t("{count} cihaz hazır", { count: overview.exitNodeCount }) : t("none|Yok")
  }

  return (
    <dl aria-label={t("Ağ durumu")} className="grid grid-cols-2 gap-x-6 gap-y-4 border-y py-4 sm:flex sm:flex-wrap sm:gap-x-10">
      <StatusItem label={t("Bağlı")} href="/devices">
        <span className="flex items-center gap-2">
          <span aria-hidden="true" className="size-2 rounded-full bg-success" />
          {known ? t("{count} cihaz", { count: online }) : t("Bilinmiyor")}
        </span>
      </StatusItem>
      <StatusItem label={t("Çevrimdışı")} href="/devices">
        <span className="flex items-center gap-2">
          <span aria-hidden="true" className="size-2 rounded-full bg-muted-foreground/50" />
          {known ? t("{count} cihaz", { count: offline }) : t("Bilinmiyor")}
        </span>
      </StatusItem>
      <StatusItem label={t("Çıkış düğümü")} href={device?.name ? "/settings/local#cikis" : "/network#cikis-dugumleri"}>
        {exit}
      </StatusItem>
      {/* i18n-ignore: sayfa içi bağlantı kimliği */}
      <StatusItem label={t("Ağ belgesi v{version}", { version: overview.version })} href="/settings#ag-belgesi">
        <span className={cn(overview.daysLeft <= 14 && "text-warning-foreground dark:text-warning")}>{daysLabel(overview.daysLeft)}</span>
      </StatusItem>
      <StatusItem label={t("Erişim kuralı")} href="/rules">
        {overview.ruleCount}
      </StatusItem>
    </dl>
  )
}

function StatusItem({ label, href, children }: { label: string; href: string; children: React.ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="text-sm font-medium">
        <Link href={href} className="rounded-sm hover:underline focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none">
          {children}
        </Link>
      </dd>
    </div>
  )
}

function Attention({ overview, devices }: { overview: Overview; devices: DevicesResponse }) {
  const { t, ts } = useI18n()
  const { status } = useAppStatus()
  const { data: invites } = useSWR<InvitesResponse>("/api/invites", fetcher, { refreshInterval: 10_000 })
  // Same key as the membership upkeep on the devices page, so they share data.
  const { data: membership } = useSWR<MembershipResponse>("/api/membership?days=30", fetcher, { refreshInterval: 30_000 })

  const items: AttentionItem[] = []
  overview.warnings.forEach((w, i) => {
    // Expiring memberships are summed up below in one row for all devices.
    if (!coveredWarnings.has(w.code)) items.push(warningItem(w, i, ts))
  })
  for (const a of status?.health ?? []) {
    // The connection row already says when the tunnel is paused.
    if (a.code === "tunnel_paused") continue
    items.push({ key: `h-${a.code}-${a.message}`, level: a.level, title: t(healthTitle(a.code)), detail: ts(a.message), href: "/diag", action: msg("Tanı") })
  }
  const pending = invites?.pending ?? []
  if (pending.length > 0) {
    items.push({
      key: "pending",
      level: "warning",
      title: t("{count} cihaz onay bekliyor", { count: pending.length }),
      detail: t("{names}. Kısa kod yeni bilgisayardakiyle aynıysa onayla.", {
        names: someNames(pending.map((p) => p.hostname || t("Adsız cihaz"))),
      }),
      href: "/devices",
      action: msg("Onayla"),
    })
  }
  const leaves = membership?.leaves ?? []
  if (leaves.length > 0) {
    items.push({
      key: "leaves",
      level: "info",
      title: t("{count} ayrılma isteği bekliyor", { count: leaves.length }),
      detail: t("{names} ağdan ayrılmak istiyor; bir imzayla belgeden çıkar.", { names: someNames(leaves.map((l) => l.name)) }),
      href: "/devices#uyelik-bakimi",
      action: msg("Göster"),
    })
  }
  for (const c of membership?.alerts ?? []) {
    items.push({
      key: `clone-${c.name}`,
      level: "danger",
      title: t("{name} iki yerde birden görüldü", { name: c.name }),
      detail: t("Uç nokta {count} kez değişti; anahtar kopyalanmış olabilir.", { count: c.flips }),
      href: "/devices#uyelik-bakimi",
      action: msg("Göster"),
    })
  }
  const expired = devices.devices.filter((d) => d.daysLeft <= 0)
  const expiring = devices.devices.filter((d) => d.daysLeft > 0 && d.daysLeft <= 30)
  if (expired.length > 0) {
    items.push({
      key: "expired",
      level: "danger",
      title: t("{count} cihazın üyeliği doldu", { count: expired.length }),
      detail: t("{names} yeni bağlantı kuramaz.", { names: someNames(expired.map((d) => d.name)) }),
      href: "/devices",
      action: msg("Uzat"),
    })
  }
  if (expiring.length > 0) {
    items.push({
      key: "expiring",
      level: "warning",
      title: t("{count} cihazın üyeliği 30 gün içinde doluyor", { count: expiring.length }),
      detail: someNames(expiring.map((d) => d.name)),
      href: "/devices",
      action: msg("Uzat"),
    })
  }
  items.sort((a, b) => levelOrder[a.level] - levelOrder[b.level])
  const danger = items.filter((i) => i.level === "danger")
  const rest = items.filter((i) => i.level !== "danger")

  return (
    <>
      {danger.length > 0 ? (
        <section
          id="tehlike"
          aria-labelledby="tehlike-baslik"
          className="flex scroll-mt-24 flex-col gap-1 rounded-lg border border-destructive/40 px-4 pt-3 pb-1"
        >
          <h2 id="tehlike-baslik" className="flex items-center gap-2 text-base font-semibold text-destructive">
            <ShieldAlert className="size-4 shrink-0" aria-hidden="true" />
            {danger.length === 1 ? t("Hemen ilgilen") : t("Hemen ilgilen: {count} sorun", { count: danger.length })}
          </h2>
          <ul aria-label={t("Acil sorunlar")} className="flex flex-col divide-y divide-destructive/20">
            {danger.map((item) => (
              <AttentionRow key={item.key} item={item} />
            ))}
          </ul>
        </section>
      ) : null}
      <DetailSection
        id="dikkat"
        title={t("Dikkat gerekenler")}
        description={t("Sağlık uyarıları, bekleyen onaylar ve süresi dolan üyelikler.")}
        framed={false}
      >
        <RowList label={t("Dikkat gerekenler")}>
          {rest.length === 0 ? (
            <li className="flex items-center gap-3 py-3">
              <CircleCheck className="size-4 shrink-0 text-success" aria-hidden="true" />
              <span className="text-sm font-medium">{danger.length > 0 ? t("Başka uyarı yok") : t("Her şey yolunda")}</span>
              <span className="hidden text-sm text-muted-foreground sm:inline">
                {danger.length > 0 ? t("Yukarıdakiler dışında bekleyen bir şey yok.") : t("Uyarı, bekleyen onay veya süresi dolan üyelik yok.")}
              </span>
            </li>
          ) : (
            rest.map((item) => <AttentionRow key={item.key} item={item} />)
          )}
        </RowList>
      </DetailSection>
    </>
  )
}

function AttentionRow({ item }: { item: AttentionItem }) {
  const { t } = useI18n()
  const meta = levelIcon[item.level]
  const Icon = meta.icon
  return (
    <li className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between sm:gap-6">
      <div className="flex min-w-0 gap-3">
        <Icon className={cn("mt-0.5 size-4 shrink-0", meta.className)} aria-hidden="true" />
        <div className="flex min-w-0 flex-col gap-0.5">
          <span className="text-sm font-medium text-pretty">{item.title}</span>
          {item.detail ? <span className="text-sm leading-relaxed text-muted-foreground text-pretty">{item.detail}</span> : null}
        </div>
      </div>
      {item.href ? (
        <Button variant="outline" size="sm" className="ml-7 self-start sm:ml-0 sm:self-auto" nativeButton={false} render={<Link href={item.href} />}>
          {item.action ? t(item.action) : t("Göster")}
        </Button>
      ) : null}
    </li>
  )
}

/**
 * Where this computer's internet traffic leaves, chosen right here. The
 * kill switch, LAN access and automatic choice stay on the settings page.
 */
function ExitSummaryRow() {
  const { t } = useI18n()
  const { status, isApp, mutate } = useAppStatus()
  const readOnly = useReadOnly()
  const [busy, setBusy] = useState(false)
  const device = status?.device
  if (!isApp || !device?.name || device.removed) return null
  const wanted = device.exitNodeWanted ?? ""
  const nodes = device.exitNodes ?? []

  async function choose(name: string) {
    setBusy(true)
    try {
      const res = await post<AppStatus>("/api/app/exit", { name })
      await mutate(res, { revalidate: false })
      toast.success(name ? t("İnternet trafiği artık {name} üzerinden çıkıyor.", { name }) : t("İnternet trafiği yeniden doğrudan çıkıyor."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  let description: string
  if (wanted) {
    description =
      device.exitNode === wanted
        ? t("İnternet trafiği {name} üzerinden çıkıyor.", { name: wanted })
        : t("İnternet trafiği {name} üzerinden çıkacak; yollar kuruluyor.", { name: wanted })
    if (device.killSwitch) description += ` ${t("Trafik kilidi (kill switch) açık.")}`
  } else if (nodes.length === 0) {
    description = t("Ağda çıkış düğümü yok; internet trafiği doğrudan bu bilgisayarın bağlantısından çıkıyor.")
  } else {
    description = t("İnternet trafiği doğrudan bu bilgisayarın bağlantısından çıkıyor.")
  }

  return (
    <SettingRow
      title={t("Çıkış düğümü")}
      description={
        <>
          {description}{" "}
          <Link href="/settings/local#cikis" className="text-foreground underline underline-offset-4">
            {t("Ayrıntılı ayarlar")}
          </Link>
        </>
      }
      action={
        readOnly || nodes.length === 0 ? null : (
          <DropdownMenu>
            <DropdownMenuTrigger render={<Button variant="outline" className="min-w-36 justify-between" disabled={busy} />}>
              {busy ? <Spinner data-icon="inline-start" /> : null}
              <span className="truncate">{wanted || t("Kullanma")}</span>
              <ChevronDown data-icon="inline-end" className="text-muted-foreground" />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-60">
              <DropdownMenuGroup>
                <DropdownMenuLabel>{t("İnternet trafiği nereden çıksın?")}</DropdownMenuLabel>
                <DropdownMenuItem disabled={wanted === ""} onClick={() => void choose("")}>
                  <span className="flex flex-col">
                    <span>{t("Kullanma")}</span>
                    <span className="text-sm text-muted-foreground">{t("Doğrudan bu bilgisayardan")}</span>
                  </span>
                </DropdownMenuItem>
              </DropdownMenuGroup>
              <DropdownMenuSeparator />
              {nodes.map((n) => (
                <DropdownMenuItem key={n.name} disabled={wanted === n.name} onClick={() => void choose(n.name)}>
                  <span className="flex min-w-0 flex-col">
                    <span className="truncate">{n.name}</span>
                    <span className="text-sm text-muted-foreground">{n.online ? t("Çevrimiçi") : t("Şu an yanıt vermiyor")}</span>
                  </span>
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        )
      }
    />
  )
}

function RecentActivity() {
  const { t } = useI18n()
  const { data } = useSWR<HistoryReport>("/api/history", fetcher)
  if (!data) return null
  const entries = data.entries.slice(0, 5)
  return (
    <DetailSection
      id="son-etkinlik"
      title={t("Son etkinlik")}
      description={t("İmzalı ağ belgesinin son sürümleri.")}
      framed={false}
      action={
        <Button variant="link" size="sm" className="px-0" nativeButton={false} render={<Link href="/activity" />}>
          {t("Tümünü gör")}
        </Button>
      }
    >
      {data.problems.length > 0 ? (
        <p className="flex items-center gap-2 text-sm text-destructive">
          <ShieldAlert className="size-4 shrink-0" aria-hidden="true" />
          {t("Belge geçmişinde sorun bulundu; Etkinlik sayfasına bak.")}
        </p>
      ) : null}
      {entries.length === 0 ? (
        <EmptyNote>{t("Henüz imzalı belge sürümü yok.")}</EmptyNote>
      ) : (
        <RowList label={t("Son belge sürümleri")}>
          {entries.map((e) => (
            <li key={e.version} className="flex flex-col gap-0.5 py-3 sm:flex-row sm:items-center sm:justify-between sm:gap-6">
              <span className="flex min-w-0 items-baseline gap-3">
                <span className="shrink-0 font-mono text-sm">v{e.version}</span>
                <span className="text-sm text-muted-foreground text-pretty">{diffSummary(e.diff)}</span>
              </span>
              <time dateTime={e.issued_at} title={formatDateTime(e.issued_at)} className="shrink-0 text-sm text-muted-foreground">
                {formatAgo(e.issued_at)}
              </time>
            </li>
          ))}
        </RowList>
      )}
    </DetailSection>
  )
}
