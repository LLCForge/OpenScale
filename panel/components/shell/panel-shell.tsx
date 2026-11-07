"use client"

import { useEffect, useLayoutEffect, useRef, useState } from "react"
import Link from "next/link"
import { usePathname, useRouter } from "next/navigation"
import useSWR from "swr"
import { useTheme } from "next-themes"
import {
  KeyRound,
  Languages,
  LogOut,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  Sun,
  UserRound,
} from "lucide-react"
import { toast } from "sonner"

import { OfferBanner } from "@/components/apps/offer-banner"
import { MemberHome } from "@/components/app/member-home"
import { ReadOnlyBanner } from "@/components/app/read-only"
import { useAppStatus } from "@/components/app/use-app-status"
import { BrandMark, BrandWordmark } from "@/components/brand"
import { AdminModeChip, DiscreetTitle } from "@/components/shell/admin-mode-chip"
import { CommandPalette } from "@/components/shell/command-palette"
import { MobileNav } from "@/components/shell/mobile-nav"
import { PresentationToggle } from "@/components/shell/presentation-mode"
import { TokenModeChip } from "@/components/shell/token-sign"
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
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { ApiError, errorMessage, fetcher, post } from "@/lib/api"
import { locales, useI18n } from "@/lib/i18n/i18n"
import type { Overview } from "@/lib/types"
import { cn } from "@/lib/utils"
import { activeGroup, activeTab, memberNav, memberPages, ownerNav, type NavGroup } from "@/components/shell/nav"

function normalize(path: string): string {
  return path.length > 1 ? path.replace(/\/+$/, "") : path
}

export function PanelShell({ children }: { children: React.ReactNode }) {
  const pathname = normalize(usePathname())
  const router = useRouter()
  const { resolvedTheme, setTheme } = useTheme()
  const { t, locale, setLocale } = useI18n()
  const [collapsed, setCollapsed] = useState(false)
  const app = useAppStatus()
  const mode = app.status?.mode
  // The desktop app decides what this computer is; the CLI panel is always
  // the owner's panel.
  const isOwner = !app.isApp || mode === "admin"
  const groups = isOwner ? ownerNav : memberNav
  const group = activeGroup(groups, pathname)
  const { data, error } = useSWR<Overview>(isOwner ? "/api/overview" : null, fetcher, { refreshInterval: 30_000 })
  const { data: info } = useSWR<{ version: string }>("/api/app/info", fetcher, { revalidateOnFocus: false })
  // Network display name (F-160): the owner's overview, else what this
  // computer's app read from the document.
  const networkName = (isOwner ? data?.displayName : undefined) || app.status?.networkName || ""
  const documentVersion = isOwner ? data?.version : app.status?.device?.documentVersion
  const deviceName = app.status?.device?.name ?? ""

  const unauthorized =
    (error instanceof ApiError && error.status === 401) || (app.error instanceof ApiError && app.error.status === 401)
  useEffect(() => {
    if (unauthorized) router.replace("/login")
  }, [unauthorized, router])
  useEffect(() => {
    if (mode === "setup" || mode === "joining") router.replace("/welcome")
  }, [mode, router])

  async function logout() {
    try {
      await post("/api/logout", {})
      router.replace("/login")
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }

  // The shell is fully translated, so it carries the chosen language even
  // on pages whose body is still Turkish (<html lang> follows the body; see
  // LocaleSync in lib/i18n).
  return (
    <div className="flex min-h-svh flex-1 flex-col">
      <a
        href="#icerik"
        lang={locale}
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded-md focus:bg-card focus:px-3 focus:py-2"
      >
        {t("İçeriğe geç")}
      </a>
      <header
        lang={locale}
        className="flex h-16 shrink-0 items-center justify-between gap-2 border-b border-sidebar-border bg-sidebar px-4 sm:gap-4"
      >
        <div className="flex min-w-0 items-center gap-2 sm:gap-3">
          <MobileNav
            groups={groups}
            current={group}
            networkName={networkName}
            documentVersion={documentVersion}
            panelVersion={info?.version}
          />
          <Link href="/" aria-label={t("Kontrol Merkezi")} className="shrink-0">
            <BrandWordmark className="hidden h-7 md:block" />
            <BrandMark className="md:hidden" />
          </Link>
          {/* Mobile: the active area's name stands in for the side menu. */}
          {group ? (
            <span className="min-w-0 truncate text-sm font-medium text-sidebar-accent-foreground md:hidden">
              <span className="sr-only">{t("Bulunduğun alan:")} </span>
              {t(group.label)}
            </span>
          ) : null}
          {networkName ? (
            <span
              className="hidden max-w-64 truncate border-l border-sidebar-border pl-3 text-sm font-medium text-sidebar-foreground md:inline"
              title={networkName}
            >
              <span className="sr-only">{t("Ağ adı:")} </span>
              {networkName}
            </span>
          ) : null}
          <Button
            variant="ghost"
            size="icon-sm"
            className="hidden text-muted-foreground md:inline-flex"
            onClick={() => setCollapsed((c) => !c)}
            aria-label={collapsed ? t("Menüyü genişlet") : t("Menüyü daralt")}
            aria-expanded={!collapsed}
          >
            {collapsed ? <PanelLeftOpen /> : <PanelLeftClose />}
          </Button>
        </div>
        <div className="flex shrink-0 items-center gap-1 sm:gap-2">
          <AdminModeChip />
          <TokenModeChip />
          <DiscreetTitle />
          <CommandPalette groups={groups} />
          <PresentationToggle />
          <DropdownMenu>
            <DropdownMenuTrigger
              render={
                <Button
                  variant="ghost"
                  size="icon"
                  className="rounded-full bg-secondary font-medium pointer-coarse:size-11"
                  aria-label={isOwner ? t("Hesap menüsü: ağ sahibi") : t("Hesap menüsü: ağ üyesi")}
                />
              }
            >
              <AccountAvatar isOwner={isOwner} deviceName={deviceName} />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-60" lang={locale}>
              {/* A group label must sit inside a group (Base UI error 31). */}
              <DropdownMenuGroup>
                <DropdownMenuLabel className="flex flex-col gap-0.5">
                  <span>{isOwner ? t("Ağ sahibi") : t("Ağ üyesi")}</span>
                  <span className="truncate font-mono text-xs font-normal text-muted-foreground">
                    {isOwner ? (data?.rootFingerprint ?? "...") : deviceName || "..."}
                  </span>
                </DropdownMenuLabel>
              </DropdownMenuGroup>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}>
                {resolvedTheme === "dark" ? <Sun /> : <Moon />}
                {resolvedTheme === "dark" ? t("Açık tema") : t("Koyu tema")}
              </DropdownMenuItem>
              {locales
                .filter((l) => l.id !== locale)
                .map((l) => (
                  <DropdownMenuItem key={l.id} lang={l.id} onClick={() => setLocale(l.id)}>
                    <Languages />
                    {l.label}
                  </DropdownMenuItem>
                ))}
              {isOwner ? (
                <DropdownMenuItem onClick={() => router.push("/settings")}>
                  <KeyRound />
                  {t("Kök anahtar ve yedekler")}
                </DropdownMenuItem>
              ) : null}
              <DropdownMenuSeparator />
              <DropdownMenuItem variant="destructive" onClick={logout}>
                <LogOut />
                {t("Çıkış yap")}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>

      <div className="flex min-h-0 flex-1">
        <nav
          aria-label={t("Ana menü")}
          lang={locale}
          className={cn(
            "hidden shrink-0 flex-col justify-between border-r border-sidebar-border bg-sidebar p-3 md:flex",
            collapsed ? "w-16" : "w-60"
          )}
        >
          <NavList groups={groups} current={group} collapsed={collapsed} />
          {!collapsed ? (
            <dl className="flex flex-col gap-1 px-3 py-2 text-sm text-muted-foreground">
              <div className="flex justify-between gap-2">
                <dt>{t("Ağ belgesi")}</dt>
                <dd className="font-mono" data-presentation-safe>v{documentVersion ?? "-"}</dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt>Panel</dt>
                <dd className="font-mono" data-presentation-safe>{info?.version ? `v${info.version}` : "-"}</dd>
              </div>
            </dl>
          ) : null}
        </nav>

        <div className="flex min-w-0 flex-1 flex-col">
          <main id="icerik" className="flex min-w-0 flex-1 flex-col p-4 md:px-8 md:py-6">
            <div className="mx-auto flex w-full max-w-7xl min-w-0 flex-col gap-6">
              {group?.tabs ? <SectionTabs group={group} pathname={pathname} /> : null}
              <ReadOnlyBanner />
              {app.isApp ? <OfferBanner /> : null}
              {isOwner || memberPages.includes(pathname) ? children : app.status ? <MemberHome status={app.status} /> : null}
            </div>
          </main>
        </div>
      </div>
    </div>
  )
}

/**
 * The account button's face. The owner holds the root key, so a key icon;
 * a member is shown by the first letter of this computer's name, never a
 * fixed "S" that reads as "Sahip" on a member's panel.
 */
function AccountAvatar({ isOwner, deviceName }: { isOwner: boolean; deviceName: string }) {
  if (isOwner) return <KeyRound aria-hidden />
  const initial = Array.from(deviceName.trim())[0]
  return initial ? <span aria-hidden>{initial.toLocaleUpperCase("tr")}</span> : <UserRound aria-hidden />
}

function NavList({ groups, current, collapsed }: { groups: NavGroup[]; current: NavGroup | undefined; collapsed: boolean }) {
  const { t } = useI18n()
  return (
    <ul className="flex flex-col gap-0.5">
      {groups.map((item) => {
        const active = item === current
        const Icon = item.icon
        const link = (
          <Link
            href={item.href}
            aria-current={active ? "page" : undefined}
            aria-label={collapsed ? t(item.label) : undefined}
            className={cn(
              "flex min-h-9 items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors pointer-coarse:min-h-11",
              collapsed && "justify-center px-0",
              active
                ? "bg-sidebar-accent font-medium text-sidebar-accent-foreground"
                : "text-sidebar-foreground hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground"
            )}
          >
            <Icon className="size-4 shrink-0" />
            {collapsed ? null : <span className="truncate">{t(item.label)}</span>}
          </Link>
        )
        return (
          <li key={item.href}>
            {collapsed ? (
              <Tooltip>
                <TooltipTrigger render={link} />
                <TooltipContent side="right">{t(item.label)}</TooltipContent>
              </Tooltip>
            ) : (
              link
            )}
          </li>
        )
      })}
    </ul>
  )
}

/**
 * The pages of the current area as a line tab strip at the top of the page.
 * On narrow screens the strip scrolls sideways inside itself, and the active
 * tab is brought into view so the current page is never hidden off-edge.
 */
function SectionTabs({ group, pathname }: { group: NavGroup; pathname: string }) {
  const { t, locale } = useI18n()
  const current = activeTab(group, pathname)
  const stripRef = useRef<HTMLElement>(null)
  const activeRef = useRef<HTMLAnchorElement>(null)

  useLayoutEffect(() => {
    const strip = stripRef.current
    const tab = activeRef.current
    if (!strip || !tab || strip.scrollWidth <= strip.clientWidth) return
    // Scroll only the strip; scrollIntoView would also move the page.
    const left = tab.offsetLeft - (strip.clientWidth - tab.offsetWidth) / 2
    strip.scrollLeft = Math.max(0, Math.min(left, strip.scrollWidth - strip.clientWidth))
  }, [current])

  return (
    <nav
      ref={stripRef}
      lang={locale}
      aria-label={t("{area} sayfaları", { area: t(group.label) })}
      className="relative -mx-4 overflow-x-auto overflow-y-hidden overscroll-x-contain border-b px-4 md:mx-0 md:px-0"
    >
      <ul className="flex gap-1">
        {(group.tabs ?? []).map((tab) => {
          const active = tab === current
          return (
            <li key={tab.href} className="shrink-0">
              <Link
                ref={active ? activeRef : undefined}
                href={tab.href}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "relative inline-flex h-11 items-center px-3 text-sm whitespace-nowrap transition-colors md:h-10",
                  "after:absolute after:inset-x-2 after:bottom-0 after:h-0.5 after:rounded-full",
                  active
                    ? "font-medium text-foreground after:bg-foreground"
                    : "text-muted-foreground hover:text-foreground after:bg-transparent"
                )}
              >
                {t(tab.label)}
              </Link>
            </li>
          )
        })}
      </ul>
    </nav>
  )
}
