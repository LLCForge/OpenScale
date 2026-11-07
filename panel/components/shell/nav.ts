import {
  BookOpen,
  LayoutDashboard,
  Laptop,
  Monitor,
  MonitorSmartphone,
  ScrollText,
  Server,
  Settings,
  Shield,
  ShieldCheck,
  Stethoscope,
  type LucideIcon,
} from "lucide-react"

import { msg } from "@/lib/i18n/i18n"

// Panel navigation: a few main areas in the side menu, each with its pages
// as a tab strip at the top of the page (like the Tailscale admin console).
// Every page keeps its own URL; groups only decide what is shown together.

export interface NavTab {
  href: string
  label: string
}

export interface NavGroup {
  /** Where the side menu entry leads; the first tab when there are tabs. */
  href: string
  label: string
  icon: LucideIcon
  /** Pages shown as a tab strip; none for single-page areas. */
  tabs?: NavTab[]
}

export const ownerNav: NavGroup[] = [
  { href: "/", label: msg("Kontrol Merkezi"), icon: LayoutDashboard },
  {
    href: "/devices",
    label: msg("Cihazlar"),
    icon: Monitor,
    tabs: [
      { href: "/devices", label: msg("Tüm cihazlar") },
      { href: "/devices/guests", label: msg("Konuklar") },
      { href: "/devices/requests", label: msg("Erişim istekleri") },
    ],
  },
  { href: "/rules", label: msg("Erişim Kontrolü"), icon: Shield },
  {
    href: "/network",
    label: msg("Ağ"),
    icon: Server,
    tabs: [
      { href: "/network", label: msg("Genel") },
      { href: "/network/dns", label: "DNS" },
      { href: "/routes", label: msg("Rotalar") },
      { href: "/network/coordinators", label: msg("Koordinatörler") },
      { href: "/map", label: msg("Harita") },
    ],
  },
  {
    href: "/remote",
    label: msg("Uzak Erişim"),
    icon: MonitorSmartphone,
    tabs: [
      { href: "/remote", label: msg("Uzak erişim") },
      { href: "/inbox", label: msg("Gelen dosyalar") },
      { href: "/sync", label: msg("Eşitleme ve yedek") },
      { href: "/files", label: msg("Uçtan uca gönder") },
      { href: "/files/quarantine", label: msg("Karantina") },
    ],
  },
  { href: "/plugins", label: msg("Engelleme ve İzleme"), icon: Shield, tabs: [{ href: "/plugins", label: msg("Engelleme ve eklentiler") }, { href: "/plugins/monitor", label: msg("İzleme") }] },
  {
    href: "/activity",
    label: msg("Günlükler"),
    icon: ScrollText,
    tabs: [
      { href: "/activity", label: msg("Etkinlik") },
      { href: "/diag", label: msg("Tanı") },
    ],
  },
  {
    href: "/settings",
    label: msg("Ayarlar"),
    icon: Settings,
    tabs: [
      // Signed network settings and this computer's own settings are two
      // pages, so nothing local looks like it needs the root key.
      { href: "/settings", label: msg("Ağ (imzalı)") },
      { href: "/settings/local", label: msg("Bu bilgisayar") },
      { href: "/settings/admins", label: msg("Yöneticiler") },
      { href: "/settings/emergency", label: msg("Acil durum") },
      { href: "/settings/canary", label: msg("Kanarya") },
      { href: "/score", label: msg("Güvenlik puanı") },
      { href: "/transfer", label: msg("Belge aktarımı") },
      { href: "/setup", label: msg("Kurulum sihirbazı") },
      { href: "/help", label: msg("Yardım") },
      { href: "/about", label: msg("Hakkında") },
      { href: "/settings/login", label: msg("Giriş ve gizlilik") },
    ],
  },
  { href: "/security", label: msg("Cihaz güvenliği"), icon: ShieldCheck, tabs: [{ href: "/security", label: msg("Duruş") }, { href: "/security/opsec", label: msg("Ağ gizliliği") }] },
]

export const memberNav: NavGroup[] = [
  { href: "/", label: msg("Bu bilgisayar"), icon: Laptop },
  {
    href: "/remote",
    label: msg("Uzak Erişim"),
    icon: MonitorSmartphone,
    tabs: [
      { href: "/remote", label: msg("Uzak erişim") },
      { href: "/inbox", label: msg("Gelen dosyalar") },
      { href: "/sync", label: msg("Eşitleme ve yedek") },
      { href: "/files", label: msg("Uçtan uca gönder") },
      { href: "/files/quarantine", label: msg("Karantina") },
    ],
  },
  { href: "/diag", label: msg("Tanı"), icon: Stethoscope },
  {
    href: "/help",
    label: msg("Yardım"),
    icon: BookOpen,
    tabs: [
      { href: "/help", label: msg("Yardım") },
      { href: "/about", label: msg("Hakkında") },
    ],
  },
  { href: "/security", label: msg("Cihaz güvenliği"), icon: ShieldCheck, tabs: [{ href: "/security", label: msg("Duruş") }, { href: "/security/opsec", label: msg("Ağ gizliliği") }] },
]

/** Pages a network member's panel shows; the rest fall back to the member home. */
export const memberPages = ["/about", "/help", "/diag", "/remote", "/inbox", "/sync"]
memberPages.push("/files", "/files/quarantine", "/security", "/security/opsec")

function covers(href: string, pathname: string): boolean {
  if (href === "/") return pathname === "/"
  return pathname === href || pathname.startsWith(`${href}/`)
}

/** The tab for a path: the longest tab address that covers it. */
export function activeTab(group: NavGroup, pathname: string): NavTab | undefined {
  return (group.tabs ?? [])
    .filter((t) => covers(t.href, pathname))
    .sort((a, b) => b.href.length - a.href.length)[0]
}

/** The group a path belongs to. */
export function activeGroup(groups: NavGroup[], pathname: string): NavGroup | undefined {
  return groups.find((g) => (g.tabs ? activeTab(g, pathname) !== undefined : covers(g.href, pathname)))
}

export interface NavPage {
  href: string
  /** The page's own name. */
  label: string
  /** The area it belongs to; none for single-page areas. */
  area?: string
}

/** Every page of the menu once, in menu order (command palette). */
export function navPages(groups: NavGroup[]): NavPage[] {
  const seen = new Set<string>()
  const pages: NavPage[] = []
  for (const g of groups) {
    const entries: NavPage[] = g.tabs
      ? g.tabs.map((tab) => ({ href: tab.href, label: tab.label, area: g.label }))
      : [{ href: g.href, label: g.label }]
    for (const page of entries) {
      if (seen.has(page.href)) continue
      seen.add(page.href)
      pages.push(page)
    }
  }
  return pages
}
