"use client"

import useSWR from "swr"

import { AutoUpdateSection } from "@/components/about/auto-update-section"
import { BrandWordmark } from "@/components/brand"
import { DetailSection } from "@/components/devices/detail-card"
import { PageHeader } from "@/components/page-header"
import { headCell, ListTable } from "@/components/settings/list-table"
import { SettingBadge, SettingRow, SettingsColumn, SettingsSection } from "@/components/settings/settings-layout"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { fetcher } from "@/lib/api"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { AboutInfo } from "@/lib/pa-types"
import { cn } from "@/lib/utils"

interface Component {
  name: string
  use: string
  license: string
  /** A license text shipped with the panel itself. */
  href?: string
}

// Hand-compiled from go.mod, panel/package.json and the embedded assets
// (F-221). Update it together with any dependency change.
const bundled: Component[] = [
  {
    name: "Wintun 0.14.1 (wintun.dll)",
    use: msg("Windows sanal ağ sürücüsü; değiştirilmeden programa gömülür"),
    license: "Wintun Prebuilt Binaries License (WireGuard LLC)",
  },
  { name: "wireguard-go", use: msg("WireGuard tünel motoru"), license: "MIT" },
  { name: "golang.zx2c4.com/wintun", use: msg("Wintun için Go bağlantısı"), license: "MIT" },
  { name: msg("Go standart kütüphanesi"), use: msg("Programın tamamı"), license: "BSD-3-Clause" },
  { name: "golang.org/x/crypto, x/net, x/sys, x/term", use: msg("Şifreleme, ağ ve Windows sistem çağrıları"), license: "BSD-3-Clause" },
  {
    name: msg("GeoIP tablosu"),
    use: msg("Genel IP adresinden ülke kodu; bilgisayardan dışarı istek yapılmaz"),
    license: msg("Bölgesel internet kayıt kuruluşlarının (RIR) kamuya açık tahsis dosyalarından üretildi"),
  },
  { name: "flag-icons 7.5.0", use: msg("Ülke bayrakları"), license: "MIT", href: "/flags/LICENSE.txt" },
  { name: "simple-icons 16.36.0", use: msg("İşletim sistemi logoları"), license: "CC0-1.0", href: "/os/LICENSE.txt" },
  // i18n-ignore: lisansın özgün adı
  { name: "Figtree", use: msg("Logo ve arayüz yazı tipi"), license: "SIL Open Font License 1.1" },
  { name: "Geist Mono", use: msg("Eş aralıklı yazı tipi"), license: "SIL Open Font License 1.1" }, // i18n-ignore: lisansın özgün adı
]

const panelPackages: Component[] = [
  { name: "Next.js 16.4.3", use: msg("Panelin derlenmesi (statik dışa aktarım)"), license: "MIT" },
  { name: "React 19.3.0, React DOM", use: msg("Arayüz"), license: "MIT" },
  { name: "Base UI 1.9.0", use: msg("Erişilebilir arayüz bileşenleri"), license: "MIT" },
  { name: "SWR 2.5.1", use: msg("Veri çekme"), license: "MIT" },
  { name: "Zod 4.6.7", use: msg("Girdi doğrulama"), license: "MIT" },
  { name: "React Hook Form 7.91.0, @hookform/resolvers", use: msg("Formlar"), license: "MIT" },
  { name: "Lucide 1.64.0", use: msg("Simgeler"), license: "ISC" },
  { name: "Sonner 2.0.8", use: msg("Bildirimler"), license: "MIT" },
  { name: "next-themes 0.4.6", use: msg("Açık/koyu tema"), license: "MIT" },
  { name: "React Flow (@xyflow/react) 12.12.0", use: msg("Kontrol Merkezi grafiği"), license: "MIT" },
  { name: "class-variance-authority 0.7.1", use: msg("Bileşen stilleri"), license: "Apache-2.0" },
  { name: "Tailwind CSS 4, tw-animate-css, cn", use: msg("Stil (derleme zamanı)"), license: "MIT" },
]

/** About page with the version and the open source licenses (F-221). */
export function AboutView() {
  const { t } = useI18n()
  const { data } = useSWR<{ version: string }>("/api/app/info", fetcher, { revalidateOnFocus: false })
  // ADR-0193: label, channel and build; an older server without the
  // endpoint leaves the plain version above.
  const { data: about } = useSWR<AboutInfo>("/api/about", fetcher, { revalidateOnFocus: false, shouldRetryOnError: false })
  const version = about?.label ?? data?.version
  return (
    <SettingsColumn>
      <PageHeader
        title={t("Hakkında")}
        description={t("Kişisel, bağımsız ve gizlilik öncelikli mesh VPN; ağın sahibi yalnızca sensin.")}
        badge={about?.channel === "beta" ? <SettingBadge tone="warning">Beta</SettingBadge> : null}
      />
      <SettingsSection id="surum" title={t("Sürüm")}>
        <SettingRow
          title={<BrandWordmark className="h-6" />}
          description={
            about?.channel === "beta"
              ? t("Bu bir önsürüm. Hata bulursanız bildirin.")
              : about?.channel === "dev"
                ? t("Geliştirme derlemesi")
                : t("Bu bilgisayarda çalışan program ve panel.")
          }
          action={<SettingBadge>{version ? t("Sürüm: {version}", { version }) : t("Sürüm bilgisi alınıyor")}</SettingBadge>}
        />
        {about?.build ? (
          <SettingRow title={t("Derleme")} action={<span className="font-mono text-sm tabular-nums">{about.build}</span>} />
        ) : null}
        {about ? (
          <SettingRow
            title={about.update_channel === "beta" ? t("Güncelleme kanalı: Beta (önsürümler dahil)") : t("Güncelleme kanalı: Kararlı")}
            description={
              <>
                {t("Değiştirmek için yönetici olarak:")} <code className="font-mono text-xs">openscale update channel beta</code> {t("veya")}{" "}
                <code className="font-mono text-xs">stable</code>
              </>
            }
          />
        ) : null}
      </SettingsSection>
      <AutoUpdateSection />
      <LicenseSection
        id="dagitilan-bilesenler"
        title={t("Programla dağıtılan bileşenler")}
        description={t("openscale.exe içine gömülü veya onunla birlikte dağıtılan açık kaynak bileşenler ve veriler.")}
        items={bundled}
      />
      <LicenseSection
        id="panel-paketleri"
        title={t("Panelin açık kaynak paketleri")}
        description={t("Panel derleme sırasında bu npm paketleriyle üretilir ve programa gömülür; çalışırken hiçbir dış adrese istek yapmaz.")}
        items={panelPackages}
      />
      <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
        {t("Lisans metinleri her bileşenin kendi kaynak deposunda yer alır. Wintun lisansı kaynak kodda")}
        <code className="mx-1 font-mono text-xs break-all">internal/wintunembed/dll/LICENSE.txt</code>
        {t("dosyasıdır; bu liste go.mod ve panel/package.json ile birlikte güncellenir.")}
      </p>
    </SettingsColumn>
  )
}

function LicenseSection({ id, title, description, items }: { id: string; title: string; description: string; items: Component[] }) {
  const { t } = useI18n()
  return (
    <DetailSection id={id} title={title} description={description} framed={false}>
      <ListTable label={title}>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className={headCell}>{t("Bileşen")}</TableHead>
            <TableHead className={cn(headCell, "hidden sm:table-cell")}>{t("Kullanım")}</TableHead>
            <TableHead className={headCell}>{t("Lisans")}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map((c) => (
            <TableRow key={c.name}>
              <TableCell className="min-w-36 whitespace-normal">
                <span className="flex flex-col gap-0.5">
                  <span className="text-sm font-medium">{t(c.name)}</span>
                  <span className="text-xs text-muted-foreground sm:hidden">{t(c.use)}</span>
                </span>
              </TableCell>
              <TableCell className="hidden min-w-48 text-sm whitespace-normal text-muted-foreground sm:table-cell">{t(c.use)}</TableCell>
              <TableCell className="min-w-32 text-sm whitespace-normal">
                {c.href ? (
                  <a href={c.href} className="underline underline-offset-4 hover:text-foreground">
                    {t(c.license)}
                  </a>
                ) : (
                  t(c.license)
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </ListTable>
    </DetailSection>
  )
}
