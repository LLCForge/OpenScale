"use client"

import { useState } from "react"
import Link from "next/link"
import useSWR from "swr"
import { CalendarClock, Download, KeyRound } from "lucide-react"

import { Writable } from "@/components/app/read-only"
import { ExitAutoCard } from "@/components/app/exit-auto-card"
import { ExitNodeCard } from "@/components/app/exit-node-card"
import { useAppStatus } from "@/components/app/use-app-status"
import { useRemoteSession } from "@/components/auth/session"
import { CopyButton } from "@/components/copy-field"
import { LanguageSwitch } from "@/components/language-switcher"
import { PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { AdvancedSettingsCard } from "@/components/security/advanced-card"
import { ApprovalRows } from "@/components/security/approval-card"
import { BackupDialog } from "@/components/security/backup-dialog"
import { KeyHardeningRows } from "@/components/security/key-hardening-card"
import { LocalSecurityCard } from "@/components/security/local-security-card"
import { PassphraseDialog } from "@/components/security/passphrase-dialog"
import { PersonalDataSection } from "@/components/security/pii-section"
import { RDeskCard } from "@/components/security/rdesk-card"
import { RenewDialog } from "@/components/security/renew-dialog"
import { TrafficCard } from "@/components/security/traffic-card"
import { TransportCard } from "@/components/security/transport-card"
import { DDNSSection } from "@/components/settings/ddns-section"
import { DesktopSection } from "@/components/settings/desktop-section"
import { PlatformSection } from "@/components/settings/platform-section"
import { EmptyNote, SettingBadge, SettingRow, SettingsColumn, SettingsSection } from "@/components/settings/settings-layout"
import { useHash, useScrollToHash } from "@/components/settings/use-hash"
import { Button } from "@/components/ui/button"
import { fetcher } from "@/lib/api"
import { daysLabel, formatDate } from "@/lib/format"
import { useI18n } from "@/lib/i18n/i18n"
import type { Overview } from "@/lib/types"

/**
 * Ayarlar > Ağ (imzalı): the root key and the signed network document that
 * every device follows. This computer's own settings are on
 * /settings/local, so nothing local looks like it needs the root key.
 * The address fragment ("/settings#ag-belgesi") scrolls to its section.
 */
export function SecurityView() {
  const { t } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<Overview>("/api/overview", fetcher)
  const [dialog, setDialog] = useState<"backup" | "passphrase" | "renew" | null>(null)
  const hash = useHash()
  useScrollToHash(hash, data !== undefined)
  const close = (open: boolean) => {
    if (!open) setDialog(null)
  }

  return (
    <SettingsColumn>
      <PageHeader
        title={t("Ağ ayarları")}
        description={t("Kök anahtar ve bütün cihazların uyduğu imzalı ağ belgesi. Yalnızca bu bilgisayarı etkileyen ayarlar Bu bilgisayar sekmesinde.")}
      />
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {data ? (
          <>
            <SettingsSection
              // i18n-ignore: adres parçası (URL fragment), gösterilmez
              id="kok-anahtar"
              title={t("Kök anahtar")}
              description={t("Ağın sahipliği bu anahtardadır; yedeksiz kaybı ağın kaybıdır.")}
            >
              <SettingRow
                title={t("Yedekler")}
                badge={
                  data.backupCount > 0 ? (
                    <SettingBadge>{t("{count} yedek", { count: data.backupCount })}</SettingBadge>
                  ) : (
                    <SettingBadge tone="danger">{t("Hiç yedek yok")}</SettingBadge>
                  )
                }
                description={
                  data.lastBackupAt
                    ? t("Son yedek {date}. Her yedek ayrı bir parolayla şifrelenir.", { date: formatDate(data.lastBackupAt) })
                    : t("Her yedek ayrı bir parolayla şifrelenir; birini çevrim dışı sakla.")
                }
                action={
                  <Writable>
                    <Button variant={data.backupCount > 0 ? "outline" : "default"} onClick={() => setDialog("backup")}>
                      <Download data-icon="inline-start" />
                      {t("Yedek indir")}
                    </Button>
                  </Writable>
                }
              />
              <SettingRow
                title={t("Parmak izi")}
                description={t("Yeni cihazlar kök anahtarı bu parmak iziyle doğrular.")}
                action={
                  <span className="flex max-w-full min-w-0 items-center gap-1 rounded-md border bg-muted/40 py-1 pr-1 pl-3">
                    <span className="truncate font-mono text-sm tracking-wider">{data.rootFingerprint}</span>
                    <CopyButton value={data.rootFingerprint} label={t("Parmak izini kopyala")} />
                  </span>
                }
              />
              <KeyHardeningRows />
            </SettingsSection>

            <SettingsSection
              // i18n-ignore: adres parçası (URL fragment), gösterilmez
              id="ag-belgesi"
              title={t("Ağ belgesi")}
              description={t("Cihazların uyduğu, kök anahtarla imzalı belge. Her değişiklik önce farkı gösterir.")}
              signed
            >
              <SettingRow
                title={t("Geçerlilik")}
                badge={data.daysLeft <= 14 ? <SettingBadge tone="danger">{daysLabel(data.daysLeft)}</SettingBadge> : null}
                description={
                  data.daysLeft > 14
                    ? t("{date} tarihine kadar geçerli ({days}). Süresi dolan belgeyle yeni bağlantı kurulmaz.", {
                        date: formatDate(data.expiresAt),
                        days: daysLabel(data.daysLeft),
                      })
                    : t("{date} tarihine kadar geçerli. Süresi dolan belgeyle yeni bağlantı kurulmaz.", { date: formatDate(data.expiresAt) })
                }
                action={
                  <Writable>
                    <Button variant="outline" onClick={() => setDialog("renew")}>
                      <CalendarClock data-icon="inline-start" />
                      {t("Belgeyi yenile")}
                    </Button>
                  </Writable>
                }
              />
              <ApprovalRows />
            </SettingsSection>

            <PersonalDataSection />

            <SettingsSection id="tehlikeli-bolge" title={t("Tehlikeli bölge")} tone="danger">
              <SettingRow
                title={t("Kök anahtar parolasını değiştir")}
                description={t("Yeni parolayı unutursan kök anahtara yalnızca yedeklerle ulaşabilirsin. Mevcut yedekler kendi parolalarıyla geçerli kalır.")}
                action={
                  <Writable>
                    <Button variant="destructive" onClick={() => setDialog("passphrase")}>
                      <KeyRound data-icon="inline-start" />
                      {t("Parolayı değiştir")}
                    </Button>
                  </Writable>
                }
              />
            </SettingsSection>
          </>
        ) : null}
      </QueryState>

      <BackupDialog open={dialog === "backup"} onOpenChange={close} onCreated={() => mutate()} />
      <PassphraseDialog open={dialog === "passphrase"} onOpenChange={close} />
      <RenewDialog open={dialog === "renew"} onOpenChange={close} />
    </SettingsColumn>
  )
}

/**
 * Ayarlar > Bu bilgisayar: settings that apply only to this computer (exit
 * node, shared services, transport). They do not change the network
 * document and need no signature. "/settings/local#cikis" scrolls to the
 * exit node section.
 */
export function LocalSettingsView() {
  const { t } = useI18n()
  const { status, isApp, error, isLoading, mutate } = useAppStatus()
  const remote = useRemoteSession()
  const hash = useHash()
  const appDevice = isApp && status?.device?.name ? status : null
  const [settingsBefore = "", settingsAfter = ""] = t(
    "Bu ayarlar OpenScale masaüstü uygulamasının servisinden gelir; komut satırından açılan panelde görünmez. Ağın imzalı ayarları {link} sayfasında."
  ).split("{link}")
  useScrollToHash(hash, appDevice !== null)

  return (
    <SettingsColumn>
      <PageHeader
        title={t("Bu bilgisayar")}
        description={t("Yalnızca bu bilgisayarda geçerli. Ağ belgesini değiştirmez, imza gerekmez; diğer cihazlar etkilenmez.")}
      />
      <SettingsSection id="dil" title={t("Görünüm")}>
        <SettingRow title={t("Arayüz dili")} description={t("Panelin dili. Seçim bu tarayıcıda saklanır.")} action={<LanguageSwitch />} />
      </SettingsSection>
      {remote ? (
        <EmptyNote>
          {t("Uzak panelde bu bilgisayarın ayarları gösterilmez. Bu ayarları ilgili bilgisayarda OpenScale uygulamasından açıp değiştir.")}
        </EmptyNote>
      ) : !isApp ? (
        <EmptyNote>
          {settingsBefore}
          <Link href="/settings" className="font-medium text-foreground underline underline-offset-4">
            {t("Ağ ayarları")}
          </Link>
          {settingsAfter}
        </EmptyNote>
      ) : (
        <QueryState error={error} isLoading={isLoading && !status} onRetry={() => mutate()}>
          {appDevice ? (
            <>
              <SettingsSection id="cikis" title={t("Çıkış düğümü")} description={t("Bu bilgisayarın internet trafiğinin nereden çıkacağı.")}>
                <ExitNodeCard />
                <ExitAutoCard />
              </SettingsSection>

              <SettingsSection
                id="yerel-guvenlik"
                title={t("Paylaşım ve koruma")}
                description={t("Bu bilgisayarın ağa açtığı hizmetler, uzak masaüstü izinleri ve DNS korumaları.")}
              >
                <LocalSecurityCard />
                <RDeskCard />
              </SettingsSection>

              <DDNSSection />
              <PlatformSection />
              <DesktopSection />

              <SettingsSection id="gelismis" title={t("Gelişmiş")} description={t("Emin değilsen varsayılanları değiştirme.")}>
                <AdvancedSettingsCard />
                <TransportCard status={appDevice} />
                <TrafficCard />
              </SettingsSection>
            </>
          ) : (
            <EmptyNote>{t("Bu bilgisayar henüz bir ağa katılmadı; ayarlar katıldıktan sonra burada görünür.")}</EmptyNote>
          )}
        </QueryState>
      )}
    </SettingsColumn>
  )
}
