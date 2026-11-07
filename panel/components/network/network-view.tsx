"use client"

import useSWR from "swr"

import { BundleDownload } from "@/components/network/bundle-download"
import { ExitUsersRow } from "@/components/network/exit-users-card"
import { InstallCommands } from "@/components/network/install-commands"
import { NetworkNameRow } from "@/components/network/network-name-card"
import { NetworkReportSection } from "@/components/network/network-report"
import { RootSASRow } from "@/components/network/root-sas-card"
import { PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { SettingDisclosure, SettingRow, SettingsColumn, SettingsSection, ValueBox } from "@/components/settings/settings-layout"
import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { NetworkInfo } from "@/lib/types"

/** Ağ > Genel: the network's identity, addresses and joining. */
export function NetworkView() {
  const { t } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<NetworkInfo>("/api/network", fetcher)

  return (
    <SettingsColumn>
      <PageHeader title={t("Ağ")} description={t("Ağın kimliği, adres aralıkları ve yeni cihazların katılımı.")} />
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {data ? (
          <>
            <SettingsSection id="ag" title={t("Ağ")} description={t("Ağ belgesinde imzalı, bütün cihazların gördüğü bilgiler.")} signed>
              <NetworkNameRow displayName={data.displayName} />
              <SettingRow
                title={t("Ağ kimliği")}
                description={t("Ağı diğer OpenScale ağlarından ayıran kimlik.")}
                action={<ValueBox value={data.networkId} label={t("Ağ kimliğini kopyala")} />}
              />
              <SettingRow
                title={t("Adres aralıkları")}
                description={t("Cihazların tünel içi adresleri bu aralıklardan verilir.")}
                action={
                  <span className="flex flex-col items-start gap-0.5 font-mono text-sm sm:items-end">
                    <span>{data.ipv4Prefix}</span>
                    <span className="text-muted-foreground">{data.ipv6Prefix}</span>
                  </span>
                }
              />
              <SettingRow
                title={t("Belge sürümü")}
                description={t("Her imzalı değişiklik sürümü bir artırır.")}
                action={<span className="font-mono text-sm">v{data.version}</span>}
              />
            </SettingsSection>

            <SettingsSection id="katilim" title={t("Katılım")} description={t("Yeni cihazlar kök anahtarı bu bilgilerle doğrular.")}>
              <SettingRow
                title={t("Kök anahtar parmak izi")}
                description={t("Yeni bir cihazda katılırken yazılan parmak izi.")}
                action={<ValueBox value={data.rootFingerprint} label={t("Parmak izini kopyala")} />}
              />
              <RootSASRow />
              <SettingRow
                title={t("Katılım paketi")}
                description={t("Kök anahtarı ve koordinatörü tanıtan paket; yalnızca açık bilgi içerir.")}
                action={<BundleDownload bundle={data.bundle} />}
              />
              <SettingDisclosure
                title={t("Komut satırıyla kurulum")}
                description={t("Yeni bir bilgisayarı ağa katmak için o bilgisayarda çalıştırılacak adımlar.")}
                openLabel={t("Adımları göster")}
                closeLabel={t("Adımları gizle")}
              >
                <InstallCommands rootFingerprint={data.rootFingerprint} />
              </SettingDisclosure>
            </SettingsSection>

            <SettingsSection id="cikis-dugumleri" title={t("Çıkış düğümleri")} description={t("İnternet trafiğini ağdaki bir cihaz üzerinden çıkarma.")} signed>
              <ExitUsersRow exitUsers={data.exitUsers} />
            </SettingsSection>

            <NetworkReportSection />
          </>
        ) : null}
      </QueryState>
    </SettingsColumn>
  )
}
