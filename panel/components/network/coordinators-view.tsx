"use client"

import { useState } from "react"
import useSWR from "swr"
import { Pencil, Plus } from "lucide-react"

import { Writable } from "@/components/app/read-only"
import { CodeLine } from "@/components/copy-field"
import { CoordinatorDialog } from "@/components/network/coordinator-dialog"
import { CoordinatorsCard } from "@/components/network/coordinators-card"
import { CoordinatorIndependence } from "@/components/network/coordinator-independence"
import { PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { EmptyNote, SettingBadge, SettingDisclosure, SettingRow, SettingsColumn, SettingsSection, ValueBox } from "@/components/settings/settings-layout"
import { Button } from "@/components/ui/button"
import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { NetworkInfo } from "@/lib/types"

const COORDINATOR_DIR = "/var/lib/openscale-coordinator"

/** Ağ > Koordinatörler: the coordinator in the document, the others and how to set one up. */
export function CoordinatorsView() {
  const { t } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<NetworkInfo>("/api/network", fetcher)
  const [editing, setEditing] = useState(false)
  const c = data?.coordinator ?? null

  return (
    <SettingsColumn>
      <PageHeader
        title={t("Koordinatörler")}
        description={t("Cihazların birbirini bulmasını sağlayan sunucular; belgeyi değiştiremez, trafiği göremez.")}
      />
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {data ? (
          <>
            <SettingsSection
              id="birincil"
              title={t("Birincil koordinatör")}
              signed
              description={t("Cihazlar bu adrese WireGuard ile bağlanır; kontrol trafiği tünel içindedir.")}
              action={
                c ? (
                  <SettingBadge tone="success">{t("Tanımlı")}</SettingBadge>
                ) : (
                  <Writable>
                    <Button onClick={() => setEditing(true)}>
                      <Plus data-icon="inline-start" />
                      {t("Koordinatör ekle")}
                    </Button>
                  </Writable>
                )
              }
            >
              {c ? (
                <>
                  <SettingRow title={t("Genel adres")} action={<ValueBox value={c.endpoint} label={t("Genel adresi kopyala")} />} />
                  <SettingRow title={t("Parmak izi")} action={<ValueBox value={c.fingerprint} label={t("Parmak izini kopyala")} />} />
                  <SettingRow title={t("WireGuard anahtarı")} action={<ValueBox value={c.wireguardKey} label={t("WireGuard anahtarını kopyala")} />} />
                  <SettingRow
                    title={t("Tünel içi adres")}
                    action={
                      <span className="flex flex-col items-start gap-0.5 font-mono text-sm sm:items-end">
                        <span>{c.ipv4}</span>
                        <span className="text-muted-foreground">{c.ipv6}</span>
                      </span>
                    }
                  />
                </>
              ) : (
                <EmptyNote framed={false}>{t("Koordinatör tanımlı değil; cihazlar birbirini bulamaz.")}</EmptyNote>
              )}
            </SettingsSection>

            <SettingsSection id="liste" title={t("Tüm koordinatörler")} description={t("Belgedeki ek koordinatörler ve bu bilgisayarın onlara bağlantısı.")} signed>
              <CoordinatorsCard />
            </SettingsSection>

            <CoordinatorIndependence />

            <SettingsSection id="kurulum" title={t("Sunucu kurulumu")} description={t("Koordinatörü bir VPS'te veya ev sunucusunda çalıştırma.")}>
              <SettingDisclosure
                title={t("Kurulum komutları")}
                description={t("Linux sunucuda root olarak çalıştırılır.")}
                openLabel={t("Komutları göster")}
                closeLabel={t("Komutları gizle")}
              >
                <div className="flex flex-col gap-3">
                  <CodeLine value={`openscale coordinator keygen --state-dir ${COORDINATOR_DIR}`} nowrap />
                  <p className="text-sm text-muted-foreground text-pretty">
                    {t("Çıkan anahtarı ve parmak izini \"Koordinatör ekle\" ile kaydet, sonra katılım paketini sunucuya kopyalayıp:")}
                  </p>
                  <CodeLine
                    value={`openscale join --state-dir ${COORDINATOR_DIR} --bundle @openscale-bundle.txt --root-fingerprint ${data.rootFingerprint}`}
                    nowrap
                  />
                  <CodeLine value={`openscale coordinator run --state-dir ${COORDINATOR_DIR} --listen-port 51820`} nowrap />
                  <p className="text-sm text-muted-foreground text-pretty">
                    {t("Ev sunucusunda modemde 51820/UDP'yi sunucuya yönlendir ve adres olarak dinamik DNS adını kullan.")}
                  </p>
                </div>
              </SettingDisclosure>
            </SettingsSection>

            {c ? (
              <Writable>
                <SettingsSection id="tehlikeli-bolge" title={t("Tehlikeli bölge")} tone="danger">
                  <SettingRow
                    title={t("Koordinatörü değiştir")}
                    description={t("Yanlış adres veya anahtar bütün cihazların bağlantısını keser; değişiklik belgeye imzalanır.")}
                    action={
                      <Button variant="outline" className="border-destructive/40 text-destructive hover:bg-destructive/10" onClick={() => setEditing(true)}>
                        <Pencil data-icon="inline-start" />
                        {t("Değiştir")}
                      </Button>
                    }
                  />
                </SettingsSection>
              </Writable>
            ) : null}
          </>
        ) : null}
      </QueryState>
      <CoordinatorDialog open={editing} onOpenChange={setEditing} current={c} />
    </SettingsColumn>
  )
}
