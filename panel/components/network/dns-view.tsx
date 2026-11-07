"use client"

import { useState } from "react"
import useSWR from "swr"
import { Lock, Pencil, Plus, Trash2, TriangleAlert } from "lucide-react"

import { Writable } from "@/components/app/read-only"
import { DnsDialog } from "@/components/network/dns-dialog"
import { PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { EmptyNote, SettingBadge, SettingRow, SettingsColumn, SettingsSection, ValueBox } from "@/components/settings/settings-layout"
import { SignChangeDialog } from "@/components/sign-change"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { NetworkInfo } from "@/lib/types"

/** Ağ > DNS: MagicDNS, the network-wide resolvers, split DNS and search domains (ADR-0024). */
export function DnsView() {
  const { t } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<NetworkInfo>("/api/network", fetcher)
  const [editing, setEditing] = useState(false)
  const [removing, setRemoving] = useState(false)

  return (
    <SettingsColumn>
      <PageHeader title="DNS" description={t("Cihazların adları nasıl çözdüğü: MagicDNS, ad sunucuları ve alan adına göre yönlendirme.")} />
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {data ? (
          <DnsSections network={data} onEdit={() => setEditing(true)} onRemove={() => setRemoving(true)} />
        ) : null}
      </QueryState>
      {data ? (
        <>
          <DnsDialog open={editing} onOpenChange={setEditing} current={data.dns} resolvers={data.resolvers} dnsDomain={data.dnsDomain} />
          <SignChangeDialog
            open={removing}
            onOpenChange={setRemoving}
            title={t("DNS bölümünü kaldır")}
            description={t("Ağın DNS ayarları belgeden kaldırılır; cihazlar yeniden kendi çözücülerini kullanır. MagicDNS etkilenmez.")}
            endpoint="/api/network/dns"
            payload={{ clear: true, nameservers: [], split: [] }}
            confirmLabel={t("İmzala ve kaldır")}
            destructive
          />
        </>
      ) : null}
    </SettingsColumn>
  )
}

function DnsSections({ network, onEdit, onRemove }: { network: NetworkInfo; onEdit: () => void; onRemove: () => void }) {
  const { t, ts } = useI18n()
  const dns = network.dns
  const names = new Map<string, string>()
  for (const r of network.resolvers) {
    if (r.ipv4) names.set(r.ipv4, r.name)
    if (r.ipv6) names.set(r.ipv6, r.name)
  }
  const magic = network.magicDns
  const search = magic?.search ?? []

  return (
    <>
      <SettingsSection id="ag-dns-adi" title={t("Ağ DNS adı")} description={t("Cihazlar bu alanın altında kendi adlarıyla çözülür.")} signed>
        <SettingRow
          title={t("Alan adı")}
          description={t("Örneğin masaustu.{domain}; ad yalnızca ağ içinde geçerlidir.", { domain: network.dnsDomain })}
          action={<ValueBox value={network.dnsDomain} label={t("Alan adını kopyala")} />}
        />
      </SettingsSection>

      {network.dnsWarnings.length > 0 ? (
        <div className="flex flex-col gap-2">
          {network.dnsWarnings.map((w) => (
            <Alert key={w}>
              <TriangleAlert />
              <AlertDescription className="text-pretty">{ts(w)}</AlertDescription>
            </Alert>
          ))}
        </div>
      ) : null}

      <SettingsSection
        // i18n-ignore: bölüm bağlantısı, ekranda gösterilmez
        id="ad-sunuculari"
        signed
        title={t("Ad sunucuları")}
        description={t("Cihazların DNS sorgularını gönderdiği çözücüler.")}
        action={
          <Writable>
            <Button variant="outline" onClick={onEdit}>
              {dns ? <Pencil data-icon="inline-start" /> : <Plus data-icon="inline-start" />}
              {dns ? t("Düzenle") : t("Ad sunucusu ekle")}
            </Button>
          </Writable>
        }
      >
        <SettingRow
          title={network.dnsDomain}
          badge={<SettingBadge>MagicDNS</SettingBadge>}
          description={t("Ağ içindeki adları {resolver} yanıtlar; bu çözücü her zaman açıktır.", { resolver: network.dnsResolver })}
          action={
            <span className="flex items-center gap-1.5 text-sm text-muted-foreground">
              <Lock className="size-4" aria-hidden="true" />
              {t("Kilitli")}
            </span>
          }
        />
        <SettingRow
          title={t("Ağ geneli çözücüler")}
          description={
            dns && dns.nameservers.length > 0
              ? t("Diğer bütün sorgular bu çözücülere gider.")
              : t("Tanımlı değil; cihazlar kendi çözücülerini kullanır.")
          }
        >
          {dns && dns.nameservers.length > 0 ? (
            <ul className="flex flex-col divide-y rounded-lg border">
              {dns.nameservers.map((a) => (
                <li key={a} className="flex items-center justify-between gap-4 px-4 py-2.5 text-sm">
                  <span className="font-mono">{a}</span>
                  <span className="text-muted-foreground">{names.get(a) ?? ""}</span>
                </li>
              ))}
            </ul>
          ) : null}
          <p className="text-xs leading-relaxed text-muted-foreground text-pretty">
            {t("Çözücü olarak yalnızca ağdaki bir cihazın tünel adresi seçilebilir ve o cihaza 53. port için erişim kuralı gerekir. Eski sürümlü cihazlar DNS bölümü olan belgeyi reddeder.")}
          </p>
        </SettingRow>
      </SettingsSection>

      <SettingsSection
        id="split-dns"
        signed
        title="Split DNS"
        description={t("Belirli alan adlarının sorgularını ayrı çözücülere gönderir.")}
        action={
          <Writable>
            <Button variant="outline" onClick={onEdit}>
              <Plus data-icon="inline-start" />
              {t("Alan adı ekle")}
            </Button>
          </Writable>
        }
      >
        {dns && dns.split.length > 0 ? (
          dns.split.map((s) => (
            <SettingRow
              key={s.domain}
              title={<span className="font-mono">{s.domain}</span>}
              description={s.nameservers.map((a) => (names.has(a) ? `${a} (${names.get(a)})` : a)).join(", ")}
            />
          ))
        ) : (
          <EmptyNote framed={false}>{t("Alan adına göre yönlendirme yok.")}</EmptyNote>
        )}
      </SettingsSection>

      <SettingsSection id="arama-alanlari" title={t("Arama alanları")} description={t("Kısa adlara eklenen alanlar; örneğin ssh masaustu.")} signed>
        {search.length > 0 ? (
          search.map((d) => <SettingRow key={d} title={<span className="font-mono">{d}</span>} />)
        ) : (
          <EmptyNote framed={false}>
            {t("Arama alanı yok. Eklemek için:")} <code className="font-mono text-xs">openscale network dns search</code>
          </EmptyNote>
        )}
      </SettingsSection>

      <SettingsSection id="magicdns" title="MagicDNS" description={t("Cihaz adlarının ağ içinde kendiliğinden çözülmesi.")} signed>
        <SettingRow
          title="MagicDNS"
          badge={<SettingBadge tone="success">{t("Her zaman açık")}</SettingBadge>}
          description={t("Her cihaz <ad>.{domain} olarak çözülür; ad sunucusu ayarlarından bağımsız çalışır.", { domain: network.dnsDomain })}
        />
        <SettingRow
          title={t("Cihaz alt alanları")}
          description={t("Açıkken web.nas.{domain} gibi adlar da cihaza çözülür.", { domain: network.dnsDomain })}
          action={<SettingBadge tone={magic?.deviceSubdomains ? "success" : "muted"}>{magic?.deviceSubdomains ? t("Açık") : t("Kapalı")}</SettingBadge>}
        />
        <SettingRow
          title={t("Ek kayıtlar")}
          description={t("Alanın altındaki takma adlar ve SRV/TXT kayıtları; openscale network dns ile yönetilir.")}
          action={<span className="font-mono text-sm">{magic?.records ?? 0}</span>}
        />
      </SettingsSection>

      {dns ? (
        <Writable>
          <SettingsSection id="tehlikeli-bolge" title={t("Tehlikeli bölge")} tone="danger">
            <SettingRow
              title={t("DNS bölümünü kaldır")}
              description={t("Ad sunucuları ve split DNS belgeden kaldırılır; cihazlar yeniden kendi çözücülerini kullanır.")}
              action={
                <Button variant="outline" className="border-destructive/40 text-destructive hover:bg-destructive/10" onClick={onRemove}>
                  <Trash2 data-icon="inline-start" />
                  {t("Kaldır")}
                </Button>
              }
            />
          </SettingsSection>
        </Writable>
      ) : null}
    </>
  )
}
