"use client"

import { useState } from "react"
import { useSearchParams } from "next/navigation"

import { RemoteActionsCard } from "@/components/apps/remote-actions-card"
import { ServeSuggestionsSection } from "@/components/apps/serve-suggestions"
import { useAppStatus } from "@/components/app/use-app-status"
import { DetailSection } from "@/components/devices/detail-card"
import { PageHeader } from "@/components/page-header"
import { radioGroupKeyDown } from "@/components/settings/radio-keys"
import { EmptyNote, SettingsColumn } from "@/components/settings/settings-layout"
import { useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

/** SSH, file send, wake and speed test from this computer to a peer. */
export function RemoteView() {
  const { t } = useI18n()
  const app = useAppStatus(10_000)
  const peers = app.status?.device?.peers ?? []
  const wanted = useSearchParams().get("device") ?? ""
  const [picked, setPicked] = useState<string>("")
  const selected = picked || (peers.some((p) => p.name === wanted) ? wanted : (peers[0]?.name ?? ""))

  return (
    <SettingsColumn className="max-w-4xl">
      <PageHeader
        title={t("Uzak erişim")}
        description={t("Tünel içinden SSH, dosya gönderme, uyandırma ve hız testi; izinleri servis kuralları belirler.")}
      />
      {!app.isApp ? (
        <EmptyNote>{t("Uzak erişim işlemleri OpenScale servisinin çalıştığı bilgisayardan, masaüstü uygulamasında yapılır.")}</EmptyNote>
      ) : peers.length === 0 ? (
        <EmptyNote>
          {t("Ulaşılabilir cihaz yok. Tünel kapalı olabilir ya da kurallar bu bilgisayarın hiçbir cihaza ulaşmasına izin vermiyor.")}
        </EmptyNote>
      ) : (
        <>
          {/* i18n-ignore: sayfa içi bağlantı kimliği */}
          <section aria-labelledby="cihaz-sec-baslik" className="flex flex-col gap-3">
            <div className="flex flex-col gap-1">
              {/* i18n-ignore: sayfa içi bağlantı kimliği */}
              <h2 id="cihaz-sec-baslik" className="text-base font-semibold">
                {t("Cihaz")}
              </h2>
              <p className="text-sm text-muted-foreground text-pretty">{t("Bu bilgisayarın ulaşabildiği cihazlardan birini seç.")}</p>
            </div>
            <div className="-mx-4 overflow-x-auto px-4 md:mx-0 md:px-0">
              <div role="radiogroup" aria-label={t("Cihaz")} onKeyDown={radioGroupKeyDown} className="inline-flex rounded-lg border p-0.5">
                {peers.map((p) => (
                  <button
                    key={p.name}
                    type="button"
                    role="radio"
                    aria-checked={selected === p.name}
                    tabIndex={selected === p.name ? 0 : -1}
                    onClick={() => setPicked(p.name)}
                    className={cn(
                      "flex items-center gap-1.5 rounded-md px-3 py-1 text-sm whitespace-nowrap transition-colors focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
                      selected === p.name ? "bg-secondary font-medium text-foreground" : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    <span
                      aria-hidden="true"
                      className={cn("size-1.5 rounded-full", p.online ? "bg-success" : "bg-muted-foreground/40")}
                    />
                    {p.name}
                  </button>
                ))}
              </div>
            </div>
          </section>
          {selected ? (
            <DetailSection
              id="uzak-erisim"
              title={t("{device} cihazına erişim", { device: selected })}
              description={t(
                "Bu bilgisayardan {device} cihazına tünel içinden yapılabilecekler. Karşı cihaz her isteği imzalı kurallara göre kendisi denetler; koordinatör hiçbirini görmez.",
                { device: selected }
              )}
            >
              <RemoteActionsCard key={selected} device={selected} bare />
            </DetailSection>
          ) : null}
        </>
      )}
      {app.isApp ? <ServeSuggestionsSection /> : null}
    </SettingsColumn>
  )
}
