"use client"

import useSWR from "swr"

import { SettingBadge, SettingRow, SettingsSection } from "@/components/settings/settings-layout"
import { fetcher } from "@/lib/api"
import { formatAgo } from "@/lib/format"
import { useI18n } from "@/lib/i18n/i18n"
import type { CoordinatorState, CoordinatorsResponse } from "@/lib/wave3-types"

/** A coordinator that has not answered for this long while another did is reported as silent (node: integrityFresh). */
const FRESH_MS = 10 * 60 * 1000

type Observed = { state: CoordinatorState; fresh: boolean }

interface Stamped {
  at: number
  body: CoordinatorsResponse
}

/** Fetches the coordinators and records when, so freshness is judged against the fetch time rather than the render. */
async function fetchStamped([path]: readonly [string, string]): Promise<Stamped> {
  const body = await fetcher<CoordinatorsResponse>(path)
  return { at: Date.now(), body }
}

function observe(list: CoordinatorState[], now: number): Observed[] {
  return list.map((state) => {
    const at = state.lastReply ? Date.parse(state.lastReply) : Number.NaN
    return { state, fresh: Number.isFinite(at) && now - at <= FRESH_MS }
  })
}

/**
 * Ağ > Koordinatörler, çapraz denetimin gözlem kaynağı (#631): bu cihazın
 * her koordinatörden en son ne zaman yanıt aldığı. Diğerleri yanıt verirken
 * susan bir koordinatör bu cihazı sansürlüyor olabilir; belge özeti
 * uyuşmazlıkları ayrıca "Bütünlük uyarıları" altında görünür.
 */
export function CoordinatorObservation() {
  const { t } = useI18n()
  const { data } = useSWR(["/api/network/coordinators", "gozlem"] as const, fetchStamped, { refreshInterval: 15_000 })
  const device = data?.body.device
  if (!device) {
    return (
      <SettingsSection id="gozlem" title={t("Bu cihazın gözlemi")}>
        <SettingRow
          title={t("Gözlem yok")}
          description={t("Panel bu bilgisayarın tünel hizmetine bağlı değil; koordinatör yanıtları yalnızca tünel çalışırken izlenir.")}
        />
      </SettingsSection>
    )
  }
  const now = data.at
  const observed = observe(device.coordinators, now)
  const anyFresh = observed.some((o) => o.fresh)
  const silent = observed.filter((o) => anyFresh && !o.fresh)
  return (
    <SettingsSection
      id="gozlem"
      title={t("Bu cihazın gözlemi")}
      description={t("Cihaz her koordinatörün yanıtını ve bildirdiği belge sürümünü izler. Biri susarken diğerleri yanıt veriyorsa o koordinatör bu cihazı sansürlüyor olabilir.")}
    >
      {observed.length === 0 ? (
        <SettingRow title={t("Henüz gözlem yok")} description={t("Tünel açıldıktan sonra koordinatör yanıtları burada görünür.")} />
      ) : (
        observed.map(({ state, fresh }) => (
          <SettingRow
            key={state.fingerprint}
            title={<span className="font-mono">{state.name || state.fingerprint}</span>}
            description={
              state.lastReply
                ? state.failures > 0
                  ? t("Son yanıt {ago}, ardından {count} başarısız deneme", { ago: formatAgo(state.lastReply, now), count: state.failures })
                  : t("Son yanıt {ago}", { ago: formatAgo(state.lastReply, now) })
                : t("Bu açılıştan beri yanıt alınmadı.")
            }
            action={
              fresh ? (
                <SettingBadge tone="success">{t("Yanıt veriyor")}</SettingBadge>
              ) : anyFresh ? (
                <SettingBadge tone="warning">{t("Susuyor")}</SettingBadge>
              ) : (
                <SettingBadge>{t("Bekleniyor")}</SettingBadge>
              )
            }
          />
        ))
      )}
      {silent.length > 0 ? (
        <p role="status" className="rounded-lg bg-warning/15 px-3 py-2 text-sm text-pretty text-warning-foreground dark:text-warning">
          {silent.length === 1
            ? t("Bir koordinatör son 10 dakikadır yanıt vermiyor, diğerleri veriyor. Sunucunun çalıştığını sağlayıcısından denetleyin; sürerse çapraz denetim eksik kalır.")
            : t("{count} koordinatör son 10 dakikadır yanıt vermiyor, diğerleri veriyor. Sunucunun çalıştığını sağlayıcısından denetleyin; sürerse çapraz denetim eksik kalır.", { count: silent.length })}
        </p>
      ) : null}
    </SettingsSection>
  )
}
