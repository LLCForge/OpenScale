"use client"

import { useState } from "react"
import useSWR from "swr"
import { toast } from "sonner"

import { useReadOnly } from "@/components/app/read-only"
import { DiagSectionState } from "@/components/diag/diag-errors"
import { SettingRow, SettingsSection } from "@/components/settings/settings-layout"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { errorMessage, fetcher, post } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { ObservePrefs } from "@/lib/observe"

type Key = "notifications" | "metrics"

/**
 * Notifications (F-158) and the local metrics endpoint (F-198). Metrics are
 * off by default and, when on, answer only on 127.0.0.1 with the app token
 * from an administrator process.
 */
export function ObserveSettingsCard() {
  const { data, error, isLoading, mutate } = useSWR<ObservePrefs>("/api/app/diag/observe", fetcher)
  const readOnly = useReadOnly()
  const { t } = useI18n()
  const [busy, setBusy] = useState<Key | null>(null)

  async function change(key: Key, on: boolean) {
    setBusy(key)
    try {
      const next = await post<ObservePrefs>("/api/app/diag/observe", { [key]: on })
      await mutate(next, { revalidate: false })
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  const rows: { key: Key; title: string; hint: string }[] = [
    {
      key: "notifications",
      title: t("Masaüstü bildirimleri"),
      hint: t("Yeni veya çıkarılan cihaz, kill switch devreye girmesi ve reddedilen ağ belgesi için tepside bildirim."),
    },
    {
      key: "metrics",
      title: t("Yerel metrik uç noktası"),
      hint: t("Prometheus biçimi; yalnızca 127.0.0.1, uygulama anahtarı ve yönetici süreci ile. Komut satırında: openscale metrics print."),
    },
  ]

  return (
    <SettingsSection id="bildirim-metrik" title={t("Bildirim ve metrik")} description={t("Hiçbir kayıt veya ölçüm bu bilgisayarın dışına gönderilmez.")}>
      {error ? (
        <div data-slot="setting-row">
          <DiagSectionState section={t("Bildirim ve metrik")} error={error} isLoading={false}>
            {null}
          </DiagSectionState>
        </div>
      ) : isLoading || !data ? (
        <div data-slot="setting-row" className="py-5">
          <Spinner />
        </div>
      ) : (
        rows.map((r) => (
          <SettingRow
            key={r.key}
            title={r.title}
            htmlFor={`observe-${r.key}`}
            description={r.hint}
            action={
              <>
                {busy === r.key ? <Spinner /> : null}
                <Switch
                  id={`observe-${r.key}`}
                  checked={data[r.key]}
                  disabled={busy !== null || readOnly}
                  onCheckedChange={(on) => void change(r.key, on)}
                />
              </>
            }
          />
        ))
      )}
    </SettingsSection>
  )
}
