"use client"

import { useState } from "react"
import useSWR from "swr"
import { toast } from "sonner"

import { useReadOnly } from "@/components/app/read-only"
import { SettingBadge, SettingRow } from "@/components/settings/settings-layout"
import { Switch } from "@/components/ui/switch"
import { errorMessage, fetcher, post } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"

/** One share a device reported (ADR-0226). */
interface NetPlaceShare {
  name: string
  comment?: string
}

/** One device of the network with the shares of its last report. */
interface NetPlaceDevice {
  name: string
  host: string
  known: boolean
  shares: NetPlaceShare[] | null
}

/** Reply of /api/app/netplaces. */
interface NetPlacesStatus {
  supported: boolean
  on: boolean
  admin: boolean
  ready: boolean
  devices: NetPlaceDevice[]
  shares: number
}

/**
 * Ayarlar > Bu bilgisayar: the switch that adds the other devices' SMB
 * shares under "Ağdaki konumlar" in Windows Explorer. The tray writes the
 * locations within a minute; credentials never pass through OpenScale.
 */
export function NetPlacesRow() {
  const { t } = useI18n()
  const { data, mutate } = useSWR<NetPlacesStatus>("/api/app/netplaces", fetcher, {
    refreshInterval: 30000,
    shouldRetryOnError: false,
  })
  const readOnly = useReadOnly()
  const [busy, setBusy] = useState(false)
  if (!data?.supported) return null

  async function toggle(on: boolean) {
    setBusy(true)
    try {
      await mutate(await post<NetPlacesStatus>("/api/app/netplaces", { on }), { revalidate: false })
      toast.success(
        on
          ? t("Ağ konumları açıldı; paylaşımlar bir dakika içinde Gezgin'de görünür.")
          : t("Ağ konumları kapatıldı; OpenScale'in eklediği konumlar kaldırılıyor.")
      )
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const note = !data.admin
    ? t("Bu cihaz yönetici değil: diğer cihazların paylaşım listesi yalnızca yönetici cihazlara gelir.")
    : !data.ready
      ? t("Tünel çalışmıyor; konumlar tünel açılınca güncellenir.")
      : data.shares === 0
        ? t("Ağdaki cihazlar henüz paylaşım bildirmedi.")
        : t("{count} paylaşım bulundu.", { count: data.shares })

  const withShares = data.devices.filter((d) => d.known && d.shares && d.shares.length > 0)

  return (
    <SettingRow
      title={t("Paylaşımları Ağdaki konumlara ekle")}
      htmlFor="netplaces-switch"
      badge={<SettingBadge tone={data.on ? "success" : "muted"}>{data.on ? t("Açık") : t("Kapalı")}</SettingBadge>}
      description={
        <span className="flex flex-col gap-1">
          <span>
            {t(
              "Ağdaki cihazların SMB paylaşımları Dosya Gezgini'nde Bu bilgisayar > Ağdaki konumlar altında görünür ve tünel üzerinden açılır. Sürücü harfi kullanılmaz; parola istenirse Windows kendi penceresini açar. Elle eklediğiniz konumlara dokunulmaz."
            )}
          </span>
          <span>{note}</span>
        </span>
      }
      action={
        <Switch
          id="netplaces-switch"
          checked={data.on}
          disabled={readOnly || busy}
          onCheckedChange={(on) => void toggle(on)}
        />
      }
    >
      {data.on && withShares.length > 0 ? (
        <ul className="flex flex-col gap-1 text-sm text-muted-foreground" aria-label={t("Bulunan paylaşımlar")}>
          {withShares.flatMap((d) =>
            (d.shares ?? []).map((s) => (
              <li key={`${d.name}/${s.name}`} className="flex flex-wrap items-center gap-2">
                <span className="font-medium text-foreground">{`${s.name} (${d.name})`}</span>
                <span className="font-mono text-xs break-all">{`\\\\${d.host}\\${s.name}`}</span>
              </li>
            ))
          )}
        </ul>
      ) : null}
    </SettingRow>
  )
}
