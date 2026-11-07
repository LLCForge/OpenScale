"use client"

import { useState } from "react"
import { ChevronDown, Timer } from "lucide-react"
import { toast } from "sonner"

import { useReadOnly } from "@/components/app/read-only"
import { useAppStatus } from "@/components/app/use-app-status"
import { SettingBadge, SettingRow } from "@/components/settings/settings-layout"
import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { errorMessage, post } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import type { AppStatus, DeviceStatus, DisconnectChoice } from "@/lib/types"

const timedChoices: { value: DisconnectChoice; label: string; done: string }[] = [
  { value: "5m", label: msg("5 dakika"), done: msg("Bağlantı kesildi; 5 dakika sonra kendiliğinden açılır.") },
  { value: "1h", label: msg("1 saat"), done: msg("Bağlantı kesildi; 1 saat sonra kendiliğinden açılır.") },
  { value: "morning", label: msg("Yarın sabaha kadar"), done: msg("Bağlantı kesildi; sabah 08.00'de kendiliğinden açılır.") },
]

/**
 * The connect switch of this computer (F-156) with the timed disconnect
 * choices (F-121), as one settings row. The service turns a timed
 * disconnect back on by itself, also after a restart.
 */
export function ConnectionRow() {
  const { t } = useI18n()
  const { status, isApp, mutate } = useAppStatus()
  const readOnly = useReadOnly()
  const [busy, setBusy] = useState<string | null>(null)
  const device = status?.device
  if (!isApp || !device || !device.name || device.removed) return null

  async function send(key: string, body: { connected: boolean; for?: DisconnectChoice }, done: string) {
    setBusy(key)
    try {
      const res = await post<AppStatus>("/api/app/connect", body)
      await mutate(res, { revalidate: false })
      toast.success(t(done))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  const on = device.connected
  const toggle = () =>
    send("toggle", { connected: !on }, on ? msg("Bağlantı kesildi. Yeniden açana kadar kapalı kalır.") : msg("Bağlantı açılıyor."))

  return (
    <SettingRow
      title={t("Bağlantı")}
      htmlFor={readOnly ? undefined : "connection-switch"}
      badge={on ? <SettingBadge tone="success">{t("Bağlı")}</SettingBadge> : <SettingBadge tone="warning">{t("Kapalı")}</SettingBadge>}
      description={describe(device)}
      action={
        readOnly ? null : (
          <>
            {on ? (
              <DropdownMenu>
                <DropdownMenuTrigger render={<Button variant="outline" size="sm" disabled={busy !== null} />}>
                  {busy !== null && busy !== "toggle" ? <Spinner data-icon="inline-start" /> : <Timer data-icon="inline-start" />}
                  {t("Süreli kes")}
                  <ChevronDown data-icon="inline-end" />
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-52">
                  {timedChoices.map((c) => (
                    <DropdownMenuItem key={c.value} onClick={() => send(c.value, { connected: false, for: c.value }, c.done)}>
                      {t(c.label)}
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
            ) : null}
            {busy === "toggle" ? <Spinner /> : null}
            <Switch id="connection-switch" checked={on} disabled={busy !== null} onCheckedChange={toggle} />
          </>
        )
      }
    />
  )
}

function describe(device: DeviceStatus): string {
  if (!device.connected && device.disconnectedUntil) {
    return tx("Süreli olarak kesik; {time} sonrasında kendiliğinden açılır. Hemen açmak için anahtarı kullan.", {
      time: formatDateTime(device.disconnectedUntil),
    })
  }
  if (!device.connected) {
    return tx("Diğer cihazlara ulaşılamaz. Bağlantı sen açana kadar kapalı kalır; bilgisayar yeniden başlasa da kapalı kalır.")
  }
  return tx(
    "{name} · {ip}. Kapatınca diğer cihazlara ulaşılmaz ve seçili çıkış düğümü kullanılmaz; süreli kesersen süre dolunca kendiliğinden açılır.",
    { name: device.name, ip: device.ipv4 },
  )
}
