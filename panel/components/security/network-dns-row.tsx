"use client"

import { useState } from "react"
import { toast } from "sonner"

import { useReadOnly } from "@/components/app/read-only"
import { useAppStatus } from "@/components/app/use-app-status"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { errorMessage, post } from "@/lib/api"
import { tx, useI18n } from "@/lib/i18n/i18n"
import type { AppStatus, DeviceStatus } from "@/lib/types"

function describe(device: DeviceStatus): string {
  if (!device.acceptNetworkDns) {
    return tx("Kapalı. Bu bilgisayar ağ belgesindeki DNS ayarlarını yok sayar ve kendi çözücülerini kullanır. MagicDNS adları çalışmaya devam eder.")
  }
  if (device.networkDnsActive) {
    return tx("Açık ve uygulanıyor. Ağ belgesindeki çözücüler ve alan adı yönlendirmeleri bu bilgisayarda etkin.")
  }
  return tx("Açık. Ağ belgesinde şu an DNS ayarı yok; bir ayar imzalandığında bu bilgisayar onu kendiliğinden uygular.")
}

/** F-065: whether this computer applies the DNS settings from the network document. */
export function NetworkDnsRow() {
  const { t, ts } = useI18n()
  const { status, mutate } = useAppStatus()
  const [busy, setBusy] = useState(false)
  const readOnly = useReadOnly()
  const device = status?.device
  if (!device || !device.name) return null

  async function toggle(accept: boolean) {
    setBusy(true)
    try {
      const res = await post<AppStatus>("/api/app/dns", { accept })
      await mutate(res, { revalidate: false })
      toast.success(accept ? t("Ağdan gelen DNS ayarları kullanılacak.") : t("Ağdan gelen DNS ayarları artık kullanılmayacak."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-col gap-2 px-4 py-3">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-start gap-3">
          <span className="flex flex-col gap-0.5">
            <label htmlFor="accept-network-dns" className="text-sm font-medium">
              {t("Ağdan gelen DNS ayarlarını kullan")}
            </label>
            <span className="text-sm leading-relaxed text-muted-foreground text-pretty">{describe(device)}</span>
          </span>
        </div>
        <div className="flex items-center gap-2">
          {busy ? <Spinner /> : null}
          <Switch
            id="accept-network-dns"
            checked={device.acceptNetworkDns}
            disabled={busy || readOnly}
            onCheckedChange={(on) => toggle(on)}
          />
        </div>
      </div>
      {device.networkDnsError ? (
        <p role="alert" className="text-sm leading-relaxed text-destructive text-pretty">
          {t("DNS ayarları uygulanamadı: {error}", { error: ts(device.networkDnsError) })}
        </p>
      ) : null}
    </div>
  )
}
