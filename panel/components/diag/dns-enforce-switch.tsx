"use client"

import { useState } from "react"
import useSWR from "swr"
import { toast } from "sonner"

import { useReadOnly } from "@/components/app/read-only"
import { SettingBadge } from "@/components/settings/settings-layout"
import { Field, FieldContent, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Switch } from "@/components/ui/switch"
import { errorMessage, fetcher, post } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"

/** Reply of /api/app/dns-enforce (#717, ADR-0224). */
interface DnsEnforceStatus {
  supported: boolean
  on: boolean
  active: boolean
  reason?: string
  error?: string
  dohList?: string
  dohRanges: number
}

/**
 * The owner's switch for DNS enforcement: while an exit node is used, DNS
 * outside the tunnel and the owner's DoH endpoints are blocked by the
 * operating system's firewall. It saves at once, without the form's
 * "Kaydet", because the tunnel does not restart for it.
 */
export function DnsEnforceSwitch() {
  const { data, mutate } = useSWR<DnsEnforceStatus>("/api/app/dns-enforce", fetcher, { refreshInterval: 10000 })
  const readOnly = useReadOnly()
  const { t, ts } = useI18n()
  const [busy, setBusy] = useState(false)
  if (!data) return null

  async function toggle(on: boolean) {
    setBusy(true)
    try {
      await mutate(await post<DnsEnforceStatus>("/api/app/dns-enforce", { on }), { revalidate: true })
      toast.success(on ? t("DNS zorlama açıldı.") : t("DNS zorlama kapatıldı; kurallar kaldırılıyor."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const state = data.active ? t("Uygulanıyor") : data.on ? t("Bekliyor") : t("Kapalı")
  const detail = data.error
    ? ts(data.error)
    : data.active
      ? data.dohRanges > 0
        ? t("Tünel dışı DNS ve listedeki {count} DoH adresi engelleniyor.", { count: data.dohRanges })
        : t("Tünel dışı DNS engelleniyor. DoH listesi tanımlı değil.")
      : data.reason
        ? ts(data.reason)
        : data.reason

  return (
    <Field orientation="horizontal">
      <FieldContent>
        <FieldLabel htmlFor="g-dns-enforce" className="flex flex-wrap items-center gap-2">
          {t("DNS yalnızca tünelden")}
          <SettingBadge tone={data.error ? "danger" : data.active ? "success" : "muted"}>{state}</SettingBadge>
        </FieldLabel>
        <FieldDescription className="text-pretty">
          {data.supported
            ? t("Çıkış düğümü kullanılırken tünel dışına giden DNS ve DoT trafiğini işletim sisteminin güvenlik duvarıyla keser. Tünel kapanınca kurallar kendiliğinden kalkar.")
            : t("Bu sistemde DNS zorlama yok.")}
          {detail ? <span className="mt-1 block">{detail}</span> : null}
        </FieldDescription>
      </FieldContent>
      <Switch
        id="g-dns-enforce"
        checked={data.on}
        disabled={readOnly || busy || !data.supported}
        onCheckedChange={(c) => void toggle(c)}
      />
    </Field>
  )
}
