"use client"

import { Fragment, useState } from "react"
import useSWR from "swr"
import { Radar, Square } from "lucide-react"
import { toast } from "sonner"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { errorMessage, fetcher, post } from "@/lib/api"
import { formatAgo, formatDateTime } from "@/lib/format"
import { useI18n } from "@/lib/i18n/i18n"
import type { NearbyRequest, NearbyStatus } from "@/lib/p02-types"

// Nearby pairing (#358, ADR-0156): the panel listens on the local network
// for five minutes; a new device announces its enrollment request with
// "openscale nearby announce". The short code is never shown here: the
// owner reads it from the new device's screen and types it.

const KEY = "/api/p02/nearby"

export function NearbyRequests({ onPick, picking }: { onPick: (r: NearbyRequest) => void; picking: string | null }) {
  const { t } = useI18n()
  const { data, error, mutate } = useSWR<NearbyStatus>(KEY, fetcher, {
    refreshInterval: (d) => (d?.listening ? 2_500 : 0),
  })
  const [busy, setBusy] = useState(false)

  async function listen(on: boolean) {
    setBusy(true)
    try {
      await post(`${KEY}/listen`, { on })
      await mutate()
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const requests = data?.requests ?? []
  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
        {t("Yeni cihazda {command} çalıştır. Aynı ağdaki istekler burada görünür. Listede adı olan herkes istek gönderebilir; yalnızca yeni cihazın ekranındaki kodu yazarak onayla.")
          .split(/(\{command\})/)
          .map((part, i) =>
            part === "{command}" ? (
              <code key={i} className="font-mono text-[0.8125rem] text-foreground">
                openscale nearby announce
              </code>
            ) : (
              <Fragment key={i}>{part}</Fragment>
            )
          )}
      </p>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{errorMessage(error)}</AlertDescription>
        </Alert>
      ) : null}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border px-4 py-3">
        <span className="flex items-center gap-2 text-sm">
          <span
            aria-hidden="true"
            className={data?.listening ? "size-2 shrink-0 rounded-full bg-success" : "size-2 shrink-0 rounded-full bg-muted-foreground/50"}
          />
          {data?.listening && data.until
            ? t("Dinleniyor; {time} saatinde kendiliğinden kapanır", { time: formatDateTime(data.until) })
            : t("Dinlemiyor")}
        </span>
        {data?.listening ? (
          <Button type="button" variant="outline" size="sm" onClick={() => listen(false)} disabled={busy}>
            {busy ? <Spinner data-icon="inline-start" /> : <Square data-icon="inline-start" />}
            {t("Dinlemeyi durdur")}
          </Button>
        ) : (
          <Button type="button" size="sm" onClick={() => listen(true)} disabled={busy || !data}>
            {busy ? <Spinner data-icon="inline-start" /> : <Radar data-icon="inline-start" />}
            {t("Yerel ağı 5 dakika dinle")}
          </Button>
        )}
      </div>
      {requests.length > 0 ? (
        <ul className="flex flex-col divide-y rounded-lg border" aria-live="polite">
          {requests.map((r) => (
            <li key={r.deviceId} className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
              <span className="flex min-w-0 flex-col gap-0.5">
                <span className="font-medium">{r.hostname || t("Adsız cihaz")}</span>
                <span className="text-sm text-muted-foreground">
                  <span className="font-mono text-[0.8125rem]">{r.from}</span> · {formatAgo(r.lastSeen)}
                </span>
              </span>
              <Button type="button" variant="outline" size="sm" onClick={() => onPick(r)} disabled={picking !== null}>
                {picking === r.deviceId ? <Spinner data-icon="inline-start" /> : null}
                {t("Bu cihazı ekle")}
              </Button>
            </li>
          ))}
        </ul>
      ) : data?.listening ? (
        <p className="rounded-lg border px-4 py-6 text-center text-sm text-muted-foreground" aria-live="polite">
          {t("Henüz istek yok. Yeni cihazda komutu çalıştırdıysan birkaç saniye bekle.")}
        </p>
      ) : null}
      <p className="text-sm text-muted-foreground text-pretty">
        {t("İlk kullanımda Windows güvenlik duvarı izin isteyebilir; yalnızca özel ağlarda izin ver.")}
      </p>
    </div>
  )
}
