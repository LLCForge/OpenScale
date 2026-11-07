"use client"

import { useState } from "react"
import useSWR from "swr"
import { toast } from "sonner"
import { LifeBuoy, ShieldAlert } from "lucide-react"

import { useAppStatus } from "@/components/app/use-app-status"
import { useReadOnly } from "@/components/app/read-only"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { errorMessage, fetcher, post } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { useI18n } from "@/lib/i18n/i18n"
import type { SupportLocalView } from "@/lib/support-types"

/**
 * This device's side of the support toolbox (#852, ADR-0232): a request
 * waits here for the person at the device, and while a session lasts a red
 * "remotely connected" bar with a disconnect button stays on every page.
 */
export function SupportLocalBanner() {
  const { t } = useI18n()
  const { isApp } = useAppStatus()
  const readOnly = useReadOnly()
  const { data, mutate } = useSWR<SupportLocalView>(isApp ? "/api/app/support/local" : null, fetcher, {
    refreshInterval: 2_000,
    shouldRetryOnError: false,
  })
  const [busy, setBusy] = useState(false)
  if (!data || (data.pending.length === 0 && data.sessions.length === 0)) return null

  async function decide(id: string, accept: boolean) {
    setBusy(true)
    try {
      await post("/api/app/support/local/decide", { id, accept })
      await mutate()
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  async function endAll() {
    setBusy(true)
    try {
      await post("/api/app/support/local/end", {})
      toast.success(t("Uzaktan destek kesildi."))
      await mutate()
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-col gap-2" aria-live="assertive">
      {data.pending.map((p) => (
        <Alert key={p.id}>
          <LifeBuoy />
          <AlertTitle>
            {p.kill
              ? t("{peer} bu cihazda bir süreci sonlandırmak istiyor", { peer: p.peer })
              : t("{peer} bu cihaza uzaktan destek vermek istiyor", { peer: p.peer })}
          </AlertTitle>
          <AlertDescription className="flex flex-col gap-3">
            <span className="text-pretty">
              {p.kill
                ? t("İzin verirsen {peer} seçtiği bir süreci kapatabilir; kritik sistem süreçleri korunur.", { peer: p.peer })
                : t("İzin verirsen {peer} çalışan işlemleri, hizmetleri, son sistem olaylarını, disk doluluğunu ve açılış programlarını salt okunur görür. Kişisel bilgiler maskelenir.", { peer: p.peer })}
            </span>
            {readOnly ? null : (
              <span className="flex flex-wrap gap-2">
                <Button size="sm" disabled={busy} onClick={() => void decide(p.id, true)}>
                  {t("İzin ver")}
                </Button>
                <Button size="sm" variant="outline" disabled={busy} onClick={() => void decide(p.id, false)}>
                  {t("Reddet")}
                </Button>
              </span>
            )}
          </AlertDescription>
        </Alert>
      ))}
      {data.sessions.length > 0 ? (
        <Alert variant="destructive">
          <ShieldAlert />
          <AlertTitle>
            {t("Uzaktan destek bağlı: {peers}", { peers: data.sessions.map((s) => s.peer).join(", ") })}
          </AlertTitle>
          <AlertDescription className="flex flex-col gap-3">
            <span className="text-pretty">
              {data.sessions.map((s) =>
                s.kill
                  ? t("{peer}: {time} saatinden beri, süreç sonlandırma dahil", { peer: s.peer, time: formatDateTime(s.started) })
                  : t("{peer}: {time} saatinden beri, salt okunur", { peer: s.peer, time: formatDateTime(s.started) }),
              ).join(" · ")}
            </span>
            {readOnly ? null : (
              <span>
                <Button size="sm" variant="destructive" disabled={busy} onClick={() => void endAll()}>
                  {t("Desteği kes")}
                </Button>
              </span>
            )}
          </AlertDescription>
        </Alert>
      ) : null}
    </div>
  )
}
