"use client"

import { useState } from "react"
import useSWR from "swr"
import { toast } from "sonner"
import { Gauge, HardDrive, Power } from "lucide-react"

import { Writable } from "@/components/app/read-only"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Spinner } from "@/components/ui/spinner"
import { ApiError, errorMessage, fetcher, post } from "@/lib/api"
import { formatDateTime, formatNumber } from "@/lib/format"
import { useI18n } from "@/lib/i18n/i18n"

import type { QualityPoint, SpeedResult } from "./types"

// Device detail cards for the device page (Panel-B places them; this file
// only exports them). Each card stays quiet when the desktop service does
// not offer the feature (HTTP 501).

function unavailable(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 501 || err.status === 404)
}

function mbps(n: number): string {
  return formatNumber(n, 1)
}

/** Hız testi (#763): one test at a time, against the device. */
export function SpeedTestCard({ device }: { device: string }) {
  const { t, ts } = useI18n()
  const key = `/api/g7/speedtest?target=${encodeURIComponent(device)}`
  const { data, error, mutate } = useSWR<{ results: SpeedResult[] }>(key, fetcher)
  const [busy, setBusy] = useState(false)
  if (unavailable(error)) return null
  const last = data?.results.at(-1)

  async function run() {
    setBusy(true)
    try {
      await post("/api/g7/speedtest", { target: device })
      await mutate()
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Gauge className="size-4" aria-hidden />
          {t("Hız testi")}
        </CardTitle>
        <CardDescription>{t("Tünel içinden bu cihaza ölçüm. Aynı anda tek test çalışır.")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {last ? (
          last.error ? (
            <p className="text-sm text-destructive">{ts(last.error)}</p>
          ) : (
            <p className="text-sm tabular-nums">
              {t("İndirme {down} Mbit/sn · Yükleme {up} Mbit/sn", { down: mbps(last.downloadMbps), up: mbps(last.uploadMbps) })}
              <span className="block text-muted-foreground">{formatDateTime(last.at)}</span>
            </p>
          )
        ) : (
          <p className="text-sm text-muted-foreground">{t("Henüz ölçüm yok.")}</p>
        )}
        <Writable>
          <Button size="sm" variant="outline" onClick={run} disabled={busy} className="self-start">
            {busy && <Spinner data-icon="inline-start" />}
            {busy ? t("Ölçülüyor") : t("Hız testi yap")}
          </Button>
        </Writable>
      </CardContent>
    </Card>
  )
}

/** Bağlantı kalitesi geçmişi (#764): 5 minute points of the last day or hourly points of 7 days. */
export function QualityHistoryCard({ device }: { device: string }) {
  const { t } = useI18n()
  const [coarse, setCoarse] = useState(false)
  const key = `/api/g7/monitor/quality?device=${encodeURIComponent(device)}&res=${coarse ? "1h" : "5m"}`
  const { data, error } = useSWR<{ points: QualityPoint[] }>(key, fetcher)
  if (unavailable(error)) return null
  const points = (data?.points ?? []).filter((p) => p.samples > 0)
  const maxRtt = Math.max(1, ...points.map((p) => p.avgRtt))
  const avgMs = points.length > 0 ? points.reduce((s, p) => s + p.avgRtt, 0) / points.length / 1e6 : 0
  const loss = points.length > 0 ? points.reduce((s, p) => s + p.lossPct, 0) / points.length : 0

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t("Bağlantı kalitesi")}</CardTitle>
        <CardDescription>{coarse ? t("Son 7 gün, saatlik ortalama") : t("Son gün, 5 dakikalık ortalama")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {points.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("Bu aralıkta ölçüm yok.")}</p>
        ) : (
          <>
            <p className="text-sm tabular-nums">
              {t("Ortalama gecikme {ms} ms · kayıp %{loss}", { ms: avgMs.toFixed(0), loss: loss.toFixed(1) })}
            </p>
            <div className="flex h-16 items-end gap-px" role="img" aria-label={t("Gecikme grafiği, {count} ölçüm", { count: points.length })}>
              {points.map((p) => (
                <div
                  key={p.at}
                  title={t("{at}: {ms} ms, kayıp %{loss}", { at: formatDateTime(p.at), ms: (p.avgRtt / 1e6).toFixed(0), loss: p.lossPct.toFixed(1) })}
                  className={p.lossPct > 2 ? "flex-1 bg-destructive/70" : "flex-1 bg-primary/60"}
                  style={{ height: `${Math.max(4, (p.avgRtt / maxRtt) * 100)}%` }}
                />
              ))}
            </div>
          </>
        )}
        <Button size="sm" variant="ghost" className="self-start" onClick={() => setCoarse((c) => !c)}>
          {coarse ? t("Son günü göster") : t("Son 7 günü göster")}
        </Button>
      </CardContent>
    </Card>
  )
}

/** Uyandırma (#749): Wake-on-LAN through an online device of the same network. */
export function WakeOnLanCard({ device }: { device: string }) {
  const { t } = useI18n()
  const [busy, setBusy] = useState(false)
  async function wake() {
    setBusy(true)
    try {
      await post("/api/g7/wake", { device })
      toast.success(t("{device} için uyandırma paketi gönderildi.", { device }))
    } catch (err) {
      toast.error(unavailable(err) ? t("Uyandırma bu sürümde masaüstü servisine bağlı değil.") : errorMessage(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Power className="size-4" aria-hidden />
          {t("Uyandır")}
        </CardTitle>
        <CardDescription>{t("Paket önce bu bilgisayardan, olmazsa aynı yerel ağdaki çevrimiçi bir cihazdan gönderilir.")}</CardDescription>
      </CardHeader>
      <CardContent>
        <Writable>
          <Button size="sm" variant="outline" onClick={wake} disabled={busy}>
            {t("Uyandırma paketi gönder")}
          </Button>
        </Writable>
      </CardContent>
    </Card>
  )
}

/** Ağ sürücüsü (#748): maps the device's SMB share; the password stays in the OS credential store. */
export function NetworkDriveCard({ name }: { name: string }) {
  const { t } = useI18n()
  const [busy, setBusy] = useState(false)
  async function run(unmap: boolean) {
    setBusy(true)
    try {
      await post("/api/g7/drives/map", { name, unmap })
      toast.success(unmap ? t("Ağ sürücüsü ayrıldı.") : t("Ağ sürücüsü bağlandı."))
    } catch (err) {
      toast.error(unavailable(err) ? t("Ağ sürücüsü bu sürümde masaüstü servisine bağlı değil.") : errorMessage(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <HardDrive className="size-4" aria-hidden />
          {t("Ağ sürücüsü")}
        </CardTitle>
        <CardDescription>{t("Paylaşım tünel adresinden bağlanır. Parola OpenScale'e gelmez, işletim sisteminin kasasında kalır.")}</CardDescription>
      </CardHeader>
      <CardContent className="flex gap-2">
        <Writable>
          <Button size="sm" variant="outline" onClick={() => run(false)} disabled={busy}>
            {t("Bağla")}
          </Button>
          <Button size="sm" variant="ghost" onClick={() => run(true)} disabled={busy}>
            {t("Ayır")}
          </Button>
        </Writable>
      </CardContent>
    </Card>
  )
}
