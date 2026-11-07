"use client"

import useSWR from "swr"
import { History } from "lucide-react"

import { useAppStatus } from "@/components/app/use-app-status"
import { QueryState } from "@/components/query-state"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { HistoryPeer, HistoryReply, HistorySample } from "@/lib/p16-types"

// Connection history (#190): the last 24 hours of how this computer reached
// each peer and the measured round-trip times. The samples live only in the
// service's memory on this computer.

const DAY_MS = 24 * 60 * 60 * 1000
const VIEW_W = 1000

const pathClass: Record<HistorySample["path"], string> = {
  direct: "fill-success",
  relay: "fill-warning",
  none: "fill-muted",
}

interface Segment {
  from: number
  to: number
  path: HistorySample["path"]
}

function segments(samples: HistorySample[], intervalMs: number, nowMs: number): Segment[] {
  const out: Segment[] = []
  samples.forEach((s, i) => {
    const from = new Date(s.at).getTime()
    const next = samples[i + 1] ? new Date(samples[i + 1].at).getTime() : Math.min(from + intervalMs, nowMs)
    // A gap longer than two intervals means the service was not sampling.
    const to = Math.min(next, from + 2 * intervalMs)
    const last = out[out.length - 1]
    if (last && last.path === s.path && last.to >= from - 1000) {
      last.to = to
    } else {
      out.push({ from, to, path: s.path })
    }
  })
  return out
}

function share(samples: HistorySample[], path: HistorySample["path"]): number {
  if (samples.length === 0) return 0
  return Math.round((100 * samples.filter((s) => s.path === path).length) / samples.length)
}

export function ConnectionHistoryCard() {
  const { t } = useI18n()
  const app = useAppStatus(30_000)
  const { data, error, isLoading, mutate } = useSWR<HistoryReply>(app.isApp ? "/api/app/diag/history" : null, fetcher, {
    refreshInterval: 60_000,
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <History className="size-4" aria-hidden="true" />
          {t("Bağlantı geçmişi (son 24 saat)")}
        </CardTitle>
        <CardDescription className="text-pretty">
          {t("Bu bilgisayarın her cihaza nasıl ulaştığı ve ölçülen gecikme, dakikada bir. Veriler yalnızca bu bilgisayarın belleğinde tutulur ve hiçbir yere gönderilmez; servis yeniden başlayınca sıfırlanır.")}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {!app.isApp ? (
          <Empty className="border">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <History />
              </EmptyMedia>
              <EmptyTitle>{t("Yalnızca masaüstü uygulamasında")}</EmptyTitle>
              <EmptyDescription>
                {t("Komut satırından açılan panel tünel çalıştırmaz, bu yüzden bağlantı geçmişi yoktur. 'openscale app' ile açılan panelde görünür.")}
              </EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
            {data ? (
              data.peers.length === 0 ? (
                <p className="text-sm text-muted-foreground">{t("Henüz örnek yok; ilk ölçüm bir dakika içinde gelir.")}</p>
              ) : (
                <div className="flex flex-col gap-6">
                  <ul className="flex flex-col gap-6">
                    {data.peers.slice(0, 32).map((p) => (
                      <PeerRow key={p.name} peer={p} intervalMs={data.intervalSec * 1000} nowIso={data.now} />
                    ))}
                  </ul>
                  <div className="flex flex-wrap gap-4 text-sm text-muted-foreground" aria-hidden="true">
                    <LegendSwatch className="bg-success" label={t("Doğrudan")} />
                    <LegendSwatch className="bg-warning" label={t("Aktarıcı")} />
                    <LegendSwatch className="bg-muted" label={t("El sıkışma yok")} />
                    <span className="flex items-center gap-1.5">
                      <span className="inline-block h-3 w-0.5 bg-foreground" />
                      {t("Yol değişimi")}
                    </span>
                    <span className="flex items-center gap-1.5">
                      <span className="inline-block h-0.5 w-4 bg-foreground/70" />
                      {t("Gecikme")}
                    </span>
                  </div>
                </div>
              )
            ) : null}
          </QueryState>
        )}
      </CardContent>
    </Card>
  )
}

function LegendSwatch({ className, label }: { className: string; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className={`inline-block size-3 rounded-sm ${className}`} />
      {label}
    </span>
  )
}

function PeerRow({ peer, intervalMs, nowIso }: { peer: HistoryPeer; intervalMs: number; nowIso: string }) {
  const { t } = useI18n()
  const nowMs = new Date(nowIso).getTime()
  const startMs = nowMs - DAY_MS
  const x = (ms: number) => Math.max(0, Math.min(VIEW_W, ((ms - startMs) / DAY_MS) * VIEW_W))
  const segs = segments(peer.samples, intervalMs, nowMs)
  const rtts = peer.samples.filter((s) => s.rttMs !== undefined && s.rttMs > 0)
  const maxRtt = Math.max(1, ...rtts.map((s) => s.rttMs ?? 0))
  const points = rtts.map((s) => `${x(new Date(s.at).getTime()).toFixed(1)},${(46 - ((s.rttMs ?? 0) / maxRtt) * 22).toFixed(1)}`).join(" ")
  const lastRtt = rtts.length > 0 ? rtts[rtts.length - 1].rttMs : undefined
  const summary = t("Doğrudan %{direct}, aktarıcı %{relay}, el sıkışma yok %{none}; {changes} yol değişimi", {
    direct: share(peer.samples, "direct"),
    relay: share(peer.samples, "relay"),
    none: share(peer.samples, "none"),
    changes: peer.changes.length,
  })

  return (
    <li className="flex flex-col gap-2">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <span className="font-medium">{peer.name}</span>
        <span className="text-sm text-muted-foreground">
          {summary}
          {lastRtt !== undefined ? ` · ${t("son gecikme {ms} ms", { ms: lastRtt.toFixed(1) })}` : ""}
          {rtts.length > 0 ? ` · ${t("en yüksek {ms} ms", { ms: maxRtt.toFixed(1) })}` : ""}
        </span>
      </div>
      <svg viewBox={`0 0 ${VIEW_W} 50`} preserveAspectRatio="none" className="h-12 w-full rounded-md bg-muted/40" aria-hidden="true">
        {segs.map((s) => (
          <rect key={s.from} x={x(s.from)} y={6} width={Math.max(1, x(s.to) - x(s.from))} height={14} className={pathClass[s.path]} />
        ))}
        {peer.changes.map((c) => (
          <rect key={`${c.at}-${c.endpoint}`} x={x(new Date(c.at).getTime()) - 1} y={2} width={2} height={22} className="fill-foreground" />
        ))}
        {rtts.length > 1 ? (
          <polyline points={points} className="fill-none stroke-foreground/70" strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
        ) : null}
      </svg>
      <div className="flex justify-between text-[11px] text-muted-foreground" aria-hidden="true">
        <span>{t("24 sa önce")}</span>
        <span>{t("12 sa önce")}</span>
        <span>{t("şimdi")}</span>
      </div>
    </li>
  )
}
