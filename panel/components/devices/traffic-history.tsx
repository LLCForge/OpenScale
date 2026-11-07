"use client"

import { useState } from "react"
import useSWR from "swr"

import { useAppStatus } from "@/components/app/use-app-status"
import { DetailSection, withNodes } from "@/components/devices/detail-card"
import { SegmentedRadio } from "@/components/devices/segmented-radio"
import { EmptyNote } from "@/components/settings/settings-layout"
import { Skeleton } from "@/components/ui/skeleton"
import { ApiError, fetcher } from "@/lib/api"
import { dateFormat, formatBytes } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { TrafficHistory, TrafficPoint } from "@/lib/p12-types"

// Per-device traffic history (#505): the bytes this computer exchanged with
// one device, hour by hour, kept on this computer for 30 days. Only totals
// are kept; no address, port or site.

type Range = "24" | "168" | "720"

const ranges: { value: Range; label: string }[] = [
  { value: "24", label: msg("24 saat") },
  { value: "168", label: msg("7 gün") },
  { value: "720", label: msg("30 gün") },
]

const VIEW_W = 1000
const VIEW_H = 120

/** Formatters in the interface language; call during render. */
function hourFormat(): Intl.DateTimeFormat {
  return dateFormat("traffic-hour", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })
}

function dayFormat(): Intl.DateTimeFormat {
  return dateFormat("traffic-day", { day: "numeric", month: "short" })
}

/** 30 days of hourly points drawn as one bar per day. */
function byDay(points: TrafficPoint[]): TrafficPoint[] {
  const days = new Map<string, TrafficPoint>()
  for (const p of points) {
    const d = new Date(p.hour)
    const key = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`
    const cur = days.get(key)
    if (cur) {
      cur.rx += p.rx
      cur.tx += p.tx
    } else {
      days.set(key, { hour: new Date(d.getFullYear(), d.getMonth(), d.getDate()).toISOString(), rx: p.rx, tx: p.tx })
    }
  }
  return [...days.values()]
}

export function TrafficHistorySection({ device }: { device: string }) {
  const { t } = useI18n()
  const { isApp } = useAppStatus(30_000)
  const [range, setRange] = useState<Range>("24")
  const key = isApp ? `/api/app/diag/traffic-history?device=${encodeURIComponent(device)}&hours=${range}` : null
  const { data, error } = useSWR<TrafficHistory>(key, fetcher, {
    refreshInterval: 300_000,
    shouldRetryOnError: (err: unknown) => !(err instanceof ApiError && err.status === 404),
  })

  // The command line panel and older services have no history: no section.
  if (!isApp || (error instanceof ApiError && error.status === 404)) return null

  const points = data?.points ?? []
  const bars = range === "720" ? byDay(points) : points
  const totalRx = points.reduce((n, p) => n + p.rx, 0)
  const totalTx = points.reduce((n, p) => n + p.tx, 0)
  const busiest = bars.reduce<TrafficPoint | null>((best, p) => (!best || p.rx + p.tx > best.rx + best.tx ? p : best), null)
  const label = range === "720" ? dayFormat() : hourFormat()
  const options = ranges.map((r) => ({ value: r.value, label: t(r.label) }))

  return (
    <DetailSection
      id="trafik"
      title={t("Trafik geçmişi")}
      description={t(
        "Yalnızca bu bilgisayarın bu cihazla değiştirdiği toplam bayt saat saat tutulur; hangi siteye veya porta gidildiği tutulmaz. Veri 30 gün sonra silinir ve bu bilgisayardan çıkmaz.",
      )}
      framed={false}
      action={<SegmentedRadio label={t("Süre")} value={range} options={options} onChange={setRange} />}
    >
      {error ? (
        <EmptyNote>{t("Trafik geçmişi okunamadı.")}</EmptyNote>
      ) : !data ? (
        <Skeleton className="h-40 w-full" />
      ) : totalRx + totalTx === 0 ? (
        <EmptyNote>{t("Henüz trafik geçmişi yok. Servis çalıştıkça saatlik toplamlar birikir.")}</EmptyNote>
      ) : (
        <div className="flex flex-col gap-3 rounded-lg border p-4">
          <p className="text-sm text-pretty">
            {withNodes(t("{rx} alındı, {tx} gönderildi"), {
              rx: <span className="font-medium tabular-nums">{formatBytes(totalRx)}</span>,
              tx: <span className="font-medium tabular-nums">{formatBytes(totalTx)}</span>,
            })}
            {busiest && busiest.rx + busiest.tx > 0 ? (
              <span className="text-muted-foreground">
                {" "}
                ·{" "}
                {range === "720"
                  ? t("en yoğun gün {date} ({size})", { date: label.format(new Date(busiest.hour)), size: formatBytes(busiest.rx + busiest.tx) })
                  : t("en yoğun saat {date} ({size})", { date: label.format(new Date(busiest.hour)), size: formatBytes(busiest.rx + busiest.tx) })}
              </span>
            ) : null}
          </p>
          <TrafficBars bars={bars} format={label} />
          <div className="flex flex-wrap items-center justify-between gap-2 text-sm text-muted-foreground">
            <span className="flex gap-4" aria-hidden="true">
              <span className="flex items-center gap-1.5">
                <span className="inline-block size-3 rounded-sm bg-foreground/80" />
                {t("Alınan")}
              </span>
              <span className="flex items-center gap-1.5">
                <span className="inline-block size-3 rounded-sm bg-foreground/30" />
                {t("Gönderilen")}
              </span>
            </span>
            {bars.length > 0 ? (
              <span className="tabular-nums" aria-hidden="true">
                {label.format(new Date(bars[0].hour))} – {label.format(new Date(bars[bars.length - 1].hour))}
              </span>
            ) : null}
          </div>
        </div>
      )}
    </DetailSection>
  )
}

function TrafficBars({ bars, format }: { bars: TrafficPoint[]; format: Intl.DateTimeFormat }) {
  const { t } = useI18n()
  const max = Math.max(1, ...bars.map((b) => b.rx + b.tx))
  const slot = VIEW_W / Math.max(1, bars.length)
  const gap = slot > 6 ? 2 : 0
  const h = (n: number) => (n / max) * (VIEW_H - 4)
  return (
    <div className="flex gap-2">
      <div className="flex w-14 shrink-0 flex-col justify-between text-right text-sm text-muted-foreground tabular-nums" aria-hidden="true">
        <span>{formatBytes(max)}</span>
        <span>0</span>
      </div>
      <svg viewBox={`0 0 ${VIEW_W} ${VIEW_H}`} preserveAspectRatio="none" className="h-32 min-w-0 flex-1 rounded-md bg-muted/40" aria-hidden="true">
        {bars.map((b, i) => {
          const rx = h(b.rx)
          const tx = h(b.tx)
          const x = i * slot + gap / 2
          const w = Math.max(1, slot - gap)
          return (
            <g key={b.hour}>
              <title>
                {t("{time}: {rx} alındı, {tx} gönderildi", {
                  time: format.format(new Date(b.hour)),
                  rx: formatBytes(b.rx),
                  tx: formatBytes(b.tx),
                })}
              </title>
              <rect x={x} y={VIEW_H - rx} width={w} height={rx} className="fill-foreground/80" />
              <rect x={x} y={VIEW_H - rx - tx} width={w} height={tx} className="fill-foreground/30" />
            </g>
          )
        })}
      </svg>
    </div>
  )
}
