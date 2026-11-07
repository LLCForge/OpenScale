"use client"

import useSWR from "swr"

import { DetailSection } from "@/components/devices/detail-card"
import { DiagSectionState } from "@/components/diag/diag-errors"
import { EmptyNote } from "@/components/settings/settings-layout"
import { useHash, useScrollToHash } from "@/components/settings/use-hash"
import { ApiError, fetcher } from "@/lib/api"
import { formatBytes, formatNumber } from "@/lib/format"
import { useI18n } from "@/lib/i18n/i18n"
import type { ResourceSample, ResourceUsage } from "@/lib/p12-types"

// OpenScale's own resource use (#516): CPU and memory of the service over
// the last 24 hours, sampled every five minutes, and the CPU time spent on
// battery. Battery drain itself cannot be measured.

const VIEW_W = 1000
const VIEW_H = 60
const DAY_MS = 24 * 60 * 60 * 1000

/** One decimal place in the interface language. */
function percent(n: number): string {
  return formatNumber(n, 1)
}

export function ResourcesCard() {
  const { t } = useI18n()
  const { data, error, isLoading } = useSWR<ResourceUsage>("/api/app/diag/resources", fetcher, {
    refreshInterval: 300_000,
    shouldRetryOnError: (err: unknown) => !(err instanceof ApiError && err.status === 404),
  })
  const hash = useHash()
  useScrollToHash(hash === "tuketim" ? hash : "", data !== undefined)
  // An older service keeps no history: no section, and no page-level error.
  if (error instanceof ApiError && error.status === 404) return null

  const s = data?.summary
  return (
    <DetailSection
      id="tuketim"
      title={t("OpenScale'in tüketimi")}
      description={t("Servisin son 24 saatteki işlemci ve bellek kullanımı, beş dakikada bir ölçülür. Veriler yalnızca bu bilgisayarda tutulur.")}
      framed={false}
    >
      <DiagSectionState section={t("OpenScale'in tüketimi")} error={error} isLoading={isLoading}>
        {!data || !s || data.samples.length === 0 ? (
          <EmptyNote>{t("Henüz ölçüm yok; ilk örnek beş dakika içinde gelir.")}</EmptyNote>
        ) : (
          <div className="grid gap-4 rounded-lg border p-4 md:grid-cols-2 md:gap-6 md:p-6">
            <Series
              title={t("İşlemci")}
              summary={
                s.cpuTimeKnown
                  ? t("Ortalama %{avg}, en yüksek %{max} (bir çekirdeğin yüzdesi)", { avg: percent(s.avgCpuPercent), max: percent(s.maxCpuPercent) })
                  : t("Bu sistemde işlem süresi okunamıyor.")
              }
              samples={data.samples}
              value={(x) => x.cpuPercent}
              max={Math.max(1, s.maxCpuPercent)}
              topLabel={t("%{value}", { value: percent(Math.max(1, s.maxCpuPercent)) })}
            />
            <Series
              title={t("Bellek")}
              summary={t("En çok {max}; sistemden alınan {sys}", { max: formatBytes(s.maxHeapBytes), sys: formatBytes(s.lastSysBytes) })}
              samples={data.samples}
              value={(x) => x.heapBytes}
              max={Math.max(1, s.maxHeapBytes)}
              topLabel={formatBytes(s.maxHeapBytes)}
            />
            <p className="text-sm text-muted-foreground text-pretty md:col-span-2">
              {s.batteryShare === undefined
                ? t("Bu bilgisayarda pil bulunamadı.")
                : t("Pildeyken harcanan işlemci süresi: {seconds} sn; ölçümlerin %{share} kadarı pildeyken.", {
                    seconds: percent(s.cpuSecondsOnBattery),
                    share: percent(s.batteryShare * 100),
                  })}
            </p>
          </div>
        )}
      </DiagSectionState>
    </DetailSection>
  )
}

interface SeriesProps {
  title: string
  summary: string
  samples: ResourceSample[]
  value: (s: ResourceSample) => number
  max: number
  topLabel: string
}

function Series({ title, summary, samples, value, max, topLabel }: SeriesProps) {
  const { t } = useI18n()
  const end = new Date(samples[samples.length - 1].at).getTime()
  const start = end - DAY_MS
  const x = (iso: string) => Math.max(0, ((new Date(iso).getTime() - start) / DAY_MS) * VIEW_W)
  const y = (v: number) => VIEW_H - 2 - (v / max) * (VIEW_H - 4)
  const points = samples.map((s) => `${x(s.at).toFixed(1)},${y(value(s)).toFixed(1)}`).join(" ")
  return (
    <figure className="flex min-w-0 flex-col gap-2">
      <figcaption className="flex flex-col gap-0.5">
        <span className="text-sm font-medium">{title}</span>
        <span className="text-sm text-muted-foreground text-pretty">{summary}</span>
      </figcaption>
      <div className="flex gap-2">
        <div className="flex w-14 shrink-0 flex-col justify-between text-right text-sm text-muted-foreground tabular-nums" aria-hidden="true">
          <span>{topLabel}</span>
          <span>0</span>
        </div>
        <svg viewBox={`0 0 ${VIEW_W} ${VIEW_H}`} preserveAspectRatio="none" className="h-20 min-w-0 flex-1 rounded-md bg-muted/40" aria-hidden="true">
          {samples.length > 1 ? (
            <polyline points={points} className="fill-none stroke-foreground/80" strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
          ) : (
            <circle cx={x(samples[0].at)} cy={y(value(samples[0]))} r={3} className="fill-foreground" />
          )}
        </svg>
      </div>
      <div className="flex justify-between pl-16 text-sm text-muted-foreground" aria-hidden="true">
        <span>{t("24 sa önce")}</span>
        <span>{t("şimdi")}</span>
      </div>
    </figure>
  )
}
