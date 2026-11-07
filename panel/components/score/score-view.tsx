"use client"

import Link from "next/link"
import useSWR from "swr"
import { CircleAlert, CircleCheck, CircleMinus, CircleX, RefreshCw } from "lucide-react"

import { DetailSection } from "@/components/devices/detail-card"
import { checkTexts, checkVars } from "@/components/score/check-texts"
import { PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { RowList } from "@/components/settings/list-table"
import { SettingBadge, SettingsColumn } from "@/components/settings/settings-layout"
import { Button } from "@/components/ui/button"
import { fetcher } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { CheckStatus, ScoreCheck, ScoreReport } from "@/lib/p16-types"
import { cn } from "@/lib/utils"

const gradeLabels: Record<ScoreReport["grade"], string> = {
  excellent: msg("Çok iyi"),
  good: msg("İyi"),
  fair: msg("Orta"),
  weak: msg("Zayıf"),
}

const statusOrder: CheckStatus[] = ["fail", "warn", "pass", "skip"]

const statusMeta: Record<CheckStatus, { label: string; icon: typeof CircleCheck; className: string }> = {
  fail: { label: msg("Düzeltilmeli"), icon: CircleX, className: "text-destructive" },
  warn: { label: msg("İyileştirilebilir"), icon: CircleAlert, className: "text-warning" },
  pass: { label: msg("Tamam"), icon: CircleCheck, className: "text-success" },
  skip: { label: msg("Uygulanmıyor"), icon: CircleMinus, className: "text-muted-foreground" },
}

export function ScoreView() {
  const { t } = useI18n()
  const { data, error, isLoading, isValidating, mutate } = useSWR<ScoreReport>("/api/security/score", fetcher)

  return (
    <SettingsColumn>
      <PageHeader
        title={t("Güvenlik puanı")}
        description={t("Ağının ayarlarından bu bilgisayarda hesaplanan puan ve öneriler; hiçbir veri dışarı çıkmaz.")}
        actions={
          <Button variant="outline" onClick={() => mutate()} disabled={isValidating}>
            <RefreshCw data-icon="inline-start" className={cn(isValidating && "animate-spin")} />
            {t("Yeniden denetle")}
          </Button>
        }
      />
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {data ? (
          <>
            <DetailSection
              id="toplam-puan"
              title={t("Toplam puan")}
              description={t("Son denetim: {time}", { time: formatDateTime(data.checkedAt) })}
              framed={false}
            >
              <div className="flex flex-col items-center gap-6 border-y py-6 sm:flex-row sm:gap-10">
                <Gauge score={data.score} label={t(gradeLabels[data.grade])} />
                <div className="flex w-full min-w-0 flex-col gap-4">
                  <ul className="flex flex-col divide-y text-sm">
                    {statusOrder.map((st) => {
                      const n = data.checks.filter((c) => c.status === st).length
                      const meta = statusMeta[st]
                      const Icon = meta.icon
                      return (
                        <li key={st} className="flex items-center justify-between gap-2 py-2">
                          <span className="flex items-center gap-2">
                            <Icon className={cn("size-4", meta.className)} aria-hidden="true" />
                            {t(meta.label)}
                          </span>
                          <span className="font-mono tabular-nums">{n}</span>
                        </li>
                      )
                    })}
                  </ul>
                  {!data.local ? (
                    <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
                      {t("Bu panel komut satırından açıldı: kill switch, RDP/SSH ve açık port denetimleri yalnızca masaüstü uygulamasında yapılır ve puana katılmadı.")}
                    </p>
                  ) : null}
                </div>
              </div>
            </DetailSection>
            {statusOrder.map((st) => {
              const checks = data.checks.filter((c) => c.status === st && checkTexts[c.id])
              if (checks.length === 0) return null
              return (
                <DetailSection key={st} id={`puan-${st}`} title={t(statusMeta[st].label)} framed={false}>
                  <RowList label={t(statusMeta[st].label)}>
                    {checks.map((c) => (
                      <CheckItem key={c.id} check={c} />
                    ))}
                  </RowList>
                </DetailSection>
              )
            })}
          </>
        ) : null}
      </QueryState>
    </SettingsColumn>
  )
}

function CheckItem({ check }: { check: ScoreCheck }) {
  const { t } = useI18n()
  const text = checkTexts[check.id]
  const meta = statusMeta[check.status]
  const Icon = meta.icon
  if (!text) return null
  const body =
    check.status === "pass" ? text.ok : check.status === "skip" ? (text.skip ?? msg("Bu denetim burada uygulanmıyor.")) : text.advice
  return (
    <li className="flex flex-col gap-3 py-4 sm:flex-row sm:items-center sm:justify-between sm:gap-8">
      <div className="flex min-w-0 gap-3">
        <Icon className={cn("mt-0.5 size-4 shrink-0", meta.className)} aria-hidden="true" />
        <div className="flex min-w-0 flex-col gap-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-medium">{t(text.title)}</h3>
            <SettingBadge>
              <span className="sr-only">{t(meta.label)}, </span>
              {t("ağırlık")} {check.weight}
            </SettingBadge>
          </div>
          <p className="text-sm leading-relaxed text-muted-foreground text-pretty">{t(body, checkVars(check))}</p>
        </div>
      </div>
      {(check.status === "fail" || check.status === "warn") && text.href && text.action ? (
        <Button variant="outline" className="ml-7 shrink-0 self-start sm:ml-0 sm:self-auto" nativeButton={false} render={<Link href={text.href} />}>
          {t(text.action)}
        </Button>
      ) : null}
    </li>
  )
}

/** Circular score meter; the number is the accessible value. */
function Gauge({ score, label }: { score: number; label: string }) {
  const { t } = useI18n()
  const r = 52
  const c = 2 * Math.PI * r
  const tone = score >= 90 ? "stroke-success" : score >= 70 ? "stroke-foreground" : score >= 50 ? "stroke-warning" : "stroke-destructive"
  return (
    <div
      className="relative flex size-36 shrink-0 items-center justify-center"
      role="meter"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={score}
      aria-valuetext={t("{score} / 100, {grade}", { score, grade: label })}
      aria-label={t("Güvenlik puanı")}
    >
      <svg viewBox="0 0 120 120" className="absolute inset-0 -rotate-90" aria-hidden="true">
        <circle cx="60" cy="60" r={r} className="fill-none stroke-muted" strokeWidth="10" />
        <circle
          cx="60"
          cy="60"
          r={r}
          className={cn("fill-none transition-[stroke-dashoffset]", tone)}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - score / 100)}
        />
      </svg>
      <div className="flex flex-col items-center" aria-hidden="true">
        <span className="text-4xl font-semibold tabular-nums">{score}</span>
        <span className="text-sm text-muted-foreground">{label}</span>
      </div>
    </div>
  )
}
