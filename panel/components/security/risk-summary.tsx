"use client"

import { TriangleAlert } from "lucide-react"

import { msg, useI18n } from "@/lib/i18n/i18n"
import type { RiskLevel, RiskReport } from "@/lib/pa-types"
import { cn } from "@/lib/utils"

// Risk summary of a signed change (ADR-0177) and the personal data
// warnings of its diff (ADR-0177, #688). Both sit above the diff in the
// signing dialog; color carries only the level, as everywhere else.

// The keys are the server's risk level values; they are never shown.
const levelTone: { [K in RiskLevel]: string } = {
  "düşük": "bg-secondary text-muted-foreground", // i18n-ignore: sunucunun risk düzeyi değeri
  orta: "bg-warning/15 text-warning-foreground dark:text-warning",
  "yüksek": "bg-warning/25 text-warning-foreground dark:text-warning", // i18n-ignore: sunucunun risk düzeyi değeri
  kritik: "bg-destructive/10 text-destructive",
}

const fallbackTone = levelTone["düşük"] // i18n-ignore: sunucunun risk düzeyi değeri

const levelText: { [K in RiskLevel]: string } = {
  "düşük": msg("Düşük risk"), // i18n-ignore: anahtar sunucunun risk düzeyi değeri
  orta: msg("Orta risk"),
  "yüksek": msg("Yüksek risk"), // i18n-ignore: anahtar sunucunun risk düzeyi değeri
  kritik: msg("Kritik risk"),
}

export function RiskBadge({ level }: { level: RiskLevel }) {
  const { t } = useI18n()
  return (
    <span className={cn("inline-flex h-5 items-center rounded-full px-2 text-xs font-medium", levelTone[level] ?? fallbackTone)}>
      {levelText[level] ? t(levelText[level]) : level}
    </span>
  )
}

/** The scored summary: level, one line, then each item; widening items in red. */
export function RiskSummary({ risk }: { risk: RiskReport }) {
  const { t, ts } = useI18n()
  const items = risk.items ?? []
  return (
    <section aria-label={t("Değişikliğin risk özeti")} className="flex flex-col gap-2 rounded-lg border px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <RiskBadge level={risk.level} />
        <span className="font-mono text-xs text-muted-foreground tabular-nums">{t("{count} puan", { count: risk.score })}</span>
      </div>
      <p className="text-sm leading-relaxed text-pretty">{ts(risk.summary)}</p>
      {items.length > 0 ? (
        <ul className="flex flex-col gap-1">
          {items.map((it, i) => (
            <li key={`${i}-${it.text}`} className={cn("flex items-start justify-between gap-3 text-sm", it.widens && "text-destructive")}>
              <span className="flex min-w-0 flex-col gap-0.5">
                <span className="text-pretty">{ts(it.text)}</span>
                {it.widens ? <span className="text-xs font-medium">{t("Erişimi genişletir")}</span> : null}
              </span>
              <span className="shrink-0 font-mono text-xs tabular-nums">+{it.points}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  )
}

// i18n-ignore: sunucunun fark satırlarındaki önekle eşleşme, gösterilmez
const piiPrefix = "UYARI (kişisel veri)"

/** Splits the diff lines into the personal data warnings and the rest. */
export function splitPersonalData(lines: string[] | null | undefined): { pii: string[]; rest: string[] } {
  const pii: string[] = []
  const rest: string[] = []
  for (const l of lines ?? []) {
    if (l.trimStart().startsWith(piiPrefix)) pii.push(l.trim())
    else rest.push(l)
  }
  return { pii, rest }
}

/** Amber box listing the new personal data in the change. */
export function PersonalDataWarnings({ lines }: { lines: string[] }) {
  const { t, ts } = useI18n()
  if (lines.length === 0) return null
  return (
    <div role="note" className="flex gap-2.5 rounded-lg bg-warning/15 px-3 py-2.5 text-sm text-warning-foreground dark:text-warning">
      <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
      <div className="flex min-w-0 flex-col gap-1">
        <span className="font-medium">{t("Adlarda kişisel veri olabilir")}</span>
        <ul className="flex flex-col gap-0.5">
          {lines.map((l) => (
            <li key={l} className="break-words text-pretty">
              {ts(l.slice(piiPrefix.length).replace(/^:\s*/, ""))}
            </li>
          ))}
        </ul>
        <span className="text-xs">{t("Bu adlar her cihaza ve koordinatöre gider; nötr adlar (ör. laptop-1) önerilir.")}</span>
      </div>
    </div>
  )
}
