"use client"

import { useState } from "react"
import { CircleAlert, CircleCheck, CircleMinus, CircleX, Stethoscope } from "lucide-react"

import { DetailSection } from "@/components/devices/detail-card"
import { layerTitles, stepTexts } from "@/components/diag/troubleshoot-texts"
import { ErrorCodeLink } from "@/components/error-code"
import { EmptyNote } from "@/components/settings/settings-layout"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { errorMessage, post } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { StepStatus, TroubleshootReport, TroubleshootStep } from "@/lib/p2-diag-types"
import { cn } from "@/lib/utils"

const statusLabel: Record<StepStatus, string> = {
  pass: msg("Geçti"),
  fail: msg("Kaldı"),
  warn: msg("Uyarı"),
  skip: msg("Atlandı"),
}

function StatusIcon({ status }: { status: StepStatus }) {
  const cls = "size-5 shrink-0"
  switch (status) {
    case "pass":
      return <CircleCheck className={cn(cls, "text-success")} aria-hidden="true" />
    case "fail":
      return <CircleX className={cn(cls, "text-destructive")} aria-hidden="true" />
    case "warn":
      return <CircleAlert className={cn(cls, "text-warning")} aria-hidden="true" />
    default:
      return <CircleMinus className={cn(cls, "text-muted-foreground")} aria-hidden="true" />
  }
}

/** Texts of one step in the interface language; unknown keys keep the service's text. */
function useStepText() {
  const { t, ts } = useI18n()
  return (s: TroubleshootStep) => {
    const vars: Record<string, string> = { ...(s.vars ?? {}) }
    if (vars.layer && layerTitles[vars.layer]) vars.layer = t(layerTitles[vars.layer])
    const known = stepTexts[s.key]
    const title = s.layer === "peer" && s.peer ? s.peer : layerTitles[s.layer] ? t(layerTitles[s.layer]) : ts(s.title)
    let detail = known ? t(known.detail, vars) : ts(s.detail ?? "")
    if (s.key === "interface.not_running" && vars.error) detail = `${detail} ${ts(vars.error)}`
    if (s.key === "peer.relayed" && vars.reason) detail = `${detail} ${ts(vars.reason)}`
    const fix = known?.fix ? t(known.fix, vars) : s.fix ? ts(s.fix) : ""
    return { title, detail, fix }
  }
}

/**
 * "Bağlantı sorununu bul" (#835): checks the tunnel interface, the local
 * gateway, DNS, the coordinator, the relay and each peer in turn, and
 * stops trusting the layers above the first failure. Only the owner's own
 * coordinator is contacted.
 */
export function TroubleshootWizard() {
  const { t } = useI18n()
  const text = useStepText()
  const [report, setReport] = useState<TroubleshootReport | null>(null)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function run() {
    setRunning(true)
    setError(null)
    try {
      setReport(await post<TroubleshootReport>("/api/app/diag/troubleshoot", {}))
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setRunning(false)
    }
  }

  const first = report && report.first_failure >= 0 ? report.steps[report.first_failure] : null

  return (
    <DetailSection
      id="sorun-bul"
      title={t("Bağlantı sorununu bul")}
      description={t(
        "Arayüz, yerel ağ geçidi, DNS, koordinatör, aktarıcı ve her eş sırayla denetlenir; ilk kalan adımın üstü atlanır. Yalnızca kendi koordinatörünüze bağlanılır.",
      )}
      framed={false}
      action={
        <Button type="button" onClick={() => void run()} disabled={running} aria-describedby="troubleshoot-live">
          {running ? <Spinner data-icon="inline-start" /> : <Stethoscope data-icon="inline-start" />}
          {report ? t("Yeniden denetle") : t("Denetimi başlat")}
        </Button>
      }
    >
      <p id="troubleshoot-live" className="sr-only" aria-live="polite">
        {running ? t("Denetleniyor…") : report ? (report.ok ? t("Sorun bulunmadı.") : t("Bir sorun bulundu.")) : ""}
      </p>
      {error ? (
        <Alert variant="destructive">
          <CircleX />
          <AlertTitle>{t("Denetim çalıştırılamadı")}</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {!report && !error ? (
        <EmptyNote>{t("Bağlantıda sorun varsa denetimi başlatın; birkaç saniye sürer.")}</EmptyNote>
      ) : null}
      {report ? (
        <>
          {first ? (
            <Alert variant="destructive">
              <CircleX />
              <AlertTitle>{t("İlk sorun: {step}", { step: text(first).title })}</AlertTitle>
              <AlertDescription className="flex flex-col gap-2">
                <span className="text-pretty">{text(first).fix || text(first).detail}</span>
                {first.code ? <ErrorCodeLink code={first.code} /> : null}
              </AlertDescription>
            </Alert>
          ) : (
            <Alert>
              <CircleCheck />
              <AlertTitle>{t("Sorun bulunmadı")}</AlertTitle>
              <AlertDescription>{t("Bütün katmanlar geçti; uyarılar varsa aşağıda.")}</AlertDescription>
            </Alert>
          )}
          <ol className="flex flex-col divide-y rounded-lg border" aria-label={t("Denetim adımları")}>
            {report.steps.map((s, i) => {
              const tx = text(s)
              return (
                <li key={`${s.layer}-${s.peer ?? ""}-${i}`} className="flex items-start gap-3 px-4 py-3">
                  <StatusIcon status={s.status} />
                  <div className="flex min-w-0 flex-1 flex-col gap-1">
                    <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                      <span className="text-sm font-medium">{tx.title}</span>
                      <span className="text-xs text-muted-foreground">{t(statusLabel[s.status] ?? s.status)}</span>
                    </div>
                    {tx.detail ? <p className="text-sm leading-relaxed text-pretty text-muted-foreground">{tx.detail}</p> : null}
                    {tx.fix && (s.status === "fail" || s.status === "warn") ? (
                      <p className="text-sm leading-relaxed text-pretty">
                        <span className="font-medium">{t("Öneri:")}</span> {tx.fix}
                      </p>
                    ) : null}
                    {s.code && s.status !== "pass" && s !== first ? <ErrorCodeLink code={s.code} /> : null}
                  </div>
                </li>
              )
            })}
          </ol>
          <p className="text-xs text-muted-foreground">
            {t("Denetim zamanı: {at}", { at: formatDateTime(report.at) })}
          </p>
        </>
      ) : null}
    </DetailSection>
  )
}
