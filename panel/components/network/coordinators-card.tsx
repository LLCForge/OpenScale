"use client"

import useSWR from "swr"
import { ShieldAlert } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Card, CardContent } from "@/components/ui/card"
import { fetcher } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { useI18n } from "@/lib/i18n/i18n"
import type { CoordinatorState, CoordinatorsResponse } from "@/lib/wave3-types"

/** Coordinators of the signed document and this computer's view (ADR-0111); the page gives the title. */
export function CoordinatorsCard() {
  const { t, ts } = useI18n()
  const { data } = useSWR<CoordinatorsResponse>("/api/network/coordinators", fetcher, { refreshInterval: 15_000 })
  if (!data || data.coordinators.length === 0) return null
  const live = new Map<string, CoordinatorState>()
  for (const c of data.device?.coordinators ?? []) live.set(c.fingerprint, c)
  const integrity = data.device?.integrity ?? []
  return (
    <Card className="xl:col-span-2">
      <CardContent className="flex flex-col gap-4">
        <ul className="flex flex-col divide-y rounded-xl border text-sm">
          {data.coordinators.map((c) => {
            const l = live.get(c.fingerprint)
            return (
              <li key={c.fingerprint} className="flex flex-col gap-1 px-4 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{c.name || c.endpoint}</span>
                  <Badge variant={c.primary ? "default" : "secondary"}>{c.primary ? t("Birincil") : t("Ek")}</Badge>
                  {l?.active ? <Badge variant="outline">{t("Bu cihaz bağlı")}</Badge> : null}
                  {l?.relay ? <Badge variant="outline">{t("Aktarıcı")}</Badge> : null}
                  {c.expired ? <Badge variant="destructive">{t("Geçiş süresi bitti")}</Badge> : null}
                </div>
                <span className="font-mono text-xs text-muted-foreground break-all">
                  {c.endpoint}
                  {c.region ? ` · ${c.region}` : ""} · {c.fingerprint}
                </span>
                {c.until ? (
                  <span className="text-xs text-muted-foreground">{t("Geçiş süresi: {date} tarihine kadar", { date: formatDateTime(c.until) })}</span>
                ) : null}
                {l ? (
                  <span className="text-xs text-muted-foreground">
                    {l.rttMs > 0 ? t("Gecikme {ms} ms", { ms: l.rttMs }) : t("Gecikme bilinmiyor")}
                    {l.lastReply ? ` · ${t("son yanıt {time}", { time: formatDateTime(l.lastReply) })}` : ""}
                    {l.failures > 0 ? ` · ${t("{count} başarısız deneme", { count: l.failures })}` : ""}
                  </span>
                ) : null}
              </li>
            )
          })}
        </ul>
        {integrity.length > 0 ? (
          <section aria-labelledby="coord-integrity" className="flex flex-col gap-2">
            <h3 id="coord-integrity" className="flex items-center gap-2 text-sm font-medium text-destructive">
              <ShieldAlert className="size-4" />
              {t("Bütünlük uyarıları")}
            </h3>
            <ul className="flex flex-col gap-1 text-xs text-muted-foreground">
              {integrity.map((f, i) => (
                <li key={i} className="text-pretty">
                  {f.severity === "kritik" ? `${t("Kritik")}: ` : `${t("Uyarı")}: `}
                  {f.coordinator ? `${f.coordinator}: ` : ""}
                  {ts(f.text)}
                </li>
              ))}
            </ul>
          </section>
        ) : null}
      </CardContent>
    </Card>
  )
}
