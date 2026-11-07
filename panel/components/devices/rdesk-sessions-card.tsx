"use client"

import useSWR from "swr"
import { MonitorSmartphone } from "lucide-react"

import { useAppStatus } from "@/components/app/use-app-status"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { fetcher } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { useI18n } from "@/lib/i18n/i18n"
import { modeText, type RDeskStatus } from "@/lib/wave2"

/** Remote desktop sessions this device opened on this computer, with the verification code and recording state (ADR-0103). */
export function RDeskSessionsCard({ device, bare }: { device: string; bare?: boolean }) {
  const { t, ts } = useI18n()
  const { isApp } = useAppStatus()
  const { data } = useSWR<RDeskStatus>(isApp ? "/api/app/rdesk" : null, fetcher, { refreshInterval: 5000 })
  if (!data) return null
  const active = data.sessions.filter((s) => s.peer === device)
  const recent = data.recent.filter((s) => s.peer === device).slice(0, 5)
  if (active.length === 0 && recent.length === 0) return null
  const list = (
    <div className="flex flex-col gap-2 text-sm">
      {active.map((s) => (
        <div key={s.id} className="flex flex-wrap items-center gap-2 rounded-md border p-2">
          <Badge>{t("Açık")}</Badge>
          <span>{t(modeText(s.mode))}</span>
          {s.code ? <span className="font-mono tracking-wider">{t("kod {code}", { code: s.code })}</span> : null}
          <Badge variant={s.recording ? "destructive" : "secondary"}>{s.recording ? t("recording|Kaydediliyor") : t("Kayıt yok")}</Badge>
          {s.unattended ? <Badge variant="outline">{t("Gözetimsiz")}</Badge> : null}
          <span className="text-muted-foreground">{formatDateTime(s.started)}</span>
        </div>
      ))}
      {recent.map((s) => (
        <div key={s.id} className="flex flex-wrap items-center gap-2 text-muted-foreground">
          <span>{formatDateTime(s.started)}</span>
          <span>{t(modeText(s.mode))}</span>
          {s.recording ? <span>{t("kaydedildi")}</span> : null}
          {s.reason ? <span>({ts(s.reason)})</span> : null}
        </div>
      ))}
    </div>
  )
  if (bare) return <div className="py-4">{list}</div>
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <MonitorSmartphone className="size-4 text-muted-foreground" />
          {t("Bu bilgisayardaki uzak masaüstü oturumları")}
        </CardTitle>
        <CardDescription>{t("Doğrulama kodu bağlanan kişinin ekranındakiyle aynı olmalı.")}</CardDescription>
      </CardHeader>
      <CardContent>{list}</CardContent>
    </Card>
  )
}
