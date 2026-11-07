"use client"

import { useState } from "react"
import useSWR from "swr"
import { MonitorSmartphone } from "lucide-react"
import { toast } from "sonner"

import { useReadOnly } from "@/components/app/read-only"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldContent, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Switch } from "@/components/ui/switch"
import { errorMessage, fetcher, post } from "@/lib/api"
import { formatDate } from "@/lib/format"
import { useI18n } from "@/lib/i18n/i18n"
import { modeText, type RDeskSettings, type RDeskStatus } from "@/lib/wave2"
import { RDeskFileRoots } from "@/components/security/rdesk-file-roots"

/** Owner switches of the remote desktop on this computer (ADR-0103, ADR-0110). */
export function RDeskCard() {
  const { t, ts } = useI18n()
  const { data, mutate } = useSWR<RDeskStatus>("/api/app/rdesk", fetcher, { refreshInterval: 5000 })
  const readOnly = useReadOnly()
  const [busy, setBusy] = useState(false)
  if (!data) return null

  async function set(change: Partial<RDeskSettings>): Promise<boolean> {
    setBusy(true)
    try {
      const res = await post<RDeskStatus>("/api/app/rdesk/settings", change)
      await mutate(res, { revalidate: false })
      toast.success(t("Uzak masaüstü ayarı kaydedildi; açık oturumlar sona erer."))
      return true
    } catch (err) {
      toast.error(errorMessage(err))
      return false
    } finally {
      setBusy(false)
    }
  }

  const switches: { key: "recording" | "localLock" | "power"; label: string; desc: string }[] = [
    {
      key: "recording",
      label: t("Oturumları kaydet"),
      desc: t("Her oturum bu bilgisayarda şifreli kaydedilir; bağlanan kişiye ve ekrandaki göstergeye bildirilir. Tuşlar ve pano kaydedilmez."),
    },
    {
      key: "localLock",
      label: t("Ekran karartma ve yerel giriş kilidi"),
      desc: t("Kontrol oturumu ekranı karartıp yerel klavye ve fareyi kilitleyebilir; Ctrl+Alt+Del her zaman çalışır."),
    },
    {
      key: "power",
      label: t("Uzaktan yeniden başlatma"),
      desc: t("Kontrol oturumu bu bilgisayarı 10 saniye sonra yeniden başlatabilir. Güvenli mod bu sürümde yok."),
    },
  ]

  return (
    <Card className="lg:col-span-3">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <MonitorSmartphone className="size-4 text-muted-foreground" />
          {t("Uzak masaüstü")}
        </CardTitle>
        <CardDescription className="text-pretty">
          {t("Kimin bağlanacağını rdesk kuralları belirler; bu anahtarlar yalnızca bu bilgisayarda geçerli ve varsayılan kapalı.")}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {!data.supported && (
          <Alert>
            <AlertDescription>{t("Bu bilgisayar uzak masaüstü sunucusu çalıştıramıyor (masaüstü oturumu yok veya desteklenmiyor).")}</AlertDescription>
          </Alert>
        )}
        {data.error && data.hosted && (
          <Alert variant="destructive">
            <AlertDescription>{ts(data.error)}</AlertDescription>
          </Alert>
        )}
        <div className="flex flex-wrap gap-2 text-sm">
          <Badge variant={data.running ? "default" : "secondary"}>{data.running ? t("Dinliyor") : data.hosted ? t("Başlatılamadı") : t("Kural yok")}</Badge>
        </div>
        <FieldGroup>
          {switches.map((s) => (
            <Field key={s.key} orientation="horizontal">
              <FieldContent>
                <FieldLabel htmlFor={`rdesk-${s.key}`}>{s.label}</FieldLabel>
                <FieldDescription>{s.desc}</FieldDescription>
              </FieldContent>
              <Switch
                id={`rdesk-${s.key}`}
                checked={data.settings[s.key]}
                disabled={readOnly || busy}
                onCheckedChange={(on) => set({ [s.key]: on })}
              />
            </Field>
          ))}
          <RDeskFileRoots roots={data.settings.fileRoots ?? []} disabled={readOnly || busy} onSave={(roots) => set({ fileRoots: roots })} />
        </FieldGroup>
        {data.sessions.length > 0 && (
          <div className="flex flex-col gap-2">
            <span className="text-sm font-medium">{t("Açık oturumlar")}</span>
            {data.sessions.map((s) => (
              <div key={s.id} className="flex flex-wrap items-center gap-2 rounded-md border p-3 text-sm">
                <span className="font-medium">{s.peer}</span>
                <span className="text-muted-foreground">{modeText(s.mode)}</span>
                {s.code && <span className="font-mono tracking-wider">{t("kod {code}", { code: s.code })}</span>}
                {s.recording && <Badge variant="destructive">{t("recording|Kaydediliyor")}</Badge>}
                {s.unattended && <Badge variant="secondary">{t("Gözetimsiz")}</Badge>}
                <span className="text-muted-foreground">{formatDate(s.started)}</span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
