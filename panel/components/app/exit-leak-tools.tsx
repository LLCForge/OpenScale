"use client"

import { useEffect, useState } from "react"
import { DoorOpen, ShieldCheck } from "lucide-react"
import { toast } from "sonner"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { errorMessage, post } from "@/lib/api"
import { formatTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { CaptiveGrant, LeakLevel, LeakReport } from "@/lib/leak-types"

const levelLabel: Record<LeakLevel, string> = { ok: msg("Tamam"), info: msg("Bilgi"), warn: msg("Uyarı"), leak: msg("Sızıntı") }

function levelVariant(level: LeakLevel): "secondary" | "outline" | "destructive" {
  if (level === "leak") return "destructive"
  if (level === "warn") return "outline"
  return "secondary"
}

const captiveMinutes = 5

/**
 * The exit node's leak test and, while the kill switch is installed, the
 * short captive portal exception the owner opens by hand (ADR-0023).
 */
export function ExitLeakTools({ killSwitchActive, readOnly }: { killSwitchActive: boolean; readOnly: boolean }) {
  const { t, ts } = useI18n()
  const [busy, setBusy] = useState<"test" | "captive" | null>(null)
  const [report, setReport] = useState<LeakReport | null>(null)
  const [grant, setGrant] = useState<CaptiveGrant | null>(null)

  async function runTest() {
    setBusy("test")
    try {
      const res = await post<LeakReport>("/api/app/exit/leak-test", {})
      setReport(res)
      if (res.leak) toast.error(t("Sızıntı bulundu; ayrıntılar kartta."))
      else toast.success(t("Sızıntı bulunmadı."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  async function captive(off: boolean) {
    setBusy("captive")
    try {
      const res = await post<CaptiveGrant>("/api/app/exit/captive", off ? { off: true } : { minutes: captiveMinutes })
      setGrant(off ? null : res)
      toast.success(off ? t("Giriş sayfası izni kapatıldı.") : t("Giriş sayfası için {count} dakikalık izin açıldı.", { count: captiveMinutes }))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  // The exception closes by itself on the computer; the card follows.
  useEffect(() => {
    if (!grant) return
    const timer = window.setTimeout(() => setGrant(null), Math.max(0, new Date(grant.until).getTime() - Date.now()))
    return () => window.clearTimeout(timer)
  }, [grant])

  const grantActive = grant !== null

  return (
    <section aria-label={t("Sızıntı denetimi")} className="flex flex-col gap-3 rounded-lg border p-3">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <span className="flex flex-col gap-0.5">
          <span className="text-sm font-medium">{t("Sızıntı testi")}</span>
          <span className="text-xs leading-relaxed text-muted-foreground text-pretty">
            {t(
              "Görünen IP adresini, DNS yolunu, IPv6'yı ve WebRTC'nin gösterebileceği adresleri denetler. Yalnızca kendi koordinatörüne ve çıkış düğümünün çözücüsüne sorar."
            )}
          </span>
        </span>
        <Button variant="outline" size="sm" disabled={busy !== null} onClick={() => void runTest()}>
          {busy === "test" ? <Spinner data-icon="inline-start" /> : <ShieldCheck data-icon="inline-start" />}
          {t("Testi çalıştır")}
        </Button>
      </div>
      {report ? (
        <ul className="flex flex-col gap-2" aria-live="polite">
          {report.checks.map((c) => (
            <li key={c.id} className="flex flex-col gap-1 rounded-md bg-muted/40 p-2">
              <span className="flex items-center gap-2 text-sm font-medium">
                <Badge variant={levelVariant(c.level)}>{t(levelLabel[c.level])}</Badge>
                {ts(c.title)}
              </span>
              {c.detail ? <span className="text-xs leading-relaxed text-muted-foreground text-pretty">{ts(c.detail)}</span> : null}
            </li>
          ))}
        </ul>
      ) : null}
      {killSwitchActive ? (
        <div className="flex flex-col gap-2 border-t pt-3 sm:flex-row sm:items-center sm:justify-between">
          <span className="flex flex-col gap-0.5">
            <span className="text-sm font-medium">{t("Giriş sayfası (otel, havaalanı Wi-Fi)")}</span>
            <span className="text-xs leading-relaxed text-muted-foreground text-pretty">
              {grantActive && grant
                ? t("{addrs} adresine HTTP/HTTPS izni {time} saatine kadar açık. Tarayıcıda {url} adresini açın.", {
                    addrs: grant.addrs.join(", "),
                    time: formatTime(grant.until),
                    url: `http://${grant.addrs[0]}/`,
                  })
                : t(
                    "Sızıntı kilidi açıkken ağın giriş sayfası açılmaz. Yalnızca yerel ağ geçidine {count} dakikalık HTTP/HTTPS izni açar; DNS ve diğer trafik kapalı kalır, süre dolunca izin kendiliğinden kapanır.",
                    { count: captiveMinutes }
                  )}
            </span>
          </span>
          <Button
            variant={grantActive ? "outline" : "secondary"}
            size="sm"
            disabled={busy !== null || readOnly}
            onClick={() => void captive(grantActive)}
          >
            {busy === "captive" ? <Spinner data-icon="inline-start" /> : <DoorOpen data-icon="inline-start" />}
            {grantActive ? t("İzni kapat") : t("Giriş sayfasına izin ver")}
          </Button>
        </div>
      ) : null}
    </section>
  )
}
