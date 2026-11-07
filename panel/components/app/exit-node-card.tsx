"use client"

import { useState } from "react"
import { Globe, Route, ShieldOff } from "lucide-react"
import { toast } from "sonner"

import { ExitLeakTools } from "@/components/app/exit-leak-tools"
import { HealthAlerts } from "@/components/app/health-alerts"
import { useReadOnly } from "@/components/app/read-only"
import { useAppStatus } from "@/components/app/use-app-status"
import { Flag } from "@/components/devices/system-bits"
import { UpstreamSummary } from "@/components/devices/upstream-status"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { errorMessage, post } from "@/lib/api"
import { tx, useI18n } from "@/lib/i18n/i18n"
import type { UpstreamInfo } from "@/lib/inventory-types"
import type { AppStatus, DeviceStatus } from "@/lib/types"
import { cn } from "@/lib/utils"

interface ExitOption {
  name: string
  label: string
  hint: string
  online: boolean
  country: string
  /** Upstream exit through an external provider (ADR-0142), when the exit node reports one. */
  upstream?: UpstreamInfo
}

/** Lets this computer send its internet traffic through an exit node. */
export function ExitNodeCard() {
  const { t } = useI18n()
  const { status, isApp, mutate } = useAppStatus()
  const readOnly = useReadOnly()
  const [busy, setBusy] = useState<string | null>(null)
  const [confirmOff, setConfirmOff] = useState(false)
  const device = status?.device
  if (!isApp || !device || !device.name) return null

  const wanted = device.exitNodeWanted ?? ""
  async function choose(name: string) {
    setBusy(name)
    try {
      const res = await post<AppStatus>("/api/app/exit", { name })
      await mutate(res, { revalidate: false })
      toast.success(name ? t("İnternet trafiği artık {name} üzerinden çıkıyor.", { name }) : t("İnternet trafiği yeniden doğrudan çıkıyor."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  async function setOptions(killSwitch: boolean, exitAllowLan: boolean, key: string) {
    setBusy(key)
    try {
      const res = await post<AppStatus>("/api/app/exit/options", { killSwitch, exitAllowLan })
      await mutate(res, { revalidate: false })
      toast.success(t("Çıkış düğümü ayarları kaydedildi."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  const options: ExitOption[] = [
    { name: "", label: t("none|Yok"), hint: t("İnternete doğrudan bu bilgisayarın bağlantısından çıkılır."), online: true, country: "" },
  ].concat(
    (device.exitNodes ?? []).map((p) => ({
      name: p.name,
      label: p.name === device.lastExitNode && wanted !== p.name ? t("{name} (son kullanılan)", { name: p.name }) : p.name,
      hint: p.online ? t("{ip}, çevrimiçi", { ip: p.ipv4 }) : t("{ip}, şu an yanıt vermiyor", { ip: p.ipv4 }),
      online: p.online,
      country: p.country ?? "",
      upstream: p.upstream,
    }))
  )

  // Turning the kill switch off while an exit node is chosen weakens the
  // protection, so it is confirmed first, as in the tray.
  function changeKillSwitch(on: boolean) {
    if (!device) return
    if (!on && wanted !== "") {
      setConfirmOff(true)
      return
    }
    void setOptions(on, device.exitAllowLan, "killSwitch")
  }

  return (
    <Card className="lg:col-span-3">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Route className="size-4 text-muted-foreground" />
          {t("Çıkış düğümü")}
        </CardTitle>
        <CardDescription className="text-pretty">{describe(device)}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {options.length === 1 ? (
          <p className="text-sm text-muted-foreground">
            {t("Ağda henüz çıkış düğümü yok. Bir sunucuyu Cihazlar sayfasından \"Çıkış düğümü yap\" ile işaretle.")}
          </p>
        ) : (
          <div role="radiogroup" aria-label={t("Çıkış düğümü")} className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {options.map((o) => {
              const selected = wanted === o.name
              const pending = selected && o.name !== "" && device.exitNode !== o.name
              return (
                <button
                  key={o.name || "none"}
                  type="button"
                  role="radio"
                  aria-checked={selected}
                  disabled={busy !== null || readOnly}
                  onClick={() => (selected ? undefined : choose(o.name))}
                  className={cn(
                    "flex items-start gap-3 rounded-lg border p-3 text-left transition-colors focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
                    selected ? "border-foreground bg-accent" : "hover:bg-accent/50"
                  )}
                >
                  <span className="flex size-8 shrink-0 items-center justify-center rounded-md bg-secondary text-muted-foreground">
                    {busy === o.name ? <Spinner /> : <Globe className="size-4" />}
                  </span>
                  <span className="flex flex-col gap-0.5">
                    <span className="flex items-center gap-1.5 text-sm font-medium">
                      {o.country ? <Flag country={o.country} /> : null}
                      {o.label}
                    </span>
                    <span className="text-xs text-muted-foreground">{pending ? t("Yollar kuruluyor...") : o.hint}</span>
                    {o.upstream ? (
                      <span className="pt-1 text-xs">
                        <UpstreamSummary upstream={o.upstream} />
                      </span>
                    ) : null}
                  </span>
                </button>
              )
            })}
          </div>
        )}
        <HealthAlerts only={["killswitch_failed", "exit_unreachable"]} label={t("Çıkış düğümü uyarıları")} />
        {wanted !== "" ? <ExitLeakTools killSwitchActive={device.killSwitchActive} readOnly={readOnly} /> : null}
        {device.killSwitchSupported ? (
          <div className="flex flex-col divide-y border-y">
            <OptionRow
              id="exit-kill-switch"
              title={t("Sızıntı kilidi (kill switch)")}
              hint={
                device.killSwitch
                  ? t("Açık. Çıkış düğümü seçiliyken tünel düşse, servis çökse veya bilgisayar yeniden başlasa da internet trafiği doğrudan çıkmaz.")
                  : t("Kapalı. Koruma yalnızca tünel yollarına dayanır; servis durursa trafik doğrudan bu bilgisayarın bağlantısından çıkabilir.")
              }
              checked={device.killSwitch}
              busy={busy === "killSwitch"}
              disabled={busy !== null || readOnly}
              onChange={changeKillSwitch}
            />
            <OptionRow
              id="exit-allow-lan"
              title={t("Çıkış düğümü kullanırken yerel ağa erişim")}
              hint={
                !device.killSwitch
                  ? t("Sızıntı kilidi kapalıyken bu ayar uygulanmaz; yerel ağ her zaman erişilebilir.")
                  : device.exitAllowLan
                    ? t("Yazıcı, NAS gibi yerel ağ cihazlarına erişilebilir. DNS sorguları yine yalnızca tünelden gider.")
                    : t("Yerel ağ engelli (önerilen). Açık Wi-Fi'de aynı ağdaki cihazlar bu bilgisayara ulaşamaz.")
              }
              checked={device.exitAllowLan}
              busy={busy === "allowLan"}
              disabled={busy !== null || !device.killSwitch || readOnly}
              onChange={(on) => setOptions(device.killSwitch, on, "allowLan")}
            />
          </div>
        ) : null}
      </CardContent>
      <Dialog open={confirmOff} onOpenChange={setConfirmOff}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t("Sızıntı kilidi (kill switch) kapatılsın mı?")}</DialogTitle>
            <DialogDescription className="text-pretty">
              {t(
                "Çıkış düğümüne ulaşılamazsa veya servis durursa internet trafiği doğrudan bu bilgisayarın bağlantısından çıkabilir. Açık Wi-Fi'de gerçek IP adresin görünür hale gelebilir."
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOff(false)}>
              {t("Vazgeç")}
            </Button>
            <Button
              variant="destructive"
              onClick={() => {
                setConfirmOff(false)
                void setOptions(false, device.exitAllowLan, "killSwitch")
              }}
            >
              <ShieldOff data-icon="inline-start" />
              {t("Sızıntı kilidini kapat")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  )
}

/** Explains what the current exit node settings do to local traffic. */
function describe(device: DeviceStatus): string {
  if (!device.killSwitchSupported || !device.killSwitch) {
    return tx(
      "Seçtiğin cihaz bu bilgisayarın bütün internet trafiğini ve DNS sorgularını kendi bağlantısından çıkarır. Yerel ağdaki cihazlara erişim değişmez. Çıkış düğümüne ulaşılamazsa trafik tünelde bekler; doğrudan internete sızmaz."
    )
  }
  return device.exitAllowLan
    ? tx(
        "Seçtiğin cihaz bu bilgisayarın bütün internet trafiğini ve DNS sorgularını kendi bağlantısından çıkarır. Yerel ağa erişim açık. Sızıntı kilidi (kill switch), OpenScale dışındaki her yolu kapatır; servis çökse bile trafik doğrudan çıkmaz."
      )
    : tx(
        "Seçtiğin cihaz bu bilgisayarın bütün internet trafiğini ve DNS sorgularını kendi bağlantısından çıkarır. Yerel ağa erişim kapalı. Sızıntı kilidi (kill switch), OpenScale dışındaki her yolu kapatır; servis çökse bile trafik doğrudan çıkmaz."
      )
}

function OptionRow({
  id,
  title,
  hint,
  checked,
  busy,
  disabled,
  onChange,
}: {
  id: string
  title: string
  hint: string
  checked: boolean
  busy: boolean
  disabled: boolean
  onChange: (on: boolean) => void
}) {
  return (
    <div className="flex items-center justify-between gap-4 py-3">
      <span className="flex flex-col gap-0.5">
        <label htmlFor={id} className="text-sm font-medium">
          {title}
        </label>
        <span className="text-sm leading-relaxed text-muted-foreground text-pretty">{hint}</span>
      </span>
      <div className="flex items-center gap-2">
        {busy ? <Spinner /> : null}
        <Switch id={id} checked={checked} disabled={disabled} onCheckedChange={(on) => onChange(on)} />
      </div>
    </div>
  )
}
