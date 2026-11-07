"use client"

import { useState } from "react"
import { MonitorPlay, TriangleAlert } from "lucide-react"

import { withReauth } from "@/components/auth/reauth"
import { CodedError, postCoded, utf8Base64 } from "@/components/auth/strict-api"
import { CopyButton } from "@/components/copy-field"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button, buttonVariants } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { msg, useI18n } from "@/lib/i18n/i18n"

// Remote desktop connection from the device page (ADR-0198, ADR-0201).
// The desktop app opens its own viewer window; the panel only starts it.
// Windows and macOS targets may ask for the target's operating system
// account; the password goes inside the end-to-end encrypted layer and
// the signed rdesk rule is still checked first.
//
// Endpoint (internal/panel/w1_rdesk_viewer.go):
//   POST /api/app/rdesk/connect {device, mode: "view"|"control",
//     channels: string[], user?, password? (UTF-8 base64)}
//     -> {ok, session, viewer, code, recorded}
// The panel dials the device itself; the open session waits a minute for
// the viewer window (/remote-viewer/#t=...). Error codes:
// "os_login_required", "os_login_failed", "os_login_blocked",
// "connect_failed". A build without it answers 404; the page then shows
// the command line way.

export type RDeskChannel = "video" | "input" | "clipboard" | "files" | "audio" | "curtain"

const channelInfo: { id: RDeskChannel; label: string; note?: string }[] = [
  { id: "video", label: msg("Görüntü") },
  { id: "input", label: msg("Klavye ve fare") },
  { id: "clipboard", label: msg("Pano") },
  { id: "files", label: msg("Dosyalar") },
  { id: "audio", label: msg("Ses"), note: msg("Bu sürümde ses taşınmıyor.") },
  { id: "curtain", label: msg("Gizlilik perdesi"), note: msg("Karşı ekranı karartır ve yerel girdiyi kilitler.") },
]

interface ConnectAnswer {
  ok: boolean
  session: string
  viewer: string
  code?: string
}

interface RDeskConnectProps {
  device: string
  /** Operating system of the target: "windows", "darwin", "linux", ... */
  os: string
}

export function RDeskConnectButton({ device, os }: RDeskConnectProps) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
        <MonitorPlay data-icon="inline-start" />
        {t("Uzak masaüstüne bağlan")}
      </Button>
      <RDeskConnectDialog device={device} os={os} open={open} onOpenChange={setOpen} />
    </>
  )
}

interface DialogProps extends RDeskConnectProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

function RDeskConnectDialog({ device, os, open, onOpenChange }: DialogProps) {
  const { t, ts } = useI18n()
  const needsAccount = os === "windows" || os === "darwin"
  const [mode, setMode] = useState<"view" | "control">("control")
  const [channels, setChannels] = useState<Set<RDeskChannel>>(new Set(["video", "input"]))
  const [user, setUser] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const [unsupported, setUnsupported] = useState(false)
  const [started, setStarted] = useState(false)
  const [viewer, setViewer] = useState("")
  const [code, setCode] = useState("")

  function toggle(id: RDeskChannel, on: boolean) {
    setChannels((prev) => {
      const next = new Set(prev)
      if (on) next.add(id)
      else next.delete(id)
      if (id === "video") next.add("video")
      return next
    })
  }

  function close(next: boolean) {
    if (!next) {
      setPassword("")
      setError("")
      setStarted(false)
      setUnsupported(false)
      setViewer("")
      setCode("")
    }
    onOpenChange(next)
  }

  async function connect(e: React.FormEvent) {
    e.preventDefault()
    if (needsAccount && user.trim() && !password) {
      setError(t("Hesap parolasını girin."))
      return
    }
    setBusy(true)
    setError("")
    const body: Record<string, unknown> = {
      device,
      mode,
      channels: Array.from(channels).filter((c) => mode === "control" || (c !== "input" && c !== "curtain")),
    }
    if (needsAccount && user.trim()) {
      body.user = user.trim()
      body.password = utf8Base64(password)
    }
    setPassword("")
    try {
      const answer = await withReauth(() => postCoded<ConnectAnswer>("/api/app/rdesk/connect", body))
      setCode(answer.code ?? "")
      // The desktop window opens the viewer as its own window; a browser
      // that blocks it leaves the button below.
      const win = window.open(answer.viewer, "_blank")
      setViewer(win ? "" : answer.viewer)
      setStarted(true)
    } catch (err) {
      if (err instanceof CodedError && (err.status === 404 || err.status === 501)) setUnsupported(true)
      else if (err instanceof CodedError && err.code === "os_login_failed") setError(t("Kullanıcı adı veya parola yanlış."))
      else if (err instanceof CodedError && err.code === "os_login_blocked") setError(err.message ? ts(err.message) : t("Çok fazla hatalı deneme; biraz sonra yeniden deneyin."))
      else if (err instanceof CodedError && err.code === "os_login_required") setError(t("Hedef cihaz hesap istiyor. Kullanıcı adı ve parolayı girin."))
      else if (err instanceof CodedError && err.code === "control_busy") {
        // #853: another administrator controls the screen; a second device may only watch.
        setMode("view")
        setError(t("Bu cihazı başka bir yönetici denetliyor. İzleyici olarak katılmak için yeniden bağlanın; ayrı bir doğrulama kodu alırsınız."))
      }
      else setError(err instanceof Error && err.message ? ts(err.message) : t("Bağlantı başlatılamadı."))
    } finally {
      setBusy(false)
    }
  }

  const command = `openscale rdesk ${device}`

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("{device} uzak masaüstü", { device })}</DialogTitle>
          <DialogDescription>
            {t(
              "Görüntü uçtan uca şifreli gelir. Karşı cihaz bağlantıyı imzalı kurala göre denetler; ekranında bağlı olduğunuzu gösteren silinemeyen bir çerçeve görünür."
            )}
          </DialogDescription>
        </DialogHeader>

        {started ? (
          <div role="status" className="flex flex-col gap-3 rounded-lg border bg-muted/40 px-3 py-2 text-sm text-pretty">
            <p>
              {viewer
                ? t("Bağlantı hazır. Görüntüleyiciyi bir dakika içinde açın; açılmazsa oturum kapanır.")
                : t("Görüntüleyici ayrı bir pencerede açıldı; pencereyi kapatınca bağlantı biter.")}
            </p>
            {code ? (
              <p>
                {t("Doğrulama kodu:")} <span className="font-mono tabular-nums text-foreground">{code}</span>.{" "}
                {t("Karşı ekrandaki kodla aynı olmalı.")}
              </p>
            ) : null}
            {viewer ? (
              <a href={viewer} target="_blank" rel="noopener" className={buttonVariants({ size: "sm", className: "self-start" })}>
                {t("Görüntüleyiciyi aç")}
              </a>
            ) : null}
          </div>
        ) : unsupported ? (
          <div className="flex flex-col gap-3 text-sm leading-relaxed text-muted-foreground">
            <p className="text-pretty">{t("Bu sürümde uzak masaüstü panelden başlatılamıyor. Komut satırından bağlanabilirsiniz:")}</p>
            <div className="flex items-center gap-1 rounded-md border bg-muted/40 px-3 py-2">
              <code className="min-w-0 flex-1 break-all text-foreground">{command}</code>
              <CopyButton value={command} label={t("Komutu kopyala")} />
            </div>
          </div>
        ) : (
          <form id="rdesk-connect" onSubmit={connect} noValidate className="flex flex-col gap-6">
            <FieldSet>
              <FieldLegend variant="label">{t("Oturum türü")}</FieldLegend>
              <div className="grid grid-cols-2 gap-2" role="radiogroup" aria-label={t("Oturum türü")}>
                {(["control", "view"] as const).map((m) => (
                  <label
                    key={m}
                    className="flex cursor-pointer flex-col gap-0.5 rounded-lg border p-3 text-sm has-checked:border-primary has-checked:bg-primary/5 has-focus-visible:ring-3 has-focus-visible:ring-ring/50"
                  >
                    <input type="radio" name="rdesk-mode" value={m} checked={mode === m} onChange={() => setMode(m)} className="sr-only" />
                    <span className="font-medium">{m === "control" ? t("Yönet") : t("Yalnızca izle")}</span>
                    <span className="text-xs text-muted-foreground">{m === "control" ? t("Klavye ve fare gönderilir.") : t("Hiçbir girdi gönderilmez.")}</span>
                  </label>
                ))}
              </div>
            </FieldSet>

            <FieldSet>
              <FieldLegend variant="label">{t("Bu oturumda izin verilenler")}</FieldLegend>
              <FieldDescription>{t("Kural izin vermiyorsa karşı cihaz seçimi yok sayar.")}</FieldDescription>
              <FieldGroup className="grid gap-3 sm:grid-cols-2">
                {channelInfo.map((c) => {
                  const disabled = c.id === "video" || c.id === "audio" || (mode === "view" && (c.id === "input" || c.id === "curtain"))
                  const checked = c.id === "video" || (!disabled && channels.has(c.id))
                  return (
                    <Field key={c.id} orientation="horizontal" data-disabled={disabled ? true : undefined}>
                      <Checkbox id={`rdesk-ch-${c.id}`} checked={checked} disabled={disabled} onCheckedChange={(v) => toggle(c.id, v === true)} />
                      <div className="flex flex-col gap-0.5">
                        <FieldLabel htmlFor={`rdesk-ch-${c.id}`} className="font-normal">
                          {t(c.label)}
                        </FieldLabel>
                        {c.note ? <span className="text-xs text-muted-foreground">{t(c.note)}</span> : null}
                      </div>
                    </Field>
                  )
                })}
              </FieldGroup>
            </FieldSet>

            {needsAccount ? (
              <FieldSet>
                <FieldLegend variant="label">{t("Hedefin {os} hesabı", { os: os === "windows" ? "Windows" : "macOS" })}</FieldLegend>
                <FieldDescription>{t("Hedef cihaz giriş istiyorsa doldurun; istemiyorsa boş bırakın.")}</FieldDescription>
                <FieldGroup className="grid gap-4 sm:grid-cols-2">
                  <Field>
                    <FieldLabel htmlFor="rdesk-user">{t("Kullanıcı adı")}</FieldLabel>
                    <Input id="rdesk-user" autoComplete="off" maxLength={256} value={user} onChange={(e) => setUser(e.target.value)} />
                  </Field>
                  <Field data-invalid={error ? true : undefined}>
                    <FieldLabel htmlFor="rdesk-password">{t("Parola")}</FieldLabel>
                    <Input
                      id="rdesk-password"
                      type="password"
                      autoComplete="off"
                      maxLength={1024}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                  </Field>
                </FieldGroup>
              </FieldSet>
            ) : null}
            {error ? (
              <Alert variant="destructive">
                <TriangleAlert />
                <AlertDescription>
                  <FieldError>{error}</FieldError>
                </AlertDescription>
              </Alert>
            ) : null}
          </form>
        )}

        <DialogFooter>
          {started || unsupported ? (
            <Button variant="outline" onClick={() => close(false)}>
              {t("Kapat")}
            </Button>
          ) : (
            <Button type="submit" form="rdesk-connect" disabled={busy}>
              {busy ? <Spinner data-icon="inline-start" /> : null}
              {t("Bağlan")}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
