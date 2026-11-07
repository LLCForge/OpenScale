"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { KeyRound, ShieldAlert, SquareTerminal, TriangleAlert } from "lucide-react"
import type { Terminal } from "@xterm/xterm"

import "@xterm/xterm/css/xterm.css"

import { withReauth } from "@/components/auth/reauth"
import { postCoded, utf8Base64 } from "@/components/auth/strict-api"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { TerminalTabs } from "@/components/terminal/f3-terminal-tabs"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"

// SSH terminal for Linux devices in the local panel (ADR-0203). The panel
// asks the Go side for a one-use ticket, opens a same-origin WebSocket and
// sends the password once as the first message; the server pins the host
// key on first use and refuses a changed key.

interface OpenAnswer {
  ticket: string
  expires_sec: number
  address: string
}

type HostKeyStatus = "pinned" | "known" | "certified"

type ServerMessage =
  | { type: "hostkey"; status: HostKeyStatus; fingerprint: string; pinned?: string }
  | { type: "ready" }
  | { type: "exit" }
  | { type: "error"; code: string; message?: string; fingerprint?: string; pinned?: string }

const errorText: Record<string, string> = {
  auth_failed: msg("Kullanıcı adı veya parola kabul edilmedi."),
  blocked: msg("Çok fazla hatalı parola; bir süre bekleyin."),
  connect_failed: msg("Cihaza bağlanılamadı. Cihazın açık olduğunu ve SSH kuralının bu bilgisayara izin verdiğini denetleyin."),
  shell_failed: msg("Kabuk açılamadı."),
}

function parseMessage(text: string): ServerMessage | null {
  try {
    const data: unknown = JSON.parse(text)
    if (data && typeof data === "object" && "type" in data && typeof data.type === "string") return data as ServerMessage
  } catch {
    // Not JSON.
  }
  return null
}

interface SSHTerminalDialogProps {
  device: string | null
  onClose: () => void
}

export function SSHTerminalDialog({ device, onClose }: SSHTerminalDialogProps) {
  const { t } = useI18n()
  return (
    <Dialog open={device !== null} onOpenChange={(open) => (open ? undefined : onClose())}>
      <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <SquareTerminal className="size-4 text-muted-foreground" aria-hidden="true" />
            {device ? t("{device} terminali", { device }) : "Terminal"}
          </DialogTitle>
          <DialogDescription>
            {t("Bağlantı tünel içinden kurulur; parola yalnızca bu oturumu açmak için bir kez gönderilir ve saklanmaz.")}
          </DialogDescription>
        </DialogHeader>
        {device ? <TerminalTabs key={device} device={device} terminal={<SSHSession device={device} />} /> : null}
      </DialogContent>
    </Dialog>
  )
}

type Phase = "form" | "connecting" | "ready" | "closed"

interface HostKeyNotice {
  status: HostKeyStatus
  fingerprint: string
}

interface KeyChanged {
  fingerprint: string
  pinned: string
}

// formError and failure hold a Turkish msg() text or a server message;
// both are shown through ts().
function SSHSession({ device }: { device: string }) {
  const { t, ts } = useI18n()
  const [user, setUser] = useState("")
  const [port, setPort] = useState("22")
  const [password, setPassword] = useState("")
  const [formError, setFormError] = useState("")
  const [phase, setPhase] = useState<Phase>("form")
  const [hostKey, setHostKey] = useState<HostKeyNotice | null>(null)
  const [keyChanged, setKeyChanged] = useState<KeyChanged | null>(null)
  const [failure, setFailure] = useState("")
  const [forgetting, setForgetting] = useState(false)
  const holder = useRef<HTMLDivElement>(null)
  const cleanup = useRef<(() => void) | null>(null)

  useEffect(() => () => cleanup.current?.(), [])

  const portNumber = Number.parseInt(port, 10)

  const start = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault()
      const name = user.trim()
      if (!/^[a-z_][a-z0-9_.-]{0,31}$/i.test(name)) {
        setFormError(msg("Geçerli bir kullanıcı adı girin."))
        return
      }
      if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
        setFormError(msg("Port 1 ile 65535 arasında olmalı."))
        return
      }
      if (!password) {
        setFormError(msg("Parola gerekli."))
        return
      }
      setFormError("")
      setFailure("")
      setKeyChanged(null)
      setHostKey(null)
      setPhase("connecting")
      let secret = password
      setPassword("")
      try {
        const open = await withReauth(() => postCoded<OpenAnswer>("/api/ssh/open", { device, port: portNumber, user: name }))
        const [{ Terminal: XTerm }, { FitAddon }] = await Promise.all([import("@xterm/xterm"), import("@xterm/addon-fit")])
        const el = holder.current
        if (!el) throw new Error(msg("Terminal alanı hazır değil."))
        const css = getComputedStyle(document.documentElement)
        const term: Terminal = new XTerm({
          cursorBlink: true,
          convertEol: false,
          fontFamily: css.getPropertyValue("--font-mono").trim() || "monospace",
          fontSize: 13,
          scrollback: 5000,
          theme: {
            background: css.getPropertyValue("--card").trim() || undefined,
            foreground: css.getPropertyValue("--foreground").trim() || undefined,
            cursor: css.getPropertyValue("--primary").trim() || undefined,
          },
        })
        const fit = new FitAddon()
        term.loadAddon(fit)
        term.open(el)
        fit.fit()

        const scheme = window.location.protocol === "https:" ? "wss" : "ws"
        const ws = new WebSocket(`${scheme}://${window.location.host}/api/ssh/ws?ticket=${encodeURIComponent(open.ticket)}`)
        ws.binaryType = "arraybuffer"
        const sendJSON = (v: unknown) => {
          if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(v))
        }
        ws.onopen = () => {
          sendJSON({ type: "auth", password: utf8Base64(secret), cols: term.cols, rows: term.rows })
          secret = ""
        }
        ws.onmessage = (ev: MessageEvent<ArrayBuffer | string>) => {
          if (typeof ev.data !== "string") {
            term.write(new Uint8Array(ev.data))
            return
          }
          const message = parseMessage(ev.data)
          if (!message) return
          switch (message.type) {
            case "hostkey":
              setHostKey({ status: message.status, fingerprint: message.fingerprint })
              break
            case "ready":
              setPhase("ready")
              term.focus()
              break
            case "exit":
              setPhase("closed")
              term.write(`\r\n[${tx("Oturum kapandı")}]\r\n`)
              break
            case "error":
              if (message.code === "host_key_changed") {
                setKeyChanged({ fingerprint: message.fingerprint ?? "-", pinned: message.pinned ?? "-" })
              } else {
                setFailure(errorText[message.code] ?? message.message ?? msg("Bağlantı kurulamadı."))
              }
              setPhase("closed")
              break
          }
        }
        ws.onclose = () => {
          secret = ""
          setPhase((p) => (p === "form" ? p : "closed"))
        }
        const dataSub = term.onData((d) => sendJSON({ type: "data", data: d }))
        const resize = () => {
          fit.fit()
          sendJSON({ type: "resize", cols: term.cols, rows: term.rows })
        }
        const observer = new ResizeObserver(resize)
        observer.observe(el)
        cleanup.current = () => {
          observer.disconnect()
          dataSub.dispose()
          ws.onclose = null
          ws.close()
          term.dispose()
        }
      } catch (err) {
        secret = ""
        setFailure(err instanceof Error && err.message ? err.message : msg("Bağlantı kurulamadı."))
        setPhase("closed")
      }
    },
    [device, password, portNumber, user]
  )

  async function forget() {
    setForgetting(true)
    try {
      await withReauth(() => postCoded("/api/ssh/hostkeys/forget", { host: `${device}:${portNumber}` }))
      setKeyChanged(null)
      setFailure(msg("Kayıt silindi. Bir sonraki bağlantıda yeni anahtar kaydedilecek; parmak izini cihazdakiyle karşılaştırın."))
    } catch (err) {
      setFailure(err instanceof Error && err.message ? err.message : msg("Kayıt silinemedi."))
    } finally {
      setForgetting(false)
    }
  }

  function reset() {
    cleanup.current?.()
    cleanup.current = null
    setPhase("form")
    setHostKey(null)
  }

  return (
    <div className="flex min-w-0 flex-col gap-4">
      {keyChanged ? (
        <Alert variant="destructive">
          <ShieldAlert />
          <AlertTitle>{t("Sunucu anahtarı değişti!")}</AlertTitle>
          <AlertDescription className="flex flex-col gap-3">
            <span className="break-all">
              {t("Kayıtlı:")} <span className="font-mono">{keyChanged.pinned}</span>, {t("gelen:")}{" "}
              <span className="font-mono">{keyChanged.fingerprint}</span>. {t("Ortadaki saldırı olabilir. Bağlantı kurulmadı.")}
            </span>
            <Button variant="outline" size="sm" className="w-fit" onClick={forget} disabled={forgetting}>
              {forgetting ? <Spinner data-icon="inline-start" /> : null}
              {t("Beklenen bir değişiklikse kaydı sil")}
            </Button>
          </AlertDescription>
        </Alert>
      ) : null}
      {failure ? (
        <Alert variant={keyChanged ? "default" : "destructive"}>
          <TriangleAlert />
          <AlertDescription>{ts(failure)}</AlertDescription>
        </Alert>
      ) : null}
      {hostKey && hostKey.status === "pinned" ? (
        <p role="status" className="flex items-start gap-2 rounded-lg border bg-muted/40 px-3 py-2 text-sm text-pretty">
          <KeyRound className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <span className="min-w-0 break-all">
            {t("Bu cihazın sunucu anahtarı ilk kez kaydedildi:")} <span className="font-mono">{hostKey.fingerprint}</span>
          </span>
        </p>
      ) : null}
      {hostKey && hostKey.status === "certified" ? (
        <p role="status" className="text-sm text-muted-foreground">{t("Sunucu anahtarı ağın sertifikasıyla doğrulandı.")}</p>
      ) : null}

      {phase === "form" ? (
        <form onSubmit={start} noValidate className="flex flex-col gap-5">
          <FieldGroup className="grid gap-4 sm:grid-cols-[1fr_7rem]">
            <Field>
              <FieldLabel htmlFor="ssh-user">{t("Kullanıcı adı")}</FieldLabel>
              <Input id="ssh-user" autoComplete="username" autoFocus value={user} maxLength={32} onChange={(e) => setUser(e.target.value)} />
            </Field>
            <Field>
              <FieldLabel htmlFor="ssh-port">Port</FieldLabel>
              <Input id="ssh-port" inputMode="numeric" value={port} maxLength={5} onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))} />
            </Field>
            <Field className="sm:col-span-2" data-invalid={formError ? true : undefined}>
              <FieldLabel htmlFor="ssh-password">{t("Parola")}</FieldLabel>
              <Input
                id="ssh-password"
                type="password"
                autoComplete="current-password"
                value={password}
                maxLength={1024}
                onChange={(e) => setPassword(e.target.value)}
                aria-invalid={formError ? true : undefined}
              />
              <FieldError>{formError ? ts(formError) : null}</FieldError>
              <FieldDescription>{t("Beş hatalı denemeden sonra bu bilgisayar 15 dakika engellenir.")}</FieldDescription>
            </Field>
          </FieldGroup>
          <Button type="submit" className="w-fit">
            {t("Bağlan")}
          </Button>
        </form>
      ) : null}

      <div
        ref={holder}
        aria-label="Terminal"
        className={phase === "form" ? "hidden" : "h-[60vh] min-h-64 overflow-hidden rounded-lg border bg-card p-2"}
      />
      {phase === "connecting" ? (
        <p className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
          <Spinner /> {t("Bağlanıyor…")}
        </p>
      ) : null}
      {phase === "closed" ? (
        <Button variant="outline" className="w-fit" onClick={reset}>
          {t("Yeniden bağlan")}
        </Button>
      ) : null}
    </div>
  )
}
