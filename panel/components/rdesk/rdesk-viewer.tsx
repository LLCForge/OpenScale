"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { ClipboardPaste, MonitorOff, TriangleAlert } from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { MonitorPicker, type RemoteMonitor } from "@/components/rdesk/f3-monitor-picker"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"

// Remote desktop viewer window (internal/panel/w1_rdesk_viewer.go). The
// connect dialog opens this page with a one-time ticket in the URL
// fragment, which never reaches a server log; the page removes it at once
// and opens the same-origin WebSocket. Frames arrive as JPEG binary
// messages; pointer, wheel and keys go back as small JSON messages, only
// while the session may send input.

interface ReadyMessage {
  type: "ready"
  device?: string
  mode?: string
  input?: boolean
  code?: string
  recorded?: boolean
  monitors?: RemoteMonitor[]
  selected?: number
}

interface MonitorsMessage {
  type: "monitors"
  monitors?: RemoteMonitor[]
  selected?: number
}

interface ExitMessage {
  type: "exit"
  message?: string
}

type ViewerMessage = ReadyMessage | ExitMessage | MonitorsMessage

type Phase = "connecting" | "live" | "ended" | "missing"

function parseMessage(text: string): ViewerMessage | null {
  try {
    const data: unknown = JSON.parse(text)
    if (data && typeof data === "object" && "type" in data && (data.type === "ready" || data.type === "exit" || data.type === "monitors")) return data as ViewerMessage
  } catch {
    // Not JSON.
  }
  return null
}

function takeTicket(): string {
  const match = /^#t=([A-Za-z0-9_-]{16,128})$/.exec(window.location.hash)
  if (!match) return ""
  window.history.replaceState(null, "", window.location.pathname)
  return match[1]
}

export function RDeskViewer() {
  const { t, ts } = useI18n()
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const buttonsRef = useRef(0)
  const [phase, setPhase] = useState<Phase>("connecting")
  const [info, setInfo] = useState<ReadyMessage | null>(null)
  const [endText, setEndText] = useState("")
  const [notice, setNotice] = useState("")
  const [monitors, setMonitors] = useState<{ list: RemoteMonitor[]; selected?: number }>({ list: [] })

  useEffect(() => {
    const ticket = takeTicket()
    if (!ticket) {
      // Reported after the effect so the first render stays the same.
      queueMicrotask(() => setPhase("missing"))
      return
    }
    const scheme = window.location.protocol === "https:" ? "wss:" : "ws:"
    const ws = new WebSocket(`${scheme}//${window.location.host}/api/rdesk/ws?ticket=${encodeURIComponent(ticket)}`)
    ws.binaryType = "arraybuffer"
    wsRef.current = ws
    let drawing = false
    let pending: ArrayBuffer | null = null
    let ended = false

    async function draw(buf: ArrayBuffer) {
      drawing = true
      try {
        const bitmap = await createImageBitmap(new Blob([buf], { type: "image/jpeg" }))
        const canvas = canvasRef.current
        if (canvas) {
          if (canvas.width !== bitmap.width || canvas.height !== bitmap.height) {
            canvas.width = bitmap.width
            canvas.height = bitmap.height
          }
          canvas.getContext("2d")?.drawImage(bitmap, 0, 0)
        }
        bitmap.close()
      } catch {
        // A frame that cannot be decoded is skipped; the next one repaints.
      }
      drawing = false
      if (pending) {
        const next = pending
        pending = null
        void draw(next)
      }
    }

    ws.onmessage = (ev: MessageEvent<ArrayBuffer | string>) => {
      if (typeof ev.data !== "string") {
        // Only the newest frame matters while the previous one decodes.
        if (drawing) pending = ev.data
        else void draw(ev.data)
        return
      }
      const message = parseMessage(ev.data)
      if (!message) return
      if (message.type === "monitors") {
        setMonitors({ list: message.monitors ?? [], selected: message.selected })
        return
      }
      if (message.type === "ready") {
        setMonitors({ list: message.monitors ?? [], selected: message.selected })
        setInfo(message)
        setPhase("live")
        document.title = `${message.device ?? tx("Uzak masaüstü")} · OpenScale`
        canvasRef.current?.focus()
      } else {
        ended = true
        // A server text or our own; both are translated with ts() when shown.
        setEndText(message.message ?? msg("Oturum kapandı."))
        setPhase("ended")
      }
    }
    ws.onclose = () => {
      if (!ended) {
        setEndText(msg("Bağlantı kapandı. Bilet bir dakika geçerlidir; panelden yeniden bağlanın."))
        setPhase("ended")
      }
    }
    return () => {
      ended = true
      ws.close()
      wsRef.current = null
    }
  }, [])

  const canInput = phase === "live" && info?.input === true

  const send = useCallback(
    (payload: Record<string, unknown>) => {
      const ws = wsRef.current
      if (!canInput || !ws || ws.readyState !== WebSocket.OPEN) return
      ws.send(JSON.stringify(payload))
    },
    [canInput],
  )

  function point(e: React.PointerEvent<HTMLCanvasElement>) {
    const canvas = e.currentTarget
    const rect = canvas.getBoundingClientRect()
    if (rect.width === 0 || rect.height === 0) return null
    return {
      x: Math.round(((e.clientX - rect.left) / rect.width) * canvas.width),
      y: Math.round(((e.clientY - rect.top) / rect.height) * canvas.height),
    }
  }

  function pointer(e: React.PointerEvent<HTMLCanvasElement>) {
    const p = point(e)
    if (!p) return
    // DOM buttons: 1 left, 2 right, 4 middle; the protocol uses the same bits.
    buttonsRef.current = e.buttons & 7
    send({ type: "pointer", x: p.x, y: p.y, buttons: buttonsRef.current })
  }

  function key(e: React.KeyboardEvent<HTMLCanvasElement>, down: boolean) {
    if (!canInput) return
    e.preventDefault()
    send({ type: "key", code: e.code, down })
  }

  function wheel(e: React.WheelEvent<HTMLCanvasElement>) {
    if (!canInput) return
    const dy = Math.sign(-e.deltaY)
    const dx = Math.sign(e.deltaX)
    if (dx !== 0 || dy !== 0) send({ type: "wheel", dx, dy })
  }

  async function pasteClipboard() {
    setNotice("")
    try {
      const text = await navigator.clipboard.readText()
      if (text.length > 8192) {
        setNotice(msg("Pano metni çok uzun; en çok 8 KB gönderilebilir."))
        return
      }
      send({ type: "clipboard", data: text })
      setNotice(msg("Pano metni karşıya gönderildi. Karşı cihaz pano iznini vermediyse yok sayılır."))
    } catch {
      setNotice(msg("Pano okunamadı. Tarayıcı izni gerekiyor olabilir."))
    }
  }

  function disconnect() {
    const ws = wsRef.current
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "close" }))
    else window.close()
  }

  return (
    <main className="flex min-h-dvh flex-col bg-background text-foreground">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <h1 className="truncate text-sm font-medium">{info?.device ? t("{device} uzak masaüstü", { device: info.device }) : t("Uzak masaüstü")}</h1>
          {phase === "live" ? (
            <Badge variant="secondary">{info?.input ? t("Yönetiliyor") : t("Yalnızca izleniyor")}</Badge>
          ) : null}
          {info?.recorded ? <Badge variant="outline">{t("Karşı cihaz kaydediyor")}</Badge> : null}
          {phase === "live" ? (
            <MonitorPicker
              monitors={monitors.list}
              selected={monitors.selected}
              onSelect={(index) => {
                const ws = wsRef.current
                if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "monitor", index }))
              }}
            />
          ) : null}
          {info?.code ? (
            <span className="text-xs text-muted-foreground">
              {t("Doğrulama kodu")} <span className="font-mono tabular-nums text-foreground">{info.code}</span>
            </span>
          ) : null}
        </div>
        <div className="flex items-center gap-2">
          {canInput ? (
            <Button variant="outline" size="sm" onClick={() => void pasteClipboard()}>
              <ClipboardPaste data-icon="inline-start" />
              {t("Panomu gönder")}
            </Button>
          ) : null}
          <Button variant="destructive" size="sm" onClick={disconnect} disabled={phase !== "live"}>
            <MonitorOff data-icon="inline-start" />
            {t("Bağlantıyı kes")}
          </Button>
        </div>
      </header>

      {notice ? (
        <p role="status" className="border-b px-4 py-2 text-xs text-muted-foreground">
          {t(notice)}
        </p>
      ) : null}

      <section aria-label={t("Uzak ekran")} className="relative flex flex-1 items-center justify-center overflow-hidden bg-muted p-2">
        {phase === "connecting" ? (
          <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground">
            <Spinner />
            {t("Görüntü bekleniyor...")}
          </p>
        ) : null}
        {phase === "missing" || phase === "ended" ? (
          <Alert className="max-w-md">
            <TriangleAlert />
            <AlertTitle>{phase === "missing" ? t("Görüntüleyici bileti yok") : t("Oturum bitti")}</AlertTitle>
            <AlertDescription>
              {phase === "missing" ? t('Bu pencereyi cihaz sayfasındaki "Uzak masaüstüne bağlan" düğmesiyle açın.') : ts(endText)}
            </AlertDescription>
          </Alert>
        ) : null}
        <canvas
          ref={canvasRef}
          tabIndex={0}
          aria-label={canInput ? t("Uzak ekran; klavye ve fare karşıya gönderilir") : t("Uzak ekran")}
          hidden={phase !== "live"}
          className="max-h-full max-w-full rounded-sm object-contain outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
          onPointerMove={canInput ? pointer : undefined}
          onPointerDown={(e) => {
            e.currentTarget.focus()
            if (canInput) pointer(e)
          }}
          onPointerUp={canInput ? pointer : undefined}
          onContextMenu={(e) => {
            if (canInput) e.preventDefault()
          }}
          onWheel={wheel}
          onKeyDown={(e) => key(e, true)}
          onKeyUp={(e) => key(e, false)}
        />
      </section>
    </main>
  )
}
