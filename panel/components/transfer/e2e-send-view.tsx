"use client"

import { useState } from "react"
import useSWR from "swr"
import { ArrowDownLeft, ArrowUpRight, FileUp, LockKeyhole, TriangleAlert } from "lucide-react"
import { toast } from "sonner"

import { useReadOnly } from "@/components/app/read-only"
import { CodedError, codedError, optionalGet, postCoded } from "@/components/auth/strict-api"
import { withReauth } from "@/components/auth/reauth"
import { PageHeader } from "@/components/page-header"
import { EmptyNote, SettingRow, SettingsSection } from "@/components/settings/settings-layout"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { errorMessage, fetcher } from "@/lib/api"
import { formatBytes, formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { DevicesResponse } from "@/lib/types"
import { cn } from "@/lib/utils"

// End-to-end encrypted file sending (ADR-0204): the file, its name and size
// are sealed to the receiving device's key; the coordinator, relays and
// onion hops see none of it.

export interface E2ETransfer {
  id: string
  outgoing: boolean
  peer: string
  name: string
  size: number
  done: number
  state: "waiting" | "sending" | "receiving" | "done" | "failed"
  path?: "direct" | "onion"
  hops?: number
  resumed?: number
  error?: string
  started: string
  finished?: string
  stripped?: boolean
  quarantined?: boolean
}

export interface E2EOffer {
  id: string
  from: string
  name: string
  size: number
  executable: boolean
  resume: boolean
  stripped: boolean
  at: string
}

interface E2EView {
  transfers: E2ETransfer[] | null
  pending: E2EOffer[] | null
  relay: boolean
}

const stateText: Record<E2ETransfer["state"], string> = {
  waiting: msg("Onay bekleniyor"),
  sending: msg("Gönderiliyor"),
  receiving: msg("Alınıyor"),
  done: msg("Tamamlandı"),
  failed: msg("Başarısız"),
}

type Route = "auto" | "direct" | "onion"

const routeText: Record<Route, string> = {
  auto: msg("Otomatik (önce doğrudan)"),
  direct: msg("Yalnızca doğrudan"),
  onion: msg("Ara cihazlar üzerinden (soğan)"),
}

export function E2ESendView() {
  const { t } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<E2EView | null>("/api/app/e2e", optionalGet, {
    refreshInterval: (latest) => {
      const busy = (latest?.transfers ?? []).some((x) => x.state !== "done" && x.state !== "failed") || (latest?.pending ?? []).length > 0
      return busy ? 1_000 : 5_000
    },
  })

  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        title={t("Uçtan uca dosya gönder")}
        description={t("Dosya, adı ve boyutu yalnızca alıcı cihazın açabileceği şekilde şifrelenir. Koordinatör, aktarıcılar ve ara cihazlar içeriği göremez.")}
      />
      {isLoading ? (
        <div className="flex flex-col gap-4" aria-busy="true" aria-label={t("Yükleniyor")}>
          <Skeleton className="h-40 w-full" />
          <Skeleton className="h-24 w-full" />
        </div>
      ) : error ? (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertTitle>{t("Aktarım durumu okunamadı")}</AlertTitle>
          <AlertDescription className="flex flex-col gap-2">
            <span>{errorMessage(error)}</span>
            <Button variant="outline" size="sm" className="w-fit" onClick={() => mutate()}>
              {t("Tekrar dene")}
            </Button>
          </AlertDescription>
        </Alert>
      ) : data === null || data === undefined ? (
        <EmptyNote>{t("Bu sürümde uçtan uca dosya gönderimi yok. Masaüstü uygulamasını güncelleyin.")}</EmptyNote>
      ) : (
        <>
          {(data.pending ?? []).map((o) => (
            <OfferCard key={o.id} offer={o} onDone={() => mutate()} />
          ))}
          <SendForm onSent={() => mutate()} />
          <TransferList transfers={data.transfers ?? []} />
          <RelaySetting relay={data.relay} onChange={() => mutate()} />
        </>
      )}
    </div>
  )
}

function OfferCard({ offer, onDone }: { offer: E2EOffer; onDone: () => void }) {
  const { t } = useI18n()
  const [busy, setBusy] = useState<"yes" | "no" | null>(null)
  async function decide(accept: boolean) {
    setBusy(accept ? "yes" : "no")
    try {
      await postCoded("/api/app/e2e/decide", { id: offer.id, accept })
    } catch (err) {
      if (!(err instanceof CodedError && err.status === 404)) toast.error(err instanceof Error ? errorMessage(err) : t("Karar gönderilemedi."))
    } finally {
      setBusy(null)
      onDone()
    }
  }
  return (
    <section
      aria-label={t("Gelen dosya teklifi")}
      className={cn("flex flex-col gap-3 rounded-lg border p-4", offer.executable && "border-destructive/50")}
    >
      <p className="text-sm text-pretty">
        {t("{from} size {name} ({size}) göndermek istiyor.", { from: offer.from, name: offer.name, size: formatBytes(offer.size) })}
      </p>
      {offer.executable ? (
        <p className="flex items-center gap-2 text-sm font-medium text-destructive">
          <TriangleAlert className="size-4 shrink-0" aria-hidden="true" />
          {t("Bu dosya açıldığında kod çalıştırabilir.")}
        </p>
      ) : null}
      {offer.resume ? <p className="text-sm text-muted-foreground">{t("Yarım kalan aktarım sürdürülecek.")}</p> : null}
      <p className="text-xs text-muted-foreground">{t("Kabul edilen dosya önce karantinaya alınır.")}</p>
      <div className="flex gap-2">
        <Button size="sm" onClick={() => decide(true)} disabled={busy !== null}>
          {busy === "yes" ? <Spinner data-icon="inline-start" /> : null}
          {t("Kabul et")}
        </Button>
        <Button size="sm" variant="outline" onClick={() => decide(false)} disabled={busy !== null}>
          {busy === "no" ? <Spinner data-icon="inline-start" /> : null}
          {t("Reddet")}
        </Button>
      </div>
    </section>
  )
}

// Neither a browser nor the desktop window tells the page where a dropped
// file lives, so its bytes are staged once over loopback; the service keeps
// them in a private folder and answers with the full path to send
// (internal/panel/w5_e2e_upload.go). Metadata is still removed when sent.
const maxStageBytes = 2 * 1024 ** 3

async function stageFile(file: File): Promise<string> {
  if (file.size > maxStageBytes) throw new Error(msg("Dosya bırakarak gönderilemeyecek kadar büyük (en çok 2 GiB); tam yolunu yazın."))
  const session = await fetch("/api/session", { credentials: "same-origin", cache: "no-store" })
  if (!session.ok) throw await codedError(session)
  const { csrfToken } = (await session.json()) as { csrfToken?: unknown }
  if (typeof csrfToken !== "string") throw new Error(msg("Oturum bilgisi okunamadı."))
  const res = await fetch("/api/app/e2e/upload", {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      "Content-Type": "application/octet-stream",
      "X-CSRF-Token": csrfToken,
      "X-OpenScale-File-Name": encodeURIComponent(file.name),
    },
    body: file,
  })
  if (!res.ok) throw await codedError(res)
  const data = (await res.json()) as { path?: unknown }
  if (typeof data.path !== "string" || data.path.length === 0) throw new Error(msg("Dosya hazırlanamadı."))
  return data.path
}

function SendForm({ onSent }: { onSent: () => void }) {
  const { t } = useI18n()
  const readOnly = useReadOnly()
  const { data: devices } = useSWR<DevicesResponse>("/api/devices", fetcher, { shouldRetryOnError: false })
  const names = (devices?.devices ?? []).filter((d) => !d.thisComputer).map((d) => d.name)
  const [device, setDevice] = useState("")
  const [path, setPath] = useState("")
  const [route, setRoute] = useState<Route>("auto")
  const [hops, setHops] = useState<string[]>([])
  const [strip, setStrip] = useState(true)
  const [error, setError] = useState("")
  const [dropNote, setDropNote] = useState("")
  const [dragging, setDragging] = useState(false)
  const [staging, setStaging] = useState(false)
  const [busy, setBusy] = useState(false)

  async function takeFile(file: File | undefined) {
    if (!file) return
    if (readOnly) return setDropNote(t("Bu oturum salt okunur; dosya gönderilemez."))
    setStaging(true)
    setDropNote(t("{name} hazırlanıyor…", { name: file.name }))
    try {
      setPath(await stageFile(file))
      setDropNote(t("{name} ({size}) gönderime hazır.", { name: file.name, size: formatBytes(file.size) }))
      setError("")
    } catch (err) {
      setDropNote(err instanceof Error ? errorMessage(err) : t("Dosya hazırlanamadı."))
    } finally {
      setStaging(false)
    }
  }

  function toggleHop(name: string, on: boolean) {
    setHops((prev) => (on ? (prev.includes(name) || prev.length >= 3 ? prev : [...prev, name]) : prev.filter((h) => h !== name)))
  }

  async function send(e: React.FormEvent) {
    e.preventDefault()
    if (!device.trim()) return setError(t("Alıcı cihazı seçin."))
    if (!path.trim()) return setError(t("Dosyanın tam yolunu girin veya dosyayı bırakın."))
    if (route === "onion" && (hops.length < 2 || hops.length > 3)) return setError(t("Soğan yolu için 2 ile 3 arası ara cihaz seçin."))
    setError("")
    setBusy(true)
    try {
      const body: Record<string, unknown> = { device: device.trim(), path: path.trim(), route, keep_metadata: !strip }
      if (route === "onion") body.hops = hops
      await withReauth(() => postCoded("/api/app/e2e/send", body))
      toast.success(t("Gönderim başladı; alıcının onayı bekleniyor."))
      setPath("")
      onSent()
    } catch (err) {
      setError(err instanceof Error ? errorMessage(err) : t("Gönderim başlatılamadı."))
    } finally {
      setBusy(false)
    }
  }

  const hopCandidates = names.filter((n) => n !== device)

  return (
    <SettingsSection id="gonder" title={t("Gönder")}>
      <form onSubmit={send} noValidate className="flex flex-col gap-6 rounded-lg border p-4" data-slot="card">
        <div
          onDragOver={(e) => {
            e.preventDefault()
            setDragging(true)
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault()
            setDragging(false)
            void takeFile(e.dataTransfer.files[0])
          }}
          className={cn(
            "flex flex-col items-center gap-2 rounded-lg border border-dashed px-4 py-8 text-center text-sm text-muted-foreground transition-colors duration-150",
            dragging && "border-primary bg-primary/5 text-foreground"
          )}
        >
          {staging ? <Spinner className="size-5" /> : <FileUp className="size-5" aria-hidden="true" />}
          <p>{t("Dosyayı buraya bırakın")}</p>
          <label className={cn("cursor-pointer text-xs font-medium text-foreground underline underline-offset-4", (staging || readOnly) && "pointer-events-none opacity-50")}>
            {t("veya bilgisayardan seçin")}
            <input
              type="file"
              className="sr-only"
              disabled={staging || readOnly}
              onChange={(e) => {
                void takeFile(e.target.files?.[0])
                e.target.value = ""
              }}
            />
          </label>
          <p className="text-xs text-pretty" role="status" aria-live="polite">
            {dropNote}
          </p>
        </div>

        <FieldGroup className="grid gap-4 md:grid-cols-2">
          <Field>
            <FieldLabel htmlFor="e2e-device">{t("Alıcı cihaz")}</FieldLabel>
            <Input id="e2e-device" list="e2e-device-list" value={device} maxLength={63} onChange={(e) => setDevice(e.target.value)} />
            <datalist id="e2e-device-list">
              {names.map((n) => (
                <option key={n} value={n} />
              ))}
            </datalist>
          </Field>
          <Field>
            <FieldLabel htmlFor="e2e-path">{t("Dosyanın tam yolu")}</FieldLabel>
            <Input id="e2e-path" value={path} maxLength={4096} placeholder={t("C:\\Users\\ayse\\Belgeler\\rapor.pdf")} onChange={(e) => setPath(e.target.value)} />
          </Field>
        </FieldGroup>

        <FieldSet>
          <FieldLegend variant="label">{t("Yol")}</FieldLegend>
          <div className="flex flex-col gap-2 sm:flex-row" role="radiogroup" aria-label={t("Yol")}>
            {(Object.keys(routeText) as Route[]).map((r) => (
              <label
                key={r}
                className="flex flex-1 cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 text-sm has-checked:border-primary has-checked:bg-primary/5 has-focus-visible:ring-3 has-focus-visible:ring-ring/50"
              >
                <input type="radio" name="e2e-route" value={r} checked={route === r} onChange={() => setRoute(r)} className="accent-primary" />
                {t(routeText[r])}
              </label>
            ))}
          </div>
          {route === "onion" ? (
            <div className="flex flex-col gap-3">
              <FieldDescription>{t("En az iki ara cihaz gerekir; böylece hiçbir ara cihaz göndereni ve alıcıyı birlikte bilmez.")}</FieldDescription>
              {hopCandidates.length === 0 ? (
                <p className="text-sm text-muted-foreground">{t("Ara cihaz olabilecek cihaz listelenemedi.")}</p>
              ) : (
                <div className="grid gap-2 sm:grid-cols-3">
                  {hopCandidates.map((n) => (
                    <Field key={n} orientation="horizontal">
                      <Checkbox
                        id={`e2e-hop-${n}`}
                        checked={hops.includes(n)}
                        disabled={!hops.includes(n) && hops.length >= 3}
                        onCheckedChange={(v) => toggleHop(n, v === true)}
                      />
                      <FieldLabel htmlFor={`e2e-hop-${n}`} className="font-normal">
                        {n}
                        {hops.includes(n) ? <span className="text-xs text-muted-foreground tabular-nums">{t("{n}. sıra", { n: hops.indexOf(n) + 1 })}</span> : null}
                      </FieldLabel>
                    </Field>
                  ))}
                </div>
              )}
            </div>
          ) : null}
        </FieldSet>

        <Field orientation="horizontal">
          <Switch id="e2e-strip" checked={strip} onCheckedChange={(v) => setStrip(v === true)} />
          <div className="flex flex-col gap-0.5">
            <FieldLabel htmlFor="e2e-strip" className="font-normal">
              {t("Konum, yazar ve üretici bilgisini temizle (önerilir)")}
            </FieldLabel>
            {strip ? null : <span className="text-xs text-warning-foreground dark:text-warning">{t("Dosya üst verisiyle birlikte gönderilecek.")}</span>}
          </div>
        </Field>

        <FieldError>{error}</FieldError>
        <div className="flex items-center gap-3">
          <Button type="submit" disabled={busy || staging || readOnly}>
            {busy ? <Spinner data-icon="inline-start" /> : <LockKeyhole data-icon="inline-start" />}
            {t("Şifreli gönder")}
          </Button>
          {readOnly ? <span className="text-sm text-muted-foreground">{t("Salt okunur panelde gönderim kapalı.")}</span> : null}
        </div>
      </form>
    </SettingsSection>
  )
}

function TransferList({ transfers }: { transfers: E2ETransfer[] }) {
  const { t } = useI18n()
  return (
    <SettingsSection id="aktarimlar" title={t("Aktarımlar")}>
      {transfers.length === 0 ? (
        <EmptyNote>{t("Henüz aktarım yok. Gönderdiğiniz ve aldığınız dosyalar burada ilerlemesiyle görünür.")}</EmptyNote>
      ) : (
        <ul className="flex flex-col divide-y rounded-lg border" data-slot="card">
          {transfers.map((item) => (
            <TransferRow key={item.id} t={item} />
          ))}
        </ul>
      )}
    </SettingsSection>
  )
}

function TransferRow({ t: item }: { t: E2ETransfer }) {
  const { t, ts } = useI18n()
  const pct = item.size > 0 ? Math.min(100, Math.round((item.done / item.size) * 100)) : item.state === "done" ? 100 : 0
  const active = item.state === "sending" || item.state === "receiving"
  return (
    <li className="flex flex-col gap-2 px-4 py-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
        {item.outgoing ? (
          <ArrowUpRight className="size-4 text-muted-foreground" aria-label={t("Giden")} />
        ) : (
          <ArrowDownLeft className="size-4 text-muted-foreground" aria-label={t("Gelen")} />
        )}
        <span className="min-w-0 flex-1 truncate font-medium" title={item.name}>
          {item.name}
        </span>
        <span className="text-muted-foreground">{item.peer}</span>
        {item.path ? (
          <span className="rounded-md bg-secondary px-1.5 py-0.5 text-xs text-muted-foreground">
            {item.path === "onion" ? t("Soğan ({count} ara cihaz)", { count: item.hops ?? 0 }) : t("Doğrudan")}
          </span>
        ) : null}
      </div>
      <div className="flex items-center gap-3">
        <div
          role="progressbar"
          aria-label={t("{name} ilerlemesi", { name: item.name })}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={pct}
          className="h-1.5 flex-1 overflow-hidden rounded-full bg-secondary"
        >
          <div
            className={cn("h-full rounded-full transition-[width] duration-300", item.state === "failed" ? "bg-destructive" : "bg-primary", active && "bg-primary")}
            style={{ width: `${pct}%` }}
          />
        </div>
        <span className="w-28 shrink-0 text-right text-xs text-muted-foreground tabular-nums">
          {formatBytes(item.done)} / {formatBytes(item.size)}
        </span>
      </div>
      <p className={cn("text-xs", item.state === "failed" ? "text-destructive" : "text-muted-foreground")}>
        {item.state === "failed"
          ? item.error
            ? t("Başarısız: {error}", { error: ts(item.error) })
            : t("Başarısız: bilinmeyen hata")
          : t(stateText[item.state])}
        {item.resumed ? ` · ${t("sürdürüldü")}` : ""}
        {item.stripped ? ` · ${t("üst veri temizlendi")}` : ""}
        {item.quarantined ? ` · ${t("karantinada")}` : ""}
        {" · "}
        {formatDateTime(item.started)}
      </p>
    </li>
  )
}

function RelaySetting({ relay, onChange }: { relay: boolean; onChange: () => void }) {
  const { t } = useI18n()
  const readOnly = useReadOnly()
  const [busy, setBusy] = useState(false)
  return (
    <SettingsSection id="ara-cihaz" /* i18n-ignore: sayfa içi bağlantı kimliği */ title={t("Ara cihaz")}>
      <div className="rounded-lg border px-4" data-slot="card">
        <SettingRow
          title={t("Bu cihaz başkalarının şifreli aktarımlarını iletsin (içeriği göremez)")}
          description={t("Soğan yolunda bu cihaz bir halka olur. Yalnızca önceki ve sonraki cihazı bilir; dosyanın adını, boyutunu ve içeriğini göremez.")}
          htmlFor="e2e-relay"
          action={
            <Switch
              id="e2e-relay"
              checked={relay}
              disabled={busy || readOnly}
              onCheckedChange={async (v) => {
                setBusy(true)
                try {
                  await postCoded("/api/app/e2e/relay", { enabled: v === true })
                  onChange()
                } catch (err) {
                  toast.error(err instanceof Error ? errorMessage(err) : t("Ayar kaydedilemedi."))
                } finally {
                  setBusy(false)
                }
              }}
            />
          }
        />
      </div>
    </SettingsSection>
  )
}
