"use client"

import { useRef, useState } from "react"
import useSWR from "swr"
import { Activity, Fingerprint, Gauge, Power, Send, Terminal, Upload } from "lucide-react"
import { toast } from "sonner"

import { Writable } from "@/components/app/read-only"
import { CopyButton } from "@/components/copy-field"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { errorMessage, post } from "@/lib/api"
import {
  MAX_UPLOAD_BYTES,
  openSSHCommand,
  optionalFetcher,
  sshCommand,
  uploadFile,
  type RemoteDevice,
  type SpeedResult,
  type TransferStatus,
  type WakeResult,
} from "@/lib/apps"
import { formatBytes } from "@/lib/format"
import { tx, useI18n } from "@/lib/i18n/i18n"
import { queueFile } from "@/lib/wave2"
import { cn } from "@/lib/utils"

/**
 * What this computer may do with another device over the tunnel (ADR-0030,
 * ADR-0031): SSH, send a file, wake it and run a speed test. Only shown in
 * the desktop app; the rules decide each action on the other device.
 */
export function RemoteActionsCard({ device, className, bare }: { device: string; className?: string; bare?: boolean }) {
  const { t } = useI18n()
  const key = device ? `/api/app/remote?device=${encodeURIComponent(device)}` : null
  const { data, error, mutate } = useSWR<RemoteDevice | null>(key, optionalFetcher, { refreshInterval: 15_000 })
  if (data === null) return null
  if (bare) {
    // Only the actions, as rows; the page gives the title (device detail).
    if (error) return <p className="py-4 text-sm text-muted-foreground">{errorMessage(error)}</p>
    if (!data) return <Spinner className="my-4" />
    return (
      <div className="flex flex-col divide-y [&>section]:py-4">
        <SSHSection device={data} />
        <SendSection device={data} />
        <WakeSection device={data} onChange={() => mutate()} />
        <SpeedSection device={data} />
      </div>
    )
  }
  return (
    <Card id="uzak-erisim" className={cn("scroll-mt-24", className)}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Terminal className="size-4 text-muted-foreground" />
          {t("Uzak erişim ve tanı")}
        </CardTitle>
        <CardDescription className="text-pretty">
          {t(
            "Bu bilgisayardan {device} cihazına tünel içinden yapılabilecekler. Karşı cihaz her isteği imzalı kurallara göre kendisi denetler; koordinatör hiçbirini görmez.",
            { device }
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {error ? (
          <p className="text-sm text-muted-foreground">{errorMessage(error)}</p>
        ) : !data ? (
          <Spinner />
        ) : (
          <div className="grid gap-6 md:grid-cols-2">
            <SSHSection device={data} />
            <SendSection device={data} />
            <WakeSection device={data} onChange={() => mutate()} />
            <SpeedSection device={data} />
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function Section({ icon: Icon, title, children }: { icon: React.ComponentType<{ className?: string }>; title: string; children: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-2.5">
      <h3 className="flex items-center gap-1.5 text-sm font-medium">
        <Icon className="size-4 text-muted-foreground" />
        {title}
      </h3>
      {children}
    </section>
  )
}

function Muted({ children }: { children: React.ReactNode }) {
  return <p className="text-sm leading-relaxed text-muted-foreground text-pretty">{children}</p>
}

function CommandLine({ value, label }: { value: string; label: string }) {
  return (
    <div className="flex items-center gap-1 rounded-lg border bg-muted/40 px-3 py-1.5">
      <code className="min-w-0 flex-1 font-mono text-xs break-all">{value}</code>
      <CopyButton value={value} label={label} />
    </div>
  )
}

function SSHSection({ device }: { device: RemoteDevice }) {
  const { t } = useI18n()
  const allowed = device.sshUsers.length > 0 || device.sshRoot
  return (
    <Section icon={Terminal} title="SSH">
      {allowed ? (
        <>
          <div className="flex flex-wrap items-center gap-1.5">
            {device.sshUsers.map((u) => (
              <Badge key={u} variant="secondary" className="font-mono">
                {u}
              </Badge>
            ))}
            {device.sshRoot ? <Badge variant="destructive">root</Badge> : null}
            {device.sshForward ? <Badge variant="outline">{t("port yönlendirme")}</Badge> : null}
          </div>
          <CommandLine value={sshCommand(device)} label={t("SSH komutunu kopyala")} />
          <Muted>
            {t("OpenSSH ile:")} <code className="font-mono text-xs">{openSSHCommand(device)}</code>.{" "}
            {t("İlk bağlantıda aşağıdaki parmak izini karşılaştır.")}
          </Muted>
        </>
      ) : (
        <Muted>{t("Bu bilgisayarın bu cihaza SSH ile girmesine izin veren bir ssh kuralı yok.")}</Muted>
      )}
      <div className="flex flex-col gap-1">
        <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Fingerprint className="size-3.5" />
          {t("SSH host anahtarı parmak izi")}
        </span>
        {device.sshFingerprint ? (
          <CommandLine value={device.sshFingerprint} label={t("Parmak izini kopyala")} />
        ) : (
          <Muted>{t("Bilinmiyor: cihaz açıkken ve SSH sunucusu bir kez çalıştıktan sonra envanterle (yönetici bilgisayarda) gelir.")}</Muted>
        )}
      </div>
    </Section>
  )
}

function SendSection({ device }: { device: RemoteDevice }) {
  const { t, ts } = useI18n()
  const input = useRef<HTMLInputElement>(null)
  const [busy, setBusy] = useState(false)
  // Metadata removal (#139) and the offline queue (#140, ADR-0104).
  const [strip, setStrip] = useState(false)
  const [wait, setWait] = useState(false)
  const { data: transfers, mutate } = useSWR<TransferStatus[] | null>("/api/app/transfers", optionalFetcher, {
    refreshInterval: (latest) => (latest?.some((tf) => tf.state === "sending") ? 1_000 : 10_000),
  })
  const mine = (transfers ?? []).filter((tf) => tf.device === device.name).slice(0, 3)

  async function onPick(file: File | undefined) {
    if (!file) return
    if (file.size === 0 || file.size > MAX_UPLOAD_BYTES) {
      toast.error(tx("Panelden en fazla 2 GiB'lık dosya gönderilebilir; daha büyükleri için: openscale send"))
      return
    }
    setBusy(true)
    try {
      if (strip || wait) {
        await queueFile(device.name, file, strip ? "location" : "")
        toast.success(
          tx("{name} kuyruğa alındı; {device} ulaşılabilir olunca gönderilecek (Eşitleme ve Yedek sayfası).", { name: file.name, device: device.name })
        )
      } else {
        await uploadFile(device.name, file)
        toast.success(tx("{name} gönderiliyor; {device} cihazında kabul edilmesi bekleniyor.", { name: file.name, device: device.name }))
      }
      await mutate()
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
      if (input.current) input.current.value = ""
    }
  }

  return (
    <Section icon={Send} title={t("Dosya gönder")}>
      {device.canSend ? (
        <>
          <Muted>{t("Dosya karşı cihazın gelen kutusuna gider; orada kabul edilmesi gerekir (otomatik kabul açık değilse).")}</Muted>
          <Writable>
            <input ref={input} type="file" className="sr-only" aria-label={t("Gönderilecek dosya")} onChange={(e) => onPick(e.target.files?.[0])} />
            <label className="flex items-center gap-2 text-xs">
              <Checkbox checked={strip} onCheckedChange={(c) => setStrip(c === true)} />
              {t("Fotoğraflardan konum bilgisini temizle (temizlenemeyen biçim gönderilmez)")}
            </label>
            <label className="flex items-center gap-2 text-xs">
              <Checkbox checked={wait} onCheckedChange={(c) => setWait(c === true)} />
              {t("Çevrimdışıysa çevrimiçi olunca gönder (en çok 7 gün)")}
            </label>
            <Button variant="outline" size="sm" className="self-start" disabled={busy} onClick={() => input.current?.click()}>
              {busy ? <Spinner data-icon="inline-start" /> : <Upload data-icon="inline-start" />}
              {t("Dosya seç ve gönder")}
            </Button>
          </Writable>
          {mine.length > 0 ? (
            <ul className="flex flex-col gap-1 text-xs">
              {mine.map((tf) => (
                <li key={tf.id} className="flex items-center justify-between gap-2">
                  <span className="truncate">{tf.name}</span>
                  <span className={cn("shrink-0", tf.state === "failed" ? "text-destructive" : "text-muted-foreground")}>
                    {tf.state === "sending"
                      ? `${formatBytes(tf.sent)} / ${formatBytes(tf.size)}`
                      : tf.state === "done"
                        ? t("Gönderildi")
                        : tf.error
                          ? ts(tf.error)
                          : t("Başarısız")}
                  </span>
                </li>
              ))}
            </ul>
          ) : null}
        </>
      ) : (
        <Muted>{t("Bu cihaza dosya göndermeye izin veren bir files kuralı yok.")}</Muted>
      )}
    </Section>
  )
}

function WakeSection({ device, onChange }: { device: RemoteDevice; onChange: () => void }) {
  const { t } = useI18n()
  const [busy, setBusy] = useState(false)
  const [editing, setEditing] = useState(false)
  const [mac, setMac] = useState(device.wakeMac)

  async function wake() {
    setBusy(true)
    try {
      const res = await post<WakeResult>("/api/app/wake", { device: device.name })
      toast.success(t("Uyandırma paketi {relay} üzerinden gönderildi.", { relay: res.relay }))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  async function saveMac() {
    try {
      await post<RemoteDevice>("/api/app/wake/mac", { device: device.name, mac: mac.trim() })
      setEditing(false)
      onChange()
      toast.success(mac.trim() ? t("MAC adresi kaydedildi.") : t("Elle girilen MAC adresi kaldırıldı."))
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }

  return (
    <Section icon={Power} title={t("Uyandır (Wake-on-LAN)")}>
      {device.wakeRelays.length > 0 ? (
        <Muted>
          {t("Aracı: {relays}. Aracı cihaz aynı yerel ağda magic paket yayınlar.", { relays: device.wakeRelays.join(", ") })}
        </Muted>
      ) : (
        <Muted>{t("Bu cihazı uyandırmaya izin veren bir wake kuralı (aracı cihazıyla) yok.")}</Muted>
      )}
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="text-muted-foreground">MAC</span>
        {editing ? (
          <>
            <Input
              value={mac}
              onChange={(e) => setMac(e.target.value)}
              className="h-7 w-44 font-mono text-xs"
              placeholder="aa:bb:cc:dd:ee:ff"
              aria-label={t("MAC adresi")}
              maxLength={17}
            />
            <Button size="sm" onClick={saveMac}>
              {t("Kaydet")}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setEditing(false)}>
              {t("Vazgeç")}
            </Button>
          </>
        ) : (
          <>
            <span className="font-mono text-xs">{device.wakeMac || t("bilinmiyor")}</span>
            <Writable>
              <Button
                size="xs"
                variant="ghost"
                onClick={() => {
                  setMac(device.wakeMac)
                  setEditing(true)
                }}
              >
                {t("Değiştir")}
              </Button>
            </Writable>
          </>
        )}
      </div>
      {device.wakeRelays.length > 0 ? (
        <Writable>
          <Button variant="outline" size="sm" className="self-start" disabled={busy || !device.wakeMac} onClick={wake}>
            {busy ? <Spinner data-icon="inline-start" /> : <Power data-icon="inline-start" />}
            {t("Uyandır")}
          </Button>
        </Writable>
      ) : null}
    </Section>
  )
}

function SpeedSection({ device }: { device: RemoteDevice }) {
  const { t, ts } = useI18n()
  const [busy, setBusy] = useState<"down" | "up" | null>(null)
  const [results, setResults] = useState<SpeedResult[]>([])

  async function run(upload: boolean) {
    setBusy(upload ? "up" : "down")
    try {
      const res = await post<SpeedResult>("/api/app/speedtest", { device: device.name, upload, seconds: 5 })
      setResults((r) => [res, ...r].slice(0, 4))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  return (
    <Section icon={Gauge} title={t("Hız testi")}>
      {device.canSpeedtest ? (
        <>
          <Muted>{t("5 saniyelik TCP testi; tünelin bu iki cihaz arasındaki gerçek hızını ölçer.")}</Muted>
          <Writable>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" size="sm" disabled={busy !== null} onClick={() => run(false)}>
                {busy === "down" ? <Spinner data-icon="inline-start" /> : <Activity data-icon="inline-start" />}
                {t("İndirme")}
              </Button>
              <Button variant="outline" size="sm" disabled={busy !== null} onClick={() => run(true)}>
                {busy === "up" ? <Spinner data-icon="inline-start" /> : <Upload data-icon="inline-start" />}
                {t("Yükleme")}
              </Button>
            </div>
          </Writable>
          {results.length > 0 ? (
            <ul className="flex flex-col gap-1 text-sm">
              {results.map((r, i) => (
                <li key={i} className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">{ts(r.direction)}</span>
                  <span className="font-mono text-xs">
                    {r.mbps.toFixed(1)} Mbit/s · {formatBytes(r.bytes)}
                  </span>
                </li>
              ))}
            </ul>
          ) : null}
        </>
      ) : (
        <Muted>{t("Bu cihazla hız testine izin veren bir speedtest kuralı yok.")}</Muted>
      )}
    </Section>
  )
}
