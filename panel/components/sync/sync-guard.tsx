"use client"

import { useState } from "react"
import Link from "next/link"
import useSWR from "swr"
import { History, Pause, Play, ShieldAlert } from "lucide-react"
import { toast } from "sonner"

import { Writable } from "@/components/app/read-only"
import { EmptyNote, SettingBadge, SettingRow, SettingsSection } from "@/components/settings/settings-layout"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Spinner } from "@/components/ui/spinner"
import { ApiError, errorMessage, fetcher, post } from "@/lib/api"
import { formatBytes, formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { BackupProbeFolder, SyncAlarm, SyncGuardFolder, SyncGuardStatus } from "@/lib/p07-types"

// Sync guard (#453), pause (#385, #447) and backup integrity probe (#452),
// ADR-0159. All are this computer's own settings; none needs a signature.

const KEY = "/api/app/sync/guard"

/** The guard state, or null when the service has no guard (older service, command line panel). */
export function useSyncGuard() {
  const { data, error, mutate } = useSWR<SyncGuardStatus>(KEY, fetcher, {
    refreshInterval: 15_000,
    shouldRetryOnError: (err: unknown) => !(err instanceof ApiError && err.status === 404),
  })
  const missing = error instanceof ApiError && error.status === 404
  return { guard: missing ? null : data, mutate }
}

async function act(path: string, body: unknown, ok: string, onChange: (s: SyncGuardStatus) => void): Promise<boolean> {
  try {
    onChange(await post<SyncGuardStatus>(path, body))
    toast.success(ok)
    return true
  } catch (err) {
    toast.error(errorMessage(err))
    return false
  }
}

/** Red strips at the top of the page, one per folder the guard suspended. */
export function SyncAlarms({
  guard,
  onChange,
  onVersions,
}: {
  guard: SyncGuardStatus
  onChange: (s: SyncGuardStatus) => void
  onVersions: (id: string) => void
}) {
  const [clearing, setClearing] = useState<string | null>(null)
  const alarmed = (guard.folders ?? []).filter((f): f is SyncGuardFolder & { alarm: SyncAlarm } => f.alarm !== undefined)
  if (alarmed.length === 0) return null
  return (
    <div className="flex flex-col gap-3">
      {alarmed.map((f) => (
        <AlarmStrip key={f.id} id={f.id} alarm={f.alarm} onVersions={() => onVersions(f.id)} onClear={() => setClearing(f.id)} />
      ))}
      <ClearDialog id={clearing} onClose={() => setClearing(null)} onChange={onChange} />
    </div>
  )
}

function AlarmStrip({ id, alarm, onVersions, onClear }: { id: string; alarm: SyncAlarm; onVersions: () => void; onClear: () => void }) {
  const { t, ts } = useI18n()
  const peer = alarm.source.startsWith("peer:") ? alarm.source.slice(5) : null
  const encrypted = alarm.high_entropy + alarm.bad_magic
  // The folder name is drawn in mono inside the translated sentence.
  const [titleBefore = "", titleAfter = ""] = t("{folder} klasöründe fidye yazılımı belirtisi görüldü", { folder: "\u0000" }).split("\u0000")
  return (
    <Alert variant="destructive" className="border-destructive/40 px-4 py-3">
      <ShieldAlert />
      <AlertTitle className="text-pretty">
        {titleBefore}
        <span className="font-mono">{id}</span>
        {titleAfter}
      </AlertTitle>
      <AlertDescription className="flex flex-col gap-2 text-pretty">
        <span>
          {t("Eşitleme ve yedek bu klasör için {since} saatinden beri durduruldu; diğer cihazlardaki kopyalar korunuyor.", {
            since: formatDateTime(alarm.since),
          })}
          {peer ? ` ${t("Belirti {peer} cihazından gelen değişikliklerde görüldü; bu cihazdaki dosyaların değişmedi.", { peer })}` : ""}
        </span>
        <span>{ts(alarm.reason)}</span>
        <span>
          {t("{modified} dosya değişti, {deleted} silindi, {ext} uzantı değişti; incelenen {sampled} dosyanın {encrypted} tanesi şifrelenmiş görünüyor.", {
            modified: alarm.modified,
            deleted: alarm.deleted,
            ext: alarm.ext_changed,
            sampled: alarm.sampled,
            encrypted,
          })}
        </span>
        {alarm.examples && alarm.examples.length > 0 ? (
          <ul className="flex flex-col gap-0.5">
            {alarm.examples.map((e) => (
              <li key={e} className="font-mono text-[0.8125rem] break-all">
                {e}
              </li>
            ))}
          </ul>
        ) : null}
        <span className="flex flex-wrap gap-2 pt-1">
          <Button variant="outline" size="sm" onClick={onVersions}>
            <History data-icon="inline-start" />
            {t("Eski sürümleri göster")}
          </Button>
          <Writable>
            <Button variant="outline" size="sm" onClick={onClear}>
              {t("Dosyaları denetledim, eşitlemeyi sürdür")}
            </Button>
          </Writable>
        </span>
      </AlertDescription>
    </Alert>
  )
}

function ClearDialog({ id, onClose, onChange }: { id: string | null; onClose: () => void; onChange: (s: SyncGuardStatus) => void }) {
  const { t } = useI18n()
  const [busy, setBusy] = useState(false)
  async function clear() {
    if (!id) return
    setBusy(true)
    const ok = await act(`${KEY}/clear`, { id }, t("Klasörün eşitlemesi sürüyor."), onChange)
    setBusy(false)
    if (ok) onClose()
  }
  return (
    <Dialog open={id !== null} onOpenChange={(v) => (!v ? onClose() : undefined)}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("Eşitleme sürdürülsün mü?")}</DialogTitle>
          <DialogDescription className="text-pretty">
            {t("Klasördeki şu anki dosyalar doğru kabul edilecek ve diğer cihazlara gönderilecek. Şifrelenmiş dosya kalmadığından emin misin?")}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t("Vazgeç")}
          </Button>
          <Button variant="destructive" onClick={clear} disabled={busy}>
            {busy ? <Spinner data-icon="inline-start" /> : null}
            {t("Denetledim, sürdür")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

const pauseChoices = [
  { hours: 1, label: msg("1 saat duraklat") },
  { hours: 8, label: msg("8 saat duraklat") },
  { hours: 0, label: msg("Ben sürdürene kadar") },
]

/** Pause for scheduled sync, backups and probes. */
export function SyncPauseSection({ guard, onChange }: { guard: SyncGuardStatus; onChange: (s: SyncGuardStatus) => void }) {
  const { t, ts } = useI18n()
  const [busy, setBusy] = useState(false)
  const pauses = guard.pauses ?? []
  const ownerPaused = pauses.some((p) => p.reason === "owner")

  async function pause(paused: boolean, hours = 0) {
    setBusy(true)
    await act("/api/app/sync/pause", { paused, hours }, paused ? t("Eşitleme duraklatıldı.") : t("Eşitleme sürüyor."), onChange)
    setBusy(false)
  }

  return (
    <SettingsSection
      id="duraklatma"
      title={t("Duraklatma")}
      description={t("Duraklatma zamanlanmış eşitlemeyi, yedeği ve yedek yoklamasını bekletir. 'Şimdi eşitle' ve 'Şimdi yedekle' yine çalışır.")}
    >
      <SettingRow
        title={t("Durum")}
        badge={guard.paused ? <SettingBadge tone="warning">{t("Duraklatıldı")}</SettingBadge> : <SettingBadge>{t("Çalışıyor")}</SettingBadge>}
        description={
          guard.paused
            ? t("Aşağıdaki nedenlerden biri sürdükçe zamanlanmış işler bekler.")
            : t("Zamanlanmış eşitleme ve yedek her zamanki gibi çalışıyor.")
        }
        action={
          <Writable>
            {ownerPaused ? (
              <Button variant="outline" disabled={busy} onClick={() => pause(false)}>
                {busy ? <Spinner data-icon="inline-start" /> : <Play data-icon="inline-start" />}
                {t("Sürdür")}
              </Button>
            ) : (
              pauseChoices.map((c) => (
                <Button key={c.hours} variant="outline" disabled={busy} onClick={() => pause(true, c.hours)}>
                  {c.hours === 1 ? <Pause data-icon="inline-start" /> : null}
                  {t(c.label)}
                </Button>
              ))
            )}
          </Writable>
        }
      >
        {pauses.length > 0 ? (
          <ul className="flex flex-col divide-y border-y text-sm">
            {pauses.map((p) => (
              <li key={p.reason} className="flex flex-col gap-0.5 py-2.5 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
                <span className="font-medium">{ts(p.label)}</span>
                <span className="text-muted-foreground text-pretty">
                  {p.reason.startsWith("edge:") ? (
                    <>
                      {t("Uç cihaz kipini kapatınca sürer")} ·{" "}
                      <Link href="/settings/local#gelismis" className="underline underline-offset-4 hover:text-foreground">
                        {t("Kip ayarları")}
                      </Link>
                    </>
                  ) : p.until ? (
                    t("{time} saatinde kendiliğinden sürer", { time: formatDateTime(p.until) })
                  ) : p.reason === "owner" ? (
                    t("Sen sürdürene kadar")
                  ) : (
                    ""
                  )}
                </span>
              </li>
            ))}
          </ul>
        ) : null}
      </SettingRow>
    </SettingsSection>
  )
}

/** The guard of one folder, for its row menu: on unless the owner turned it off. */
export function guardOf(guard: SyncGuardStatus | null | undefined, id: string): SyncGuardFolder | undefined {
  return guard?.folders?.find((f) => f.id === id)
}

/** Turns the ransomware guard of one folder on or off; turning off asks first. */
export function GuardToggleDialog({
  target,
  onClose,
  onChange,
}: {
  target: { id: string; off: boolean } | null
  onClose: () => void
  onChange: (s: SyncGuardStatus) => void
}) {
  const { t } = useI18n()
  const [busy, setBusy] = useState(false)
  async function apply() {
    if (!target) return
    setBusy(true)
    const ok = await act(
      KEY,
      { id: target.id, off: target.off },
      target.off ? t("Fidye yazılımı koruması kapatıldı.") : t("Fidye yazılımı koruması açıldı."),
      onChange
    )
    setBusy(false)
    if (ok) onClose()
  }
  return (
    <Dialog open={target !== null} onOpenChange={(v) => (!v ? onClose() : undefined)}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>
            {target?.off ? t("Fidye yazılımı korumasını kapat") : t("Fidye yazılımı korumasını aç")}: <span className="font-mono">{target?.id}</span>
          </DialogTitle>
          <DialogDescription className="text-pretty">
            {target?.off
              ? t(
                  "Koruma kapalıyken şifrelenen dosyalar diğer cihazlara ve yedeğe geçebilir. Yalnızca şifreli kap dosyaları (VeraCrypt vb.) tutan klasörler için kapat."
                )
              : t("Her taramada dosyalar bir öncekiyle karşılaştırılır; toplu şifreleme belirtisinde klasörün eşitlemesi ve yedeği durur.")}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t("Vazgeç")}
          </Button>
          <Button variant={target?.off ? "destructive" : "default"} onClick={apply} disabled={busy}>
            {busy ? <Spinner data-icon="inline-start" /> : null}
            {target?.off ? t("Korumayı kapat") : t("Korumayı aç")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** "Yedek bütünlüğü" row of the backup section. */
export function BackupProbeRow({ guard, onChange }: { guard: SyncGuardStatus; onChange: (s: SyncGuardStatus) => void }) {
  const { t, ts } = useI18n()
  const [busy, setBusy] = useState(false)
  const probe = guard.probe

  async function run() {
    setBusy(true)
    await act("/api/app/sync/backup/probe", {}, t("Yedek yoklaması bitti."), onChange)
    setBusy(false)
  }

  return (
    <SettingRow
      title={t("Yedek bütünlüğü")}
      badge={
        probe ? (
          probe.ok ? (
            <SettingBadge tone="success">{t("Geri yüklenebilir")}</SettingBadge>
          ) : (
            <SettingBadge tone="danger">{t("Sorun var")}</SettingBadge>
          )
        ) : null
      }
      description={
        <>
          {t("Yedek hedefinden rastgele dosyalar indirilir, bu cihazda çözülür ve özetleri karşılaştırılır. Hedef dosya adlarını ve içeriği görmez.")}
          {probe ? ` ${t("Son yoklama {at} ({target}).", { at: formatDateTime(probe.at), target: probe.target })}` : ""}
          {guard.probe_hours > 0 ? ` ${t("Yedek açıkken en az {count} saatte bir kendiliğinden çalışır.", { count: guard.probe_hours })}` : ""}
        </>
      }
      action={
        <Writable>
          <Button variant="outline" disabled={busy} onClick={run}>
            {busy ? <Spinner data-icon="inline-start" /> : null}
            {busy ? t("Yoklanıyor…") : t("Şimdi yokla")}
          </Button>
        </Writable>
      }
    >
      {probe?.error ? <p className="text-sm text-destructive">{ts(probe.error)}</p> : null}
      {probe && probe.folders.length > 0 ? (
        <ul className="flex flex-col divide-y border-y text-sm">
          {probe.folders.map((f) => (
            <ProbeFolder key={f.folder} folder={f} />
          ))}
        </ul>
      ) : probe ? null : (
        <EmptyNote framed={false}>{t("Henüz yoklama yapılmadı.")}</EmptyNote>
      )}
    </SettingRow>
  )
}

function ProbeFolder({ folder: f }: { folder: BackupProbeFolder }) {
  const { t, ts } = useI18n()
  // i18n-ignore: sunucu iletisiyle eşleşme
  const noBackup = !f.ok && f.error?.includes("yedeği yok")
  return (
    <li className="flex flex-col gap-1 py-2.5">
      <span className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-[0.8125rem] font-medium">{f.folder}</span>
        {f.ok ? (
          <SettingBadge tone="success">{t("Geri yüklenebilir")}</SettingBadge>
        ) : noBackup ? (
          <SettingBadge>{t("Yedek yok")}</SettingBadge>
        ) : (
          <SettingBadge tone="danger">{t("Sorun")}</SettingBadge>
        )}
      </span>
      <span className="text-muted-foreground text-pretty">
        {f.ok
          ? f.snapshot_time
            ? t("{count} dosya, {size} çözüldü ve doğrulandı; yedek {time}.", {
                count: f.checked,
                size: formatBytes(f.bytes),
                time: formatDateTime(f.snapshot_time),
              })
            : t("{count} dosya, {size} çözüldü ve doğrulandı.", { count: f.checked, size: formatBytes(f.bytes) })
          : f.error
            ? ts(f.error)
            : t("{count} parça eksik.", { count: f.missing })}
      </span>
      {f.problems && f.problems.length > 0 ? (
        <ul className="flex flex-col gap-0.5">
          {f.problems.map((p) => (
            <li key={p.path} className="flex flex-wrap gap-x-2">
              <span className="font-mono text-[0.8125rem] break-all">{p.path}</span>
              <span className="text-destructive">{ts(p.reason)}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </li>
  )
}
