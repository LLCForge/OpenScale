"use client"

import { useState } from "react"
import useSWR from "swr"
import { Download, History, KeyRound, Plus, RefreshCw, ShieldCheck, ShieldOff, Trash2 } from "lucide-react"
import { toast } from "sonner"

import { Writable, useReadOnly } from "@/components/app/read-only"
import { DetailSection } from "@/components/devices/detail-card"
import { PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { headCell, ListTable, RowMenu } from "@/components/settings/list-table"
import { EmptyNote, SettingBadge, SettingRow, SettingsColumn, SettingsSection } from "@/components/settings/settings-layout"
import { BackupProbeRow, GuardToggleDialog, SyncAlarms, SyncPauseSection, guardOf, useSyncGuard } from "@/components/sync/sync-guard"
import type { SyncGuardStatus } from "@/lib/p07-types"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { DropdownMenuItem, DropdownMenuSeparator } from "@/components/ui/dropdown-menu"
import { Field, FieldContent, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { errorMessage, fetcher, post } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { getLocale, msg, translateServer, tx, useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"
import { formatBytes, type SyncSnapshot, type SyncStatus, type SyncVersion } from "@/lib/wave2"

const idPattern = /^[a-z0-9][a-z0-9-]{0,62}$/
const modeLabels: Record<string, string> = {
  sendreceive: msg("Gönder ve al"),
  sendonly: msg("Yalnızca paylaş"),
  receiveonly: msg("Yalnızca al"),
}

function splitNames(s: string): string[] {
  return s
    .split(",")
    .map((x) => x.trim().toLowerCase())
    .filter((x) => x.length > 0)
}

/** Folder sync, encrypted backup and the offline queue (ADR-0104, ADR-0110). */
export function SyncView() {
  const { t, ts } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<SyncStatus>("/api/app/sync", fetcher, { refreshInterval: 10000 })
  const { guard, mutate: mutateGuard } = useSyncGuard()
  const [alarmVersions, setAlarmVersions] = useState<string | null>(null)
  const guardChange = (s: SyncGuardStatus) => void mutateGuard(s, { revalidate: false })
  return (
    <SettingsColumn className="max-w-4xl">
      <PageHeader
        title={t("Eşitleme ve yedek")}
        description={t("Klasörler özel ağ içinden çekilerek eşitlenir; yedekler bu bilgisayarda şifrelenir.")}
      />
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {data ? (
          <>
            {guard ? <SyncAlarms guard={guard} onChange={guardChange} onVersions={setAlarmVersions} /> : null}
            {data.error ? (
              <Alert variant="destructive">
                <AlertDescription>{ts(data.error)}</AlertDescription>
              </Alert>
            ) : null}
            <FoldersSection status={data} guard={guard} onGuardChange={guardChange} onChange={(s) => mutate(s, { revalidate: false })} />
            {guard ? <SyncPauseSection guard={guard} onChange={guardChange} /> : null}
            <BackupSection status={data} onChange={(s) => mutate(s, { revalidate: false })}>
              {guard && data.backup.keyExported ? <BackupProbeRow guard={guard} onChange={guardChange} /> : null}
            </BackupSection>
            <OutboxSection status={data} onChange={(s) => mutate(s, { revalidate: false })} />
            <VersionsDialog id={alarmVersions} onClose={() => setAlarmVersions(null)} />
          </>
        ) : null}
      </QueryState>
    </SettingsColumn>
  )
}

interface FoldersSectionProps {
  status: SyncStatus
  guard: SyncGuardStatus | null | undefined
  onGuardChange: (s: SyncGuardStatus) => void
  onChange: (s: SyncStatus) => void
}

function FoldersSection({ status, guard, onGuardChange, onChange }: FoldersSectionProps) {
  const { t, ts } = useI18n()
  const readOnly = useReadOnly()
  const [adding, setAdding] = useState(false)
  const [guardTarget, setGuardTarget] = useState<{ id: string; off: boolean } | null>(null)
  const [busy, setBusy] = useState(false)
  const [versionsOf, setVersionsOf] = useState<string | null>(null)

  async function act(path: string, body: unknown, ok: string) {
    setBusy(true)
    try {
      onChange(await post<SyncStatus>(path, body))
      toast.success(ok)
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <DetailSection
      id="klasorler"
      title={t("Klasörler")}
      description={t(
        "Paylaşılan klasörü hangi cihazın okuyabileceğini sync kuralları belirler. Bu bilgisayar listelenen eşlerden {count} dakikada bir çeker; çevrimdışı eş bir sonraki turda yeniden denenir. Çakışmada iki sürüm de saklanır.",
        { count: Math.round(status.intervalSec / 60) }
      )}
      framed={false}
      action={
        <Writable>
          <Button
            variant="ghost"
            size="icon"
            aria-label={t("Şimdi eşitle")}
            title={t("Şimdi eşitle")}
            disabled={busy || status.folders.length === 0}
            onClick={() => act("/api/app/sync/now", {}, t("Eşitleme tamamlandı."))}
          >
            {busy ? <Spinner /> : <RefreshCw />}
          </Button>
          <Button variant="outline" onClick={() => setAdding(true)}>
            <Plus data-icon="inline-start" />
            {t("Klasör ekle")}
          </Button>
        </Writable>
      }
    >
      {status.folders.length === 0 ? (
        <EmptyNote>{t("Henüz eşitlenen klasör yok.")}</EmptyNote>
      ) : (
        <ListTable label={t("Eşitlenen klasörler")}>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className={headCell}>{t("Klasör")}</TableHead>
              <TableHead className={cn(headCell, "hidden md:table-cell")}>{t("Eşler")}</TableHead>
              <TableHead className="w-12">
                <span className="sr-only">{t("İşlemler")}</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {status.folders.map((f) => (
              <TableRow key={f.id}>
                <TableCell className="whitespace-normal">
                  <div className="flex min-w-0 flex-col gap-1">
                    <span className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm font-medium">{f.id}</span>
                      <SettingBadge>{t(modeLabels[f.mode] ?? f.mode)}</SettingBadge>
                      {f.propagateDeletes ? <SettingBadge tone="warning">{t("Silmeler yayılır")}</SettingBadge> : null}
                      {guardOf(guard, f.id)?.alarm ? <SettingBadge tone="danger">{t("Askıda")}</SettingBadge> : null}
                      {guardOf(guard, f.id)?.guard_off ? <SettingBadge>{t("Fidye koruması kapalı")}</SettingBadge> : null}
                    </span>
                    <span className="font-mono text-[0.8125rem] break-all text-muted-foreground">{f.path}</span>
                    {f.lastPull ? (
                      <span className="text-sm text-muted-foreground">
                        {t("Son çekme {time}: {fetched} alındı, {deleted} silindi, {conflicts} çakışma", {
                          time: formatDateTime(f.lastPull),
                          fetched: f.fetched,
                          deleted: f.deleted,
                          conflicts: f.conflicts,
                        })}
                        {f.failed > 0 ? t(", {count} yapılamadı", { count: f.failed }) : ""}
                      </span>
                    ) : null}
                    {f.lastError ? <span className="text-sm text-destructive">{ts(f.lastError)}</span> : null}
                    <FolderPeers folder={f} className="md:hidden" />
                  </div>
                </TableCell>
                <TableCell className="hidden whitespace-normal md:table-cell">
                  <FolderPeers folder={f} />
                </TableCell>
                <TableCell className="text-right">
                  <RowMenu label={t("{folder} klasörü için işlemler", { folder: f.id })}>
                    <DropdownMenuItem onClick={() => setVersionsOf(f.id)}>
                      <History />
                      {t("Eski sürümler")}
                    </DropdownMenuItem>
                    {readOnly || !guard ? null : guardOf(guard, f.id)?.guard_off ? (
                      <DropdownMenuItem onClick={() => setGuardTarget({ id: f.id, off: false })}>
                        <ShieldCheck />
                        {t("Fidye yazılımı korumasını aç…")}
                      </DropdownMenuItem>
                    ) : (
                      <DropdownMenuItem onClick={() => setGuardTarget({ id: f.id, off: true })}>
                        <ShieldOff />
                        {t("Fidye yazılımı korumasını kapat…")}
                      </DropdownMenuItem>
                    )}
                    {readOnly ? null : (
                      <>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          variant="destructive"
                          disabled={busy}
                          onClick={() => act("/api/app/sync/folder/remove", { id: f.id }, t("Klasör listeden çıkarıldı; dosyalar yerinde kaldı."))}
                        >
                          <Trash2 />
                          {t("Listeden çıkar")}
                        </DropdownMenuItem>
                      </>
                    )}
                  </RowMenu>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </ListTable>
      )}
      <AddFolderDialog open={adding} onOpenChange={setAdding} onSaved={onChange} />
      <VersionsDialog id={versionsOf} onClose={() => setVersionsOf(null)} />
      <GuardToggleDialog target={guardTarget} onClose={() => setGuardTarget(null)} onChange={onGuardChange} />
    </DetailSection>
  )
}

function FolderPeers({ folder: f, className }: { folder: SyncStatus["folders"][number]; className?: string }) {
  const { t } = useI18n()
  const blocked = f.peers.filter((p) => !f.readable.includes(p))
  return (
    <span className={cn("flex flex-col gap-0.5 text-sm text-muted-foreground", className)}>
      {f.peers.length > 0 ? (
        <span>
          {t("Çekilen:")} <span className="text-foreground">{f.peers.join(", ")}</span>
          {blocked.length > 0 ? (
            <span className="text-destructive"> {t("(kural izin vermiyor: {names})", { names: blocked.join(", ") })}</span>
          ) : null}
        </span>
      ) : null}
      <span>{f.servedTo.length > 0 ? t("Okuyabilen: {names}", { names: f.servedTo.join(", ") }) : t("Okuyabilen: kimse")}</span>
    </span>
  )
}

function AddFolderDialog({ open, onOpenChange, onSaved }: { open: boolean; onOpenChange: (o: boolean) => void; onSaved: (s: SyncStatus) => void }) {
  const { t } = useI18n()
  const [id, setId] = useState("")
  const [path, setPath] = useState("")
  const [mode, setMode] = useState("sendreceive")
  const [peers, setPeers] = useState("")
  const [del, setDel] = useState(false)
  const [busy, setBusy] = useState(false)
  const idOK = idPattern.test(id)

  async function save() {
    setBusy(true)
    try {
      const res = await post<SyncStatus>("/api/app/sync/folder", {
        id,
        path: path.trim(),
        mode,
        peers: mode === "sendonly" ? [] : splitNames(peers),
        propagateDeletes: del,
        versions: 0,
      })
      onSaved(res)
      toast.success(t("Klasör kaydedildi."))
      onOpenChange(false)
      setId("")
      setPath("")
      setPeers("")
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("Klasör ekle")}</DialogTitle>
          <DialogDescription>{t("Aynı kimlik, eşitlenecek her cihazda kullanılır. OpenScale veri klasörü ve sürücü kökleri eşitlenemez.")}</DialogDescription>
        </DialogHeader>
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="sync-id">{t("Kimlik")}</FieldLabel>
            <Input id="sync-id" className="font-mono" placeholder={t("belgeler")} value={id} onChange={(e) => setId(e.target.value.toLowerCase())} aria-invalid={id !== "" && !idOK} />
            <FieldDescription>{t("Küçük harf, rakam ve tire.")}</FieldDescription>
          </Field>
          <Field>
            <FieldLabel htmlFor="sync-path">{t("Bu bilgisayardaki klasör")}</FieldLabel>
            <Input id="sync-path" placeholder={t("C:\\Users\\ali\\Belgeler")} value={path} onChange={(e) => setPath(e.target.value)} />
          </Field>
          <Field>
            <FieldLabel htmlFor="sync-mode">{t("Kip")}</FieldLabel>
            <select id="sync-mode" className="h-9 rounded-md border border-input bg-background px-3 text-sm" value={mode} onChange={(e) => setMode(e.target.value)}>
              <option value="sendreceive">{t("Gönder ve al (paylaşır ve eşlerden çeker)")}</option>
              <option value="sendonly">{t("Yalnızca paylaş (salt okunur, hiç çekmez)")}</option>
              <option value="receiveonly">{t("Yalnızca al (eşin kopyasını aynalar)")}</option>
            </select>
          </Field>
          {mode !== "sendonly" ? (
            <Field>
              <FieldLabel htmlFor="sync-peers">{t("Çekilecek eşler")}</FieldLabel>
              <Input id="sync-peers" placeholder="nas, laptop" value={peers} onChange={(e) => setPeers(e.target.value)} />
              <FieldDescription>{t("Virgülle. Eşin sync kuralı bu bilgisayara bu klasörü okuma izni vermelidir.")}</FieldDescription>
            </Field>
          ) : null}
          <Field orientation="horizontal">
            <FieldContent>
              <FieldLabel htmlFor="sync-del">{t("Eşte silineni burada da sil")}</FieldLabel>
              <FieldDescription>{t("Silinen dosyalar sürüm deposuna taşınır. Varsayılan kapalı: değişiklik silmeye üstün gelir.")}</FieldDescription>
            </FieldContent>
            <Switch id="sync-del" checked={del} onCheckedChange={setDel} />
          </Field>
        </FieldGroup>
        <DialogFooter>
          <Button onClick={save} disabled={busy || !idOK || path.trim() === ""}>
            {busy ? <Spinner /> : null}
            {t("Kaydet")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function VersionsDialog({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { data, mutate } = useSWR<{ versions: SyncVersion[] }>(id ? `/api/app/sync/versions?id=${encodeURIComponent(id)}` : null, fetcher)
  const readOnly = useReadOnly()
  const { t } = useI18n()

  async function restore(stored: string) {
    try {
      await post("/api/app/sync/versions/restore", { id, stored })
      toast.success(t("Sürüm geri kondu; o anki dosya da sürüm olarak saklandı."))
      await mutate()
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }

  return (
    <Dialog open={id !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{t("Eski sürümler: {folder}", { folder: id ?? "" })}</DialogTitle>
          <DialogDescription>{t("Eşitlemenin değiştirdiği veya sildiği dosyalar. Dosya başına son 5 sürüm, en çok 30 gün saklanır.")}</DialogDescription>
        </DialogHeader>
        {!data ? (
          <Spinner />
        ) : data.versions.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("Saklanan sürüm yok.")}</p>
        ) : (
          <ul className="flex flex-col divide-y border-y text-sm">
            {data.versions.map((v) => (
              <li key={v.stored} className="flex flex-wrap items-center justify-between gap-2 py-2.5">
                <span className="flex min-w-0 flex-col gap-0.5">
                  <span className="font-mono text-[0.8125rem] break-all">{v.path}</span>
                  <span className="text-sm text-muted-foreground">
                    {formatDateTime(v.time)} · {formatBytes(v.size)}
                  </span>
                </span>
                {!readOnly ? (
                  <Button size="sm" variant="outline" onClick={() => restore(v.stored)}>
                    {t("Geri koy")}
                  </Button>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </DialogContent>
    </Dialog>
  )
}

function BackupSection({ status, onChange, children }: { status: SyncStatus; onChange: (s: SyncStatus) => void; children?: React.ReactNode }) {
  const readOnly = useReadOnly()
  const { t, ts } = useI18n()
  const b = status.backup
  const [exportOpen, setExportOpen] = useState(false)
  const [target, setTarget] = useState(b.target)
  const [folders, setFolders] = useState<string[]>(b.folders)
  const [hours, setHours] = useState(b.intervalHours || 24)
  const [busy, setBusy] = useState(false)
  const [snapshots, setSnapshots] = useState<SyncSnapshot[] | null>(null)

  async function save(enabled: boolean) {
    setBusy(true)
    try {
      onChange(await post<SyncStatus>("/api/app/sync/backup", { enabled, target, folders, intervalHours: hours }))
      toast.success(enabled ? t("Yedek zamanlaması açıldı.") : t("Yedek zamanlaması kapatıldı."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  async function runNow() {
    setBusy(true)
    try {
      onChange(await post<SyncStatus>("/api/app/sync/backup/now", {}))
      toast.success(t("Yedek alındı."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  async function listSnapshots() {
    try {
      const res = await fetcher<{ snapshots: SyncSnapshot[] }>("/api/app/sync/backup/snapshots")
      setSnapshots(res.snapshots)
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }

  return (
    <SettingsSection
      id="sifreli-yedek" // i18n-ignore: sayfa içi bağlantı kimliği
      title={t("Şifreli yedek")}
      description={t(
        "Yedekler bu bilgisayardaki yedek anahtarıyla şifrelenir. Anahtar kaybolursa yedekler açılamaz; bu yüzden önce anahtarı parolayla dışa aktarıp sakla."
      )}
    >
      <SettingRow
        title={t("Yedek anahtarı")}
        badge={
          b.keyExported ? (
            <SettingBadge tone="success">{t("Dışa aktarıldı")}</SettingBadge>
          ) : (
            <SettingBadge tone="warning">{t("Dışa aktarılmadı")}</SettingBadge>
          )
        }
        description={
          b.keyExported ? (
            <span className="font-mono text-[0.8125rem] break-all">{b.keyFingerprint}</span>
          ) : (
            t("Yedek almadan önce anahtarı dışa aktar.")
          )
        }
        action={
          <Writable>
            <Button variant={b.keyExported ? "outline" : "default"} onClick={() => setExportOpen(true)}>
              <KeyRound data-icon="inline-start" />
              {t("Anahtarı dışa aktar")}
            </Button>
          </Writable>
        }
      />
      {b.keyExported ? (
        <SettingRow
          title={t("Zamanlanmış yedek")}
          badge={b.enabled ? <SettingBadge tone="success">{t("Açık")}</SettingBadge> : <SettingBadge>{t("Kapalı")}</SettingBadge>}
          description={
            b.lastRun ? (
              <>
                {b.lastError ? (
                  <>
                    {t("Son yedek {time}", { time: formatDateTime(b.lastRun) })}
                    <span className="text-destructive">: {ts(b.lastError)}</span>
                  </>
                ) : (
                  t("Son yedek {time} başarılı.", { time: formatDateTime(b.lastRun) })
                )}
              </>
            ) : (
              t("Henüz yedek alınmadı.")
            )
          }
        >
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="backup-target">{t("Hedef cihaz")}</FieldLabel>
              <select
                id="backup-target"
                className="h-9 rounded-md border border-input bg-background px-3 text-sm sm:max-w-xs"
                value={target}
                disabled={readOnly}
                onChange={(e) => setTarget(e.target.value)}
              >
                <option value="">{t("Seçin")}</option>
                {status.backupTargets.map((tg) => (
                  <option key={tg} value={tg}>
                    {tg}
                  </option>
                ))}
              </select>
              <FieldDescription>{t("Yalnızca bu bilgisayardan yedek kabul eden (sync kuralında backup) cihazlar listelenir.")}</FieldDescription>
            </Field>
            <Field>
              <FieldLabel>{t("Yedeklenecek klasörler")}</FieldLabel>
              {status.folders.length === 0 ? (
                <FieldDescription>{t("Önce eşitlenecek bir klasör ekle.")}</FieldDescription>
              ) : (
                <div className="flex flex-wrap gap-3">
                  {status.folders.map((f) => (
                    <label key={f.id} className="flex items-center gap-2 text-sm">
                      <Checkbox
                        checked={folders.includes(f.id)}
                        disabled={readOnly}
                        onCheckedChange={(c) => setFolders((cur) => (c === true ? [...cur.filter((x) => x !== f.id), f.id] : cur.filter((x) => x !== f.id)))}
                      />
                      <span className="font-mono">{f.id}</span>
                    </label>
                  ))}
                </div>
              )}
            </Field>
            <Field>
              <FieldLabel htmlFor="backup-hours">{t("Aralık (saat)")}</FieldLabel>
              <Input
                id="backup-hours"
                type="number"
                min={1}
                max={720}
                className="sm:max-w-32"
                value={hours}
                disabled={readOnly}
                onChange={(e) => setHours(Number(e.target.value) || 24)}
              />
            </Field>
          </FieldGroup>
          <Writable>
            <div className="flex flex-wrap gap-2">
              <Button disabled={busy || !target || folders.length === 0} onClick={() => save(true)}>
                {b.enabled ? t("Kaydet") : t("Yedeklemeyi aç")}
              </Button>
              {b.enabled ? (
                <>
                  <Button variant="outline" disabled={busy} onClick={runNow}>
                    {t("Şimdi yedekle")}
                  </Button>
                  <Button variant="ghost" disabled={busy} onClick={() => save(false)}>
                    {t("turn-off|Kapat")}
                  </Button>
                </>
              ) : null}
            </div>
          </Writable>
        </SettingRow>
      ) : null}
      {b.keyExported ? (
        <SettingRow
          title={t("Hedefteki yedekler")}
          description={b.target ? t("{device} cihazında saklanan yedek anlık görüntüleri.", { device: b.target }) : t("Önce bir hedef cihaz seç ve kaydet.")}
          action={
            <Writable>
              <Button variant="outline" disabled={!b.target} onClick={listSnapshots}>
                {t("Yedekleri listele")}
              </Button>
            </Writable>
          }
        >
          {snapshots ? (
            snapshots.length === 0 ? (
              <EmptyNote>{t("Hedefte yedek yok.")}</EmptyNote>
            ) : (
              <ul className="flex flex-col divide-y border-y">
                {snapshots.map((sn) => (
                  <li key={sn.folder + sn.name} className="flex items-center justify-between gap-4 py-2.5 text-sm">
                    <span className="font-mono">{sn.folder}</span>
                    <span className="text-muted-foreground">{formatDateTime(sn.time)}</span>
                  </li>
                ))}
              </ul>
            )
          ) : null}
        </SettingRow>
      ) : null}
      {children}
      <ExportKeyDialog open={exportOpen} onOpenChange={setExportOpen} onDone={() => post<SyncStatus>("/api/app/sync/backup", { enabled: false, target: "", folders: [], intervalHours: 0 }).then(onChange).catch(() => undefined)} keepEnabled={b.enabled} />
    </SettingsSection>
  )
}

function ExportKeyDialog({
  open,
  onOpenChange,
  onDone,
  keepEnabled,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  onDone: () => void
  keepEnabled: boolean
}) {
  const { t } = useI18n()
  const [pass, setPass] = useState("")
  const [confirm, setConfirm] = useState("")
  const [text, setText] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [busy, setBusy] = useState(false)
  const ok = Array.from(pass).length >= 12 && pass === confirm

  async function exportKey() {
    setBusy(true)
    try {
      const res = await post<{ key: string }>("/api/app/sync/backup/key", { passphrase: pass })
      setText(res.key)
      setPass("")
      setConfirm("")
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  function download() {
    if (!text) return
    const url = URL.createObjectURL(new Blob([text + "\n"], { type: "text/plain" }))
    const a = document.createElement("a")
    a.href = url
    a.download = t("openscale-yedek-anahtari.txt")
    a.click()
    URL.revokeObjectURL(url)
    setSaved(true)
  }

  function close(o: boolean) {
    if (!o) {
      if (text && !keepEnabled) onDone()
      setText(null)
      setSaved(false)
    }
    onOpenChange(o)
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("Yedek anahtarını dışa aktar")}</DialogTitle>
          <DialogDescription>
            {t("Anahtar parolayla (Argon2id) şifrelenmiş tek satır olarak verilir. Bu bilgisayar kaybolursa yedekleri yalnızca bu satır ve parola açar.")}
          </DialogDescription>
        </DialogHeader>
        {text ? (
          <div className="flex flex-col gap-3">
            <pre className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs">{text}</pre>
            <p className="text-sm text-muted-foreground">{t("Dosyayı bu bilgisayarın dışında (USB bellek, kâğıt) saklayın; parolayı ayrı tutun.")}</p>
            <DialogFooter>
              <Button variant="outline" onClick={download}>
                <Download data-icon="inline-start" />
                {t("Dosya olarak indir")}
              </Button>
              <Button onClick={() => close(false)} disabled={!saved}>
                {t("Sakladım")}
              </Button>
            </DialogFooter>
          </div>
        ) : (
          <>
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="bk-pass">{t("passphrase|Parola")}</FieldLabel>
                <Input id="bk-pass" type="password" autoComplete="new-password" value={pass} onChange={(e) => setPass(e.target.value)} />
                <FieldDescription>{t("En az 12 karakter.")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="bk-confirm">{t("Parola (tekrar)")}</FieldLabel>
                <Input id="bk-confirm" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
              </Field>
            </FieldGroup>
            <DialogFooter>
              <Button onClick={exportKey} disabled={!ok || busy}>
                {busy ? <Spinner /> : null}
                {t("Dışa aktar")}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}

function OutboxSection({ status, onChange }: { status: SyncStatus; onChange: (s: SyncStatus) => void }) {
  const readOnly = useReadOnly()
  const { t } = useI18n()
  async function remove(id: string) {
    try {
      onChange(await post<SyncStatus>("/api/app/files/queue/remove", { id }))
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }
  return (
    <DetailSection
      id="bekleyen-gonderimler"
      title={t("Bekleyen gönderimler")}
      description={t("Alıcı çevrimiçi olunca gönderilecek dosyalar. Dosya bu bilgisayarda bekler; 7 gün içinde gönderilemezse silinir.")}
      framed={false}
    >
      {status.outbox.length === 0 ? (
        <EmptyNote>{t("Bekleyen dosya yok.")}</EmptyNote>
      ) : (
        <ListTable label={t("Bekleyen gönderimler")}>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className={headCell}>{t("Dosya")}</TableHead>
              <TableHead className={cn(headCell, "hidden sm:table-cell")}>{t("Durum")}</TableHead>
              <TableHead className="w-12">
                <span className="sr-only">{t("İşlemler")}</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {status.outbox.map((o) => (
              <TableRow key={o.id}>
                <TableCell className="whitespace-normal">
                  <div className="flex min-w-0 flex-col gap-1">
                    <span className="text-sm">
                      <span className="font-medium break-all">{o.name}</span> → {o.peer}
                    </span>
                    <span className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
                      {formatBytes(o.size)}
                      {o.strip ? <SettingBadge>{o.strip === "all" ? t("Üst veri temizlenecek") : t("Konum temizlenecek")}</SettingBadge> : null}
                    </span>
                    <span className="text-sm text-muted-foreground sm:hidden">{outboxState(o)}</span>
                  </div>
                </TableCell>
                <TableCell className="hidden text-sm whitespace-normal text-muted-foreground sm:table-cell">{outboxState(o)}</TableCell>
                <TableCell className="text-right">
                  {readOnly ? null : (
                    <RowMenu label={t("{name} gönderimi için işlemler", { name: o.name })} className="w-44">
                      <DropdownMenuItem variant="destructive" onClick={() => remove(o.id)}>
                        {t("Gönderimden vazgeç")}
                      </DropdownMenuItem>
                    </RowMenu>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </ListTable>
      )}
    </DetailSection>
  )
}

function outboxState(o: SyncStatus["outbox"][number]): string {
  const base = o.attempts > 0 ? tx("{count} deneme; sonraki {time}", { count: o.attempts, time: formatDateTime(o.nextTry) }) : tx("Bekliyor")
  return o.lastError ? `${base} (${translateServer(getLocale(), o.lastError)})` : base
}
