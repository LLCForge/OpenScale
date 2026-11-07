"use client"

import { useState } from "react"
import useSWR from "swr"
import { toast } from "sonner"
import { LifeBuoy, RefreshCw, ShieldAlert } from "lucide-react"

import { useAppStatus } from "@/components/app/use-app-status"
import { useReadOnly } from "@/components/app/read-only"
import { DetailSection } from "@/components/devices/detail-card"
import { SignChangeDialog } from "@/components/sign-change"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Spinner } from "@/components/ui/spinner"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { errorMessage, fetcher, post } from "@/lib/api"
import { formatBytes, formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { SupportKind, SupportProcess, SupportRuleState, SupportSnapshot } from "@/lib/support-types"
import type { Device } from "@/lib/types"

const KINDS: { kind: SupportKind; label: string }[] = [
  { kind: "processes", label: msg("İşlemler") },
  { kind: "services", label: msg("Hizmetler") },
  { kind: "events", label: msg("Sistem olayları") },
  { kind: "disks", label: msg("Diskler") },
  { kind: "startup", label: msg("Açılış programları") },
]

/**
 * "Destek araçları" on a device's detail page (#852, ADR-0232): read-only
 * views of the device through its support service. The device decides by
 * its signed rules, asks the person there and shows the "remotely
 * connected" notice; this panel only displays what comes back.
 */
export function SupportToolsSection({ device }: { device: string }) {
  const { t } = useI18n()
  const { isApp } = useAppStatus()
  const { data: list } = useSWR<{ devices: Device[] }>(isApp ? "/api/devices" : null, fetcher)
  const self = list?.devices.find((d) => d.thisComputer)?.name
  const ruleKey = self ? `/api/support/rule?from=${encodeURIComponent(self)}&to=${encodeURIComponent(device)}` : null
  const { data: rule, mutate } = useSWR<SupportRuleState>(ruleKey, fetcher)
  if (!isApp || !self || self === device || !rule) return null
  return (
    <DetailSection
      id="destek-araclari"
      title={t("Destek araçları")}
      description={t("Salt okunur görünümler tünel üzerinden gelir. {name} cihazındaki kişi her oturumu onaylar ve oturum boyunca orada \"uzaktan bağlı\" göstergesi görünür.", { name: device })}
      framed={false}
    >
      {rule.read ? (
        <SupportTabs device={device} canKill={rule.kill} />
      ) : (
        <NoSupportRule from={self} to={device} onSigned={() => void mutate()} />
      )}
    </DetailSection>
  )
}

function NoSupportRule({ from, to, onSigned }: { from: string; to: string; onSigned: () => void }) {
  const { t } = useI18n()
  const readOnly = useReadOnly()
  const [open, setOpen] = useState(false)
  const [kill, setKill] = useState(false)
  return (
    <>
      <Empty className="border">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <LifeBuoy />
          </EmptyMedia>
          <EmptyTitle>{t("Destek kuralı yok")}</EmptyTitle>
          <EmptyDescription className="text-pretty">
            {t("{from} cihazının {to} cihazına destek vermesi için imzalı bir support kuralı gerekir. Kural yalnızca okumaya izin verir; süreç sonlandırma ayrı bir izindir.", { from, to })}
          </EmptyDescription>
        </EmptyHeader>
        {readOnly ? null : (
          <EmptyContent>
            <Button onClick={() => setOpen(true)}>{t("Destek izni ver…")}</Button>
          </EmptyContent>
        )}
      </Empty>
      <SignChangeDialog
        open={open}
        onOpenChange={(v) => {
          setOpen(v)
          if (!v) onSigned()
        }}
        title={t("{to} için destek izni", { to })}
        description={t("Ağ belgesine bir support kuralı eklenir. İlk support kuralı asgari istemci sürümünü 1.0.0-beta.2 yapar; daha eski cihazlar yeni belgeyi reddeder.")}
        extra={
          <Field orientation="horizontal">
            <Checkbox id="support-kill" checked={kill} onCheckedChange={(c) => setKill(c === true)} />
            <div className="flex flex-col gap-1">
              <FieldLabel htmlFor="support-kill">{t("Süreç sonlandırmaya da izin ver (support.kill)")}</FieldLabel>
              <FieldDescription>{t("Kritik sistem süreçleri hiçbir zaman sonlandırılamaz; her sonlandırma hedefte ayrıca onaylanır.")}</FieldDescription>
            </div>
          </Field>
        }
        endpoint="/api/support/rule"
        payload={{ from, to, allowKill: kill }}
        confirmLabel={t("İmzala ve kaydet")}
      />
    </>
  )
}

function SupportTabs({ device, canKill }: { device: string; canKill: boolean }) {
  const { t } = useI18n()
  return (
    <Tabs defaultValue="processes" className="flex flex-col gap-4">
      <TabsList className="flex-wrap">
        {KINDS.map(({ kind, label }) => (
          <TabsTrigger key={kind} value={kind}>
            {t(label)}
          </TabsTrigger>
        ))}
      </TabsList>
      {KINDS.map(({ kind }) => (
        <TabsContent key={kind} value={kind}>
          <SnapshotPanel device={device} kind={kind} canKill={canKill} />
        </TabsContent>
      ))}
    </Tabs>
  )
}

function SnapshotPanel({ device, kind, canKill }: { device: string; kind: SupportKind; canKill: boolean }) {
  const { t } = useI18n()
  const [requested, setRequested] = useState(false)
  const key = requested ? `/api/app/support/snapshot?device=${encodeURIComponent(device)}&kind=${kind}` : null
  const { data, error, isValidating, mutate } = useSWR<SupportSnapshot>(key, fetcher, {
    revalidateOnFocus: false,
    revalidateIfStale: false,
    shouldRetryOnError: false,
  })
  const busy = requested && isValidating
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-muted-foreground">
          {data ? t("Toplandı: {date}", { date: formatDateTime(data.collected_at) }) : t("Bilgi yalnızca istediğinde, karşı taraf onaylarsa toplanır.")}
        </p>
        <Button variant="outline" size="sm" disabled={busy} onClick={() => (requested ? void mutate() : setRequested(true))}>
          {busy ? <Spinner data-icon="inline-start" /> : <RefreshCw data-icon="inline-start" />}
          {requested ? t("Yenile") : t("Getir")}
        </Button>
      </div>
      {busy && !data ? (
        <p className="text-sm text-muted-foreground" role="status">
          {t("Karşı cihazdaki kişinin onayı bekleniyor; en fazla bir dakika sürer.")}
        </p>
      ) : null}
      {error ? (
        <Alert variant="destructive">
          <ShieldAlert />
          <AlertTitle>{t("Bilgi alınamadı")}</AlertTitle>
          <AlertDescription>{errorMessage(error)}</AlertDescription>
        </Alert>
      ) : null}
      {data?.truncated ? <p className="text-sm text-muted-foreground">{t("Liste uzun olduğu için kısaltıldı.")}</p> : null}
      {data ? <SnapshotTable device={device} snap={data} canKill={canKill} onKilled={() => void mutate()} /> : null}
    </div>
  )
}

function SnapshotTable({ device, snap, canKill, onKilled }: { device: string; snap: SupportSnapshot; canKill: boolean; onKilled: () => void }) {
  const { t, ts } = useI18n()
  const [target, setTarget] = useState<SupportProcess | null>(null)
  const empty = <p className="text-sm text-muted-foreground">{t("Gösterilecek bir şey yok.")}</p>

  async function kill(p: SupportProcess) {
    try {
      await post("/api/app/support/kill", { device, pid: p.pid, name: p.name })
      toast.success(t("{name} sonlandırıldı.", { name: p.name }))
      onKilled()
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setTarget(null)
    }
  }

  switch (snap.kind) {
    case "processes":
      if (!snap.processes?.length) return empty
      return (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("Program")}</TableHead>
                <TableHead className="text-right">{t("PID")}</TableHead>
                <TableHead className="text-right">{t("Bellek")}</TableHead>
                {canKill ? <TableHead className="sr-only">{t("İşlem")}</TableHead> : null}
              </TableRow>
            </TableHeader>
            <TableBody>
              {snap.processes.map((p) => (
                <TableRow key={p.pid}>
                  <TableCell className="max-w-64 truncate font-mono text-sm">{p.name}</TableCell>
                  <TableCell className="text-right font-mono tabular-nums">{p.pid}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatBytes(p.memory_kb * 1024)}</TableCell>
                  {canKill ? (
                    <TableCell className="text-right">
                      <Button variant="ghost" size="sm" onClick={() => setTarget(p)}>
                        {t("Sonlandır…")}
                      </Button>
                    </TableCell>
                  ) : null}
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <AlertDialog open={target !== null} onOpenChange={(open) => (open ? undefined : setTarget(null))}>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>{t("{name} sonlandırılsın mı?", { name: target?.name ?? "" })}</AlertDialogTitle>
                <AlertDialogDescription>
                  {t("Süreç {device} cihazında kapatılır; kaydedilmemiş çalışma kaybolabilir. Cihazdaki kişi bunu ayrıca onaylar.", { device })}
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>{t("Vazgeç")}</AlertDialogCancel>
                <AlertDialogAction variant="destructive" onClick={() => (target ? void kill(target) : undefined)}>
                  {t("Sonlandır")}
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </>
      )
    case "services":
      if (!snap.services?.length) return empty
      return (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("Hizmet")}</TableHead>
              <TableHead>{t("Durum")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {snap.services.map((s) => (
              <TableRow key={s.name}>
                <TableCell className="max-w-80">
                  <span className="block truncate font-mono text-sm">{s.name}</span>
                  {s.display ? <span className="block truncate text-sm text-muted-foreground">{s.display}</span> : null}
                </TableCell>
                <TableCell>
                  <Badge variant={s.state.startsWith("running") || s.state.startsWith("active") ? "default" : "secondary"}>{s.state}</Badge>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )
    case "events":
      if (!snap.events?.length) return empty
      return (
        <ul className="flex flex-col divide-y rounded-lg border">
          {snap.events.map((e, i) => (
            <li key={`${e.time}-${i}`} className="flex flex-col gap-1 p-3 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={e.level === "warning" ? "secondary" : "destructive"}>{e.level}</Badge>
                <span className="font-mono">{e.source}</span>
                {e.id ? <span className="text-muted-foreground">#{e.id}</span> : null}
                <span className="text-muted-foreground">{formatDateTime(e.time)}</span>
              </div>
              <p className="break-words text-pretty">{ts(e.message)}</p>
            </li>
          ))}
        </ul>
      )
    case "disks":
      if (!snap.disks?.length) return empty
      return (
        <ul className="flex flex-col gap-3">
          {snap.disks.map((d) => {
            const used = d.total_bytes > 0 ? Math.round(((d.total_bytes - d.free_bytes) / d.total_bytes) * 100) : 0
            return (
              <li key={d.mount} className="flex flex-col gap-1 text-sm">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono">{d.mount}</span>
                  <span className="text-muted-foreground tabular-nums">
                    {t("{free} boş / {total}", { free: formatBytes(d.free_bytes), total: formatBytes(d.total_bytes) })}
                  </span>
                </div>
                <div
                  role="meter"
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={used}
                  aria-label={t("{mount} doluluk", { mount: d.mount })}
                  className="h-2 overflow-hidden rounded-full bg-muted"
                >
                  <div className={used >= 90 ? "h-full bg-destructive" : "h-full bg-primary"} style={{ width: `${used}%` }} />
                </div>
              </li>
            )
          })}
        </ul>
      )
    case "startup":
      if (!snap.startup?.length) return empty
      return (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("Program")}</TableHead>
              <TableHead>{t("Konum")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {snap.startup.map((s, i) => (
              <TableRow key={`${s.location}-${s.name}-${i}`}>
                <TableCell className="max-w-72">
                  <span className="block truncate font-mono text-sm">{s.name}</span>
                  {s.command ? <span className="block truncate text-sm text-muted-foreground">{s.command}</span> : null}
                </TableCell>
                <TableCell className="max-w-72 truncate text-sm text-muted-foreground">{ts(s.location)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )
  }
  return null
}
