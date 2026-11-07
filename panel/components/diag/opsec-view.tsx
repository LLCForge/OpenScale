"use client"

import { useState } from "react"
import useSWR from "swr"
import { MapPinOff, TriangleAlert } from "lucide-react"
import { toast } from "sonner"

import { useReadOnly } from "@/components/app/read-only"
import { CodedError, optionalGet, postCoded } from "@/components/auth/strict-api"
import { PageHeader } from "@/components/page-header"
import { EmptyNote, SettingBadge, SettingsSection } from "@/components/settings/settings-layout"
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
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { errorMessage } from "@/lib/api"
import { formatAgo, formatDateTime, formatNumber } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

// Network privacy on this computer (ADR-0186..0191): traffic camouflage,
// local quarantine after a scan or decoy port touch, alarms (exit node
// interception, clone suspicion, lost mode, coordinator mismatch), the exit
// node TLS canary and the double-hop exit plan.

interface OpsecView {
  obfs: { mode: "off" | "auto" | "on"; tls: boolean; buckets: number[] | null; jitter: string; wrapped: number }
  quarantine: { peer: string; reason: string; since: string; until?: string }[] | null
  alerts: { kind: "exit_mitm" | "clone_suspect" | "lost_mode" | "coordinators" | string; peer: string; text: string; at: string }[] | null
  canary: { address: string; status: "ok" | "learned" | "mitm" | "untrusted" | "unreachable"; via_exit: string; at: string }[] | null
  chain: { entry: string; final: string; ready: boolean; reason: string } | null
  lost: { lost: boolean; since?: string } | null
}

const modeText = { off: msg("Kapalı"), auto: msg("Otomatik"), on: msg("Açık") } as const

const alertKind: Record<string, string> = {
  exit_mitm: msg("Çıkış düğümü müdahalesi"),
  clone_suspect: msg("Klon şüphesi"),
  lost_mode: msg("Kayıp kip"),
  coordinators: msg("Koordinatör tutarsızlığı"),
}

const canaryText: Record<string, { text: string; tone: "success" | "muted" | "danger" | "warning" }> = {
  ok: { text: msg("Temiz"), tone: "success" },
  learned: { text: msg("Anahtar öğrenildi"), tone: "muted" },
  mitm: { text: msg("Anahtar farklı: müdahale olabilir"), tone: "danger" },
  untrusted: { text: msg("Güvenilmeyen sertifika"), tone: "danger" },
  unreachable: { text: msg("Ulaşılamadı"), tone: "warning" },
}

// Without a running tunnel the service has no engine to read and answers
// 503; that is a normal state, not an error.
async function opsecGet(path: string): Promise<OpsecView | null | "offline"> {
  try {
    return await optionalGet<OpsecView>(path)
  } catch (err) {
    if (err instanceof CodedError && err.status === 503) return "offline"
    throw err
  }
}

export function OpsecView() {
  const { t } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<OpsecView | null | "offline">("/api/app/opsec", opsecGet, { refreshInterval: 15_000 })
  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        title={t("Ağ gizliliği")}
        description={t("Bu bilgisayarın trafiği nasıl gizlediği, karantinaya aldığı cihazlar ve ağ müdahalesi alarmları.")}
      />
      {isLoading ? (
        <div className="flex flex-col gap-4" aria-busy="true" aria-label={t("Yükleniyor")}>
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-48 w-full" />
        </div>
      ) : error ? (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertTitle>{t("Ağ gizliliği durumu okunamadı")}</AlertTitle>
          <AlertDescription className="flex flex-col gap-2">
            <span>{errorMessage(error)}</span>
            <Button variant="outline" size="sm" className="w-fit" onClick={() => mutate()}>
              {t("Tekrar dene")}
            </Button>
          </AlertDescription>
        </Alert>
      ) : data === "offline" ? (
        <EmptyNote>{t("Tünel kapalı. Ağ gizliliği durumu, bu bilgisayar ağa bağlandığında burada görünür.")}</EmptyNote>
      ) : !data ? (
        <EmptyNote>{t("Bu sürümde ağ gizliliği durumu masaüstü hizmetinden alınamıyor.")}</EmptyNote>
      ) : (
        <>
          {data.lost?.lost ? (
            <Alert variant="destructive">
              <MapPinOff />
              <AlertTitle>{t("Bu cihaz kayıp olarak işaretlendi")}</AlertTitle>
              <AlertDescription>
                {t("Yalnızca koordinatör bağlantısı açık.")}
                {data.lost.since ? ` ${t("İşaret zamanı: {at}.", { at: formatDateTime(data.lost.since) })}` : ""}
              </AlertDescription>
            </Alert>
          ) : null}
          <ObfsSection obfs={data.obfs} />
          <AlertsSection alerts={data.alerts ?? []} />
          <QuarantineSection rows={data.quarantine ?? []} onChange={() => mutate()} />
          <CanarySection rows={data.canary ?? []} />
          {data.chain ? <ChainSection chain={data.chain} /> : null}
        </>
      )}
    </div>
  )
}

function Line({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 py-2.5 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-right tabular-nums">{value}</span>
    </div>
  )
}

function ObfsSection({ obfs }: { obfs: OpsecView["obfs"] }) {
  const { t } = useI18n()
  const buckets = (obfs.buckets ?? []).join(", ")
  return (
    <SettingsSection
      id="gizleme"
      title={t("Trafik gizleme")}
      description={t("WireGuard paketleri sıradan şifreli web trafiğine benzetilir. Gizlilik WireGuard'dan gelir; bu katman yalnızca trafiğin VPN diye tanınmasını zorlaştırır.")}
    >
      <div className="flex flex-col divide-y rounded-lg border px-4" data-slot="card">
        <Line label={t("Kip")} value={modeText[obfs.mode] ? t(modeText[obfs.mode]) : obfs.mode} />
        <Line label="TCP/443 TLS" value={obfs.tls ? t("Açık") : t("Kapalı")} />
        <Line label={t("Dolgu kovaları")} value={buckets ? t("{buckets} bayt", { buckets }) : "-"} />
        <Line label={t("Zamanlama gürültüsü")} value={obfs.jitter ? t("en çok {value}", { value: obfs.jitter.replace("ms", " ms") }) : "-"} />
        <Line label={t("Gizlenen paket")} value={formatNumber(obfs.wrapped)} />
      </div>
      {obfs.mode === "on" ? (
        <p className="text-sm text-warning-foreground dark:text-warning text-pretty">
          {t("Açık kipte bütün cihazlar ve koordinatör güncel sürümde olmalı; emin değilseniz Otomatik seçin.")}
        </p>
      ) : null}
      <p className="text-sm text-muted-foreground">
        {t("Değiştirmek için:")} <code className="text-foreground">openscale opsec obfs --mode auto</code>
      </p>
    </SettingsSection>
  )
}

function AlertsSection({ alerts }: { alerts: NonNullable<OpsecView["alerts"]> }) {
  const { t, ts } = useI18n()
  return (
    <SettingsSection id="alarmlar" title={t("Ağ gizliliği alarmları")}>
      {alerts.length === 0 ? (
        <EmptyNote>{t("Alarm yok. Tuzak port dokunuşu, tarama, klon şüphesi ve çıkış düğümü müdahalesi burada görünür.")}</EmptyNote>
      ) : (
        <ul className="flex flex-col divide-y rounded-lg border" data-slot="card">
          {alerts.map((a, i) => {
            const red = a.kind === "exit_mitm" || a.kind === "coordinators"
            return (
              <li key={`${a.kind}-${a.at}-${i}`} className="flex flex-col gap-1 px-4 py-3 sm:flex-row sm:items-start sm:gap-4">
                <SettingBadge tone={red ? "danger" : "warning"}>{alertKind[a.kind] ? t(alertKind[a.kind]) : a.kind}</SettingBadge>
                <p className={cn("min-w-0 flex-1 text-sm text-pretty", red && "text-destructive")}>{ts(a.text)}</p>
                <time dateTime={a.at} title={formatDateTime(a.at)} className="shrink-0 text-xs text-muted-foreground tabular-nums">
                  {formatAgo(a.at)}
                </time>
              </li>
            )
          })}
        </ul>
      )}
    </SettingsSection>
  )
}

function QuarantineSection({ rows, onChange }: { rows: NonNullable<OpsecView["quarantine"]>; onChange: () => void }) {
  const readOnly = useReadOnly()
  const { t, ts } = useI18n()
  const [target, setTarget] = useState<string | null>(null)

  async function release(peer: string) {
    try {
      await postCoded("/api/app/opsec/quarantine/release", { peer })
      toast.success(t("{peer} karantinadan çıkarıldı.", { peer }))
      onChange()
    } catch (err) {
      toast.error(err instanceof Error ? errorMessage(err) : t("Karantina kaldırılamadı."))
    } finally {
      setTarget(null)
    }
  }

  return (
    <SettingsSection
      id="karantina"
      title={t("Karantinadaki cihazlar")}
      description={t("Karantina yalnızca bu bilgisayarda geçerlidir. Cihazı ağdan tamamen çıkarmak için Cihazlar sayfasından iptal edin (kök imzası gerekir).")}
    >
      {rows.length === 0 ? (
        <EmptyNote>{t("Karantinada cihaz yok.")}</EmptyNote>
      ) : (
        <div className="overflow-x-auto rounded-lg border" data-slot="card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">{t("Cihaz")}</TableHead>
                <TableHead scope="col">{t("Neden")}</TableHead>
                <TableHead scope="col">{t("Başlangıç")}</TableHead>
                <TableHead scope="col">{t("Bitiş")}</TableHead>
                <TableHead scope="col">
                  <span className="sr-only">{t("İşlem")}</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((q) => (
                <TableRow key={q.peer}>
                  <TableCell className="font-medium">{q.peer}</TableCell>
                  <TableCell className="max-w-80 text-sm whitespace-normal text-pretty">{ts(q.reason)}</TableCell>
                  <TableCell className="tabular-nums">{formatDateTime(q.since)}</TableCell>
                  <TableCell className="tabular-nums">{q.until ? formatDateTime(q.until) : t("Siz kaldırana dek")}</TableCell>
                  <TableCell className="text-right">
                    <Button size="sm" variant="outline" disabled={readOnly} onClick={() => setTarget(q.peer)}>
                      {t("Karantinayı kaldır")}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      <AlertDialog open={target !== null} onOpenChange={(open) => (open ? undefined : setTarget(null))}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("{peer} karantinadan çıksın mı?", { peer: target ?? "" })}</AlertDialogTitle>
            <AlertDialogDescription>{t("Bu cihazın bu bilgisayarla bağlantısı yeniden açılacak. Emin misiniz?")}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("Vazgeç")}</AlertDialogCancel>
            <AlertDialogAction onClick={() => (target ? release(target) : undefined)}>{t("Karantinayı kaldır")}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </SettingsSection>
  )
}

function CanarySection({ rows }: { rows: NonNullable<OpsecView["canary"]> }) {
  const { t } = useI18n()
  return (
    <SettingsSection
      id="kanarya"
      title={t("Çıkış düğümü TLS denetimi")}
      description={t("Bilinen sunucuların anahtarı çıkış düğümü kullanılırken karşılaştırılır; fark, trafiğe müdahale edildiğini gösterebilir.")}
    >
      {rows.length === 0 ? (
        <EmptyNote>
          {t("Denetlenecek sunucu yok. Eklemek için:")} <code className="text-foreground">{t("openscale opsec canary --add sunucu:443")}</code>
        </EmptyNote>
      ) : (
        <div className="overflow-x-auto rounded-lg border" data-slot="card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">{t("Sunucu")}</TableHead>
                <TableHead scope="col">{t("Durum")}</TableHead>
                <TableHead scope="col">{t("Çıkış düğümü")}</TableHead>
                <TableHead scope="col">{t("Zaman")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((c) => {
                const known = canaryText[c.status]
                const s = known ? { text: t(known.text), tone: known.tone } : { text: c.status, tone: "muted" as const }
                return (
                  <TableRow key={`${c.address}-${c.via_exit}`}>
                    <TableCell className="font-mono text-xs">{c.address}</TableCell>
                    <TableCell>
                      <SettingBadge tone={s.tone}>{s.text}</SettingBadge>
                    </TableCell>
                    <TableCell>{c.via_exit || "-"}</TableCell>
                    <TableCell className="tabular-nums">{formatAgo(c.at)}</TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>
      )}
    </SettingsSection>
  )
}

function ChainSection({ chain }: { chain: NonNullable<OpsecView["chain"]> }) {
  const { t, ts } = useI18n()
  if (!chain.entry && !chain.final) return null
  return (
    <SettingsSection id="cift-cikis" title={t("Çift sıçramalı çıkış")} description={t("Bu sürümde zincir planı denetlenir; yönlendirme henüz bağlı değil.")}>
      <div className="flex flex-col gap-1 rounded-lg border px-4 py-3 text-sm" data-slot="card">
        <p>
          {t("Giriş düğümü:")} <span className="font-medium">{chain.entry || "-"}</span> → {t("Son düğüm:")} <span className="font-medium">{chain.final || "-"}</span>
        </p>
        {chain.ready ? (
          <p className="text-muted-foreground">{t("Plan geçerli.")}</p>
        ) : (
          <p className="text-warning-foreground dark:text-warning">{ts(chain.reason)}</p>
        )}
      </div>
    </SettingsSection>
  )
}
