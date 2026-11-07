"use client"

import { useState } from "react"
import Link from "next/link"
import useSWR from "swr"
import { CircleCheck, CircleX, TriangleAlert, Wrench } from "lucide-react"
import { toast } from "sonner"

import { useReadOnly } from "@/components/app/read-only"
import { EmptyNote, SettingBadge, SettingDisclosure, SettingRow, SettingsSection } from "@/components/settings/settings-layout"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { ApiError, errorMessage, fetcher, post } from "@/lib/api"
import { formatBytes, formatDateTime } from "@/lib/format"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import type { PlatformCheck, PlatformStatus } from "@/lib/platform-types"
import { cn } from "@/lib/utils"

// Platform (P10, #498, #392, #494, #490): the operating system, the self
// repair after an OS update, the memory profile and the service's resource
// limit. Repair only touches this computer's own system settings; it needs
// no signature but is refused in a read-only panel.

const KEY = "/api/app/platform"

const families: Record<string, string> = { windows: "Windows", linux: "Linux", darwin: "macOS", freebsd: "FreeBSD" }

const checkIcon: Record<PlatformCheck["level"], { icon: typeof CircleCheck; className: string; label: string }> = {
  ok: { icon: CircleCheck, className: "text-success", label: msg("Sorun yok") },
  repaired: { icon: Wrench, className: "text-foreground", label: msg("Onarıldı") },
  warn: { icon: TriangleAlert, className: "text-warning-foreground dark:text-warning", label: msg("Uyarı") },
  error: { icon: CircleX, className: "text-destructive", label: msg("Hata") },
}

function osLine(s: PlatformStatus): string {
  const o = s.os
  const parts = [families[o.family] ?? o.family]
  if (o.version) parts[0] = `${parts[0]} ${o.version}`
  if (o.build) parts.push(tx("derleme {build}", { build: `${o.build}${o.patch ? `.${o.patch}` : ""}` }))
  parts.push(o.arch)
  return parts.join(" · ")
}

export function PlatformSection() {
  const { t, ts } = useI18n()
  const { data, error, mutate } = useSWR<PlatformStatus>(KEY, fetcher, {
    refreshInterval: (d) => (d?.repairing ? 3_000 : 60_000),
    shouldRetryOnError: (err: unknown) => !(err instanceof ApiError && err.status === 404),
  })
  const readOnly = useReadOnly()
  const [busy, setBusy] = useState(false)

  // An older service has no platform endpoint: no section.
  if (error instanceof ApiError && error.status === 404) return null
  if (!data) return null

  async function repair() {
    setBusy(true)
    try {
      const res = await post<PlatformStatus>(`${KEY}/repair`, {})
      await mutate(res, { revalidate: false })
      const checks = res.last_repair?.checks ?? []
      const fixed = checks.filter((c) => c.level === "repaired").length
      const warned = checks.filter((c) => c.level === "warn" || c.level === "error").length
      toast.success(t("Denetim bitti: {fixed} sorun onarıldı, {warned} uyarı.", { fixed, warned }))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const r = data.last_repair
  const m = data.memory
  const working = busy || data.repairing === true
  return (
    <SettingsSection
      id="platform"
      title={t("Platform")}
      description={t("İşletim sistemi, güncelleme sonrası öz onarım ve OpenScale servisinin bellek sınırları.")}
    >
      {data.os_update ? (
        <Alert className="my-4">
          <TriangleAlert />
          <AlertDescription className="text-pretty">
            {t("İşletim sistemi güncellendi ({from} → {to}). OpenScale ayarları tünel açılınca denetlenip onarılacak.", {
              from: data.os_update.from,
              to: data.os_update.to,
            })}
          </AlertDescription>
        </Alert>
      ) : null}
      <SettingRow
        title={t("İşletim sistemi")}
        badge={
          data.os.server_core ? (
            <SettingBadge>{t("Server Core: tepsi yok")}</SettingBadge>
          ) : data.os.edition && data.os.edition !== "Client" ? (
            <SettingBadge>{data.os.edition}</SettingBadge>
          ) : null
        }
        description={
          <>
            <span className="font-mono text-[0.8125rem]">{osLine(data)}</span>
            {data.os.server_core ? <span className="block">{t("Bu sunucuda masaüstü yok; yönetim komut satırıyla veya bu panelden yapılır.")}</span> : null}
          </>
        }
      />
      <SettingRow
        title={t("Öz onarım")}
        description={
          r
            ? r.reason === "os-update"
              ? t("Son onarım: {time} (güncelleme sonrası).", { time: formatDateTime(r.at) })
              : t("Son onarım: {time} (elle).", { time: formatDateTime(r.at) })
            : t("Henüz onarım yapılmadı. İşletim sistemi güncellendiğinde OpenScale kendi ayarlarını kendiliğinden denetler.")
        }
        action={
          readOnly ? null : (
            <Button variant="outline" disabled={working} onClick={repair}>
              {working ? <Spinner data-icon="inline-start" /> : <Wrench data-icon="inline-start" />}
              {working ? t("Denetleniyor…") : t("Şimdi denetle ve onar")}
            </Button>
          )
        }
      >
        {r && r.checks.length > 0 ? (
          <ul className="flex flex-col divide-y border-y text-sm">
            {r.checks.map((c, i) => {
              const k = checkIcon[c.level] ?? checkIcon.warn
              const Icon = k.icon
              return (
                <li key={`${c.area}-${i}`} className="flex items-start gap-2.5 py-2.5">
                  <Icon className={cn("mt-0.5 size-4 shrink-0", k.className)} aria-label={t(k.label)} role="img" />
                  <span className="flex min-w-0 flex-col gap-0.5">
                    <span className="font-medium">{ts(c.area)}</span>
                    <span className="text-muted-foreground text-pretty">{ts(c.message)}</span>
                  </span>
                </li>
              )
            })}
          </ul>
        ) : null}
      </SettingRow>
      <SettingRow
        title={t("Bellek")}
        badge={m.profile === "low" ? <SettingBadge>{t("Düşük bellek profili")}</SettingBadge> : null}
        description={
          <>
            {m.budget
              ? t("{used} / {total} kullanılıyor.", { used: formatBytes(m.live), total: formatBytes(m.budget) })
              : t("{used} kullanılıyor.", { used: formatBytes(m.live) })}{" "}
            <Link href="/diag#tuketim" className="underline underline-offset-4 hover:text-foreground">
              {t("Tüketimi gör")}
            </Link>
          </>
        }
      >
        {m.budget ? <MemoryBar used={m.live} total={m.budget} /> : null}
      </SettingRow>
      {data.limits ? (
        <SettingRow
          title={t("Servis bellek tavanı")}
          badge={data.limits.applied ? null : <SettingBadge tone="warning">{t("Uygulanmadı")}</SettingBadge>}
          description={
            <>
              {data.limits.memory_max ? formatBytes(data.limits.memory_max) : t("Sınırsız")}
              {data.limits.mechanism ? ` (${data.limits.mechanism === "job" ? t("Windows iş nesnesi") : data.limits.mechanism})` : ""}
              {data.limits.cpu_percent ? t(", işlemci en çok %{percent}", { percent: data.limits.cpu_percent }) : ""}.
              {!data.limits.applied && data.limits.error ? <span className="block text-destructive">{ts(data.limits.error)}</span> : null}
            </>
          }
        />
      ) : null}
      {data.wsl && (data.wsl.notes?.length ?? 0) > 0 ? (
        <SettingDisclosure
          title={t("WSL2 ile kullanım")}
          description={data.wsl.mode ? t("WSL {version}, {mode} kipi.", { version: data.wsl.version ?? 2, mode: data.wsl.mode }) : t("WSL kurulu.")}
          openLabel={t("Önerileri göster")}
        >
          <ul className="flex list-disc flex-col gap-1 pl-5 text-sm text-muted-foreground">
            {data.wsl.notes?.map((n) => (
              <li key={n} className="text-pretty">
                {ts(n)}
              </li>
            ))}
          </ul>
        </SettingDisclosure>
      ) : null}
      {(data.notes ?? []).length > 0 ? (
        <SettingRow title={t("Notlar")}>
          <ul className="flex list-disc flex-col gap-1 pl-5 text-sm text-muted-foreground">
            {data.notes?.map((n) => (
              <li key={n} className="text-pretty">
                {ts(n)}
              </li>
            ))}
          </ul>
        </SettingRow>
      ) : null}
      {data.repairing && !busy ? <EmptyNote framed={false}>{t("Onarım sürüyor…")}</EmptyNote> : null}
    </SettingsSection>
  )
}

function MemoryBar({ used, total }: { used: number; total: number }) {
  const { t } = useI18n()
  const share = Math.min(1, used / Math.max(1, total))
  return (
    <svg viewBox="0 0 100 4" preserveAspectRatio="none" className="h-1.5 w-full max-w-sm rounded-full bg-secondary" role="img" aria-label={t("Bellek bütçesinin yüzde {percent} kadarı kullanılıyor", { percent: Math.round(share * 100) })}>
      <rect x={0} y={0} width={share * 100} height={4} rx={2} className={share > 0.9 ? "fill-warning" : "fill-foreground/70"} />
    </svg>
  )
}
