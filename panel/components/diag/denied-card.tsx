"use client"

import { useState } from "react"
import useSWR from "swr"
import { Trash2 } from "lucide-react"
import { toast } from "sonner"

import { Writable } from "@/components/app/read-only"
import { DetailSection } from "@/components/devices/detail-card"
import { DiagSectionState } from "@/components/diag/diag-errors"
import { headCell, ListTable } from "@/components/settings/list-table"
import { EmptyNote, SettingBadge } from "@/components/settings/settings-layout"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { errorMessage, fetcher, post } from "@/lib/api"
import { formatAgo, formatDateTime } from "@/lib/format"
import { useI18n } from "@/lib/i18n/i18n"
import { denyReasonLabels, type DeniedEntry, type DeniedReply } from "@/lib/observe"
import { cn } from "@/lib/utils"

function reasonTone(reason: string): "muted" | "warning" | "danger" {
  switch (reason) {
    case "deny_rule":
    case "unknown_peer":
    case "not_for_device":
      return "danger"
    case "no_rule":
    case "disabled_rule":
      return "warning"
    default:
      return "muted"
  }
}

function target(e: DeniedEntry): string {
  return e.port ? `${e.proto}/${e.port}` : e.proto
}

function DeniedRow({ e }: { e: DeniedEntry }) {
  const { t, ts } = useI18n()
  const who = e.peer || e.remote || t("bilinmeyen")
  const flow = e.direction === "in" ? t("{who} → bu cihaz", { who }) : t("bu cihaz → {who}", { who })
  const reason = denyReasonLabels[e.reason] ? t(denyReasonLabels[e.reason]) : e.reason
  return (
    <TableRow>
      <TableCell className="whitespace-normal">
        <div className="flex min-w-0 flex-col gap-1">
          <span className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium">{flow}</span>
            <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[0.8125rem]">{target(e)}</code>
          </span>
          <span className="text-sm leading-relaxed text-pretty text-muted-foreground">{ts(e.why)}</span>
          <span className="sm:hidden">
            <SettingBadge tone={reasonTone(e.reason)}>{reason}</SettingBadge>
          </span>
        </div>
      </TableCell>
      <TableCell className="hidden sm:table-cell">
        <SettingBadge tone={reasonTone(e.reason)}>{reason}</SettingBadge>
      </TableCell>
      <TableCell className="text-sm text-muted-foreground">
        <span className="flex flex-col gap-0.5">
          <span>{t("{count} kez", { count: e.count })}</span>
          <time dateTime={e.last} title={formatDateTime(e.last)}>
            {formatAgo(e.last)}
          </time>
        </span>
      </TableCell>
    </TableRow>
  )
}

/**
 * Refused connections and why they did not open (F-199, #107). The packet
 * filter keeps the last 256 kinds in memory; other devices appear by name,
 * other addresses only masked.
 */
export function DeniedCard() {
  const { t } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<DeniedReply>("/api/app/diag/denied", fetcher, { refreshInterval: 30_000 })
  const [busy, setBusy] = useState(false)
  const entries = data?.entries ?? []

  async function clear() {
    setBusy(true)
    try {
      await post("/api/app/diag/denied/clear", {})
      await mutate()
      toast.success(t("Liste temizlendi."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <DetailSection
      id="reddedilenler"
      title={t("Reddedilen bağlantılar")}
      description={
        <>
          {t(
            "Bir bağlantı neden açılmadı? Kural yok, reddet kuralı, devre dışı kural veya kalkan. Yalnızca bellekte tutulur; diğer adresler kısaltılır. Komut satırında:",
          )}{" "}
          <code className="font-mono text-[0.8125rem]">openscale denied</code>.
        </>
      }
      framed={false}
      action={
        entries.length > 0 ? (
          <Writable>
            <Button variant="outline" onClick={clear} disabled={busy}>
              {busy ? <Spinner data-icon="inline-start" /> : <Trash2 data-icon="inline-start" />}
              {t("Temizle")}
            </Button>
          </Writable>
        ) : null
      }
    >
      <DiagSectionState section={t("Reddedilen bağlantılar")} error={error} isLoading={isLoading}>
        {entries.length === 0 ? (
          <EmptyNote>{t("Reddedilen bağlantı yok. Kuralların izin vermediği bir bağlantı denendiğinde burada nedeniyle birlikte görünür.")}</EmptyNote>
        ) : (
          <ListTable label={t("Reddedilen bağlantılar")}>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className={headCell}>{t("Bağlantı")}</TableHead>
                <TableHead className={cn(headCell, "hidden sm:table-cell")}>{t("Neden")}</TableHead>
                <TableHead className={cn(headCell, "w-28")}>{t("Son")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {entries.slice(0, 50).map((e) => (
                <DeniedRow key={`${e.direction}-${e.peer ?? e.remote}-${e.proto}-${e.port ?? 0}-${e.reason}`} e={e} />
              ))}
            </TableBody>
          </ListTable>
        )}
      </DiagSectionState>
    </DetailSection>
  )
}
