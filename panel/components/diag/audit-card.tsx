"use client"

import Link from "next/link"
import useSWR from "swr"
import { ShieldCheck, ShieldAlert } from "lucide-react"

import { DetailSection } from "@/components/devices/detail-card"
import { DiagSectionState } from "@/components/diag/diag-errors"
import { headCell, ListTable } from "@/components/settings/list-table"
import { EmptyNote, SettingBadge } from "@/components/settings/settings-layout"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { fetcher } from "@/lib/api"
import { formatAgo, formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { AuditReply } from "@/lib/observe"
import { cn } from "@/lib/utils"

const severityTone = {
  info: "muted",
  warning: "warning",
  critical: "danger",
} as const

const severityLabel = { info: msg("Bilgi"), warning: msg("Uyarı"), critical: msg("Kritik") } as const

/** Pages where the owner acts on an event (P07: sync guard, backups, DDNS). */
function eventLink(kind: string): { href: string; label: string } | null {
  if (kind.startsWith("sync_") || kind.startsWith("backup_probe")) return { href: "/sync", label: msg("Eşitleme sayfasına git") }
  if (kind.startsWith("ddns_")) return { href: "/settings/local#ddns", label: msg("Dinamik DNS ayarlarına git") }
  if (kind === "file_link_created") return { href: "/inbox#sureli-baglanti", label: msg("Süreli bağlantılar") }
  return null
}

/**
 * The security event log (#187) with its hash chain check (#188): every
 * record carries the SHA-256 of the one before it, so an edited or removed
 * record is found. The log never leaves this computer.
 */
export function AuditCard() {
  const { t, ts } = useI18n()
  const { data, error, isLoading } = useSWR<AuditReply>("/api/app/diag/audit?n=30", fetcher, { refreshInterval: 60_000 })
  const records = data?.records ?? []
  const verify = data?.verify
  return (
    <DetailSection
      id="denetim-kaydi"
      title={t("Denetim kaydı")}
      description={
        <>
          {t(
            "Belge değişiklikleri, eklenen ve iptal edilen cihazlar, reddedilen belgeler, sızıntı kilidi (kill switch), eşitleme koruması ve yerel ayar değişiklikleri. Hash zinciriyle saklanır; doğrulamak için",
          )}{" "}
          <code className="font-mono text-[0.8125rem]">openscale audit verify</code>.
        </>
      }
      framed={false}
      action={
        verify?.ok ? (
          <span className="flex items-center gap-1.5 text-sm text-muted-foreground">
            <ShieldCheck className="size-4 text-success" aria-hidden="true" />
            {t("Zincir sağlam: {count} kayıt", { count: verify.records })}
            {verify.records > 0 ? ` (#${verify.first_seq}–#${verify.last_seq})` : ""}
          </span>
        ) : null
      }
    >
      <DiagSectionState section={t("Denetim kaydı")} error={error} isLoading={isLoading}>
        {verify && !verify.ok ? (
          <Alert variant="destructive">
            <ShieldAlert />
            <AlertTitle>{t("Denetim kaydının zinciri bozuk")}</AlertTitle>
            <AlertDescription>
              <ul className="flex list-disc flex-col gap-1 pl-4">
                {verify.problems.slice(0, 5).map((p) => (
                  <li key={p} className="text-pretty">
                    {ts(p)}
                  </li>
                ))}
              </ul>
            </AlertDescription>
          </Alert>
        ) : null}
        {records.length === 0 ? (
          <EmptyNote>{t("Henüz güvenlik olayı yok. Ağ belgesi değiştiğinde veya bir cihaz eklendiğinde burada görünür.")}</EmptyNote>
        ) : (
          <ListTable label={t("Güvenlik olayları")} className="max-h-[28rem] overflow-y-auto">
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className={cn(headCell, "w-32")}>{t("Zaman")}</TableHead>
                <TableHead className={cn(headCell, "hidden w-28 sm:table-cell")}>{t("Önem")}</TableHead>
                <TableHead className={headCell}>{t("Olay")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {records.map((r) => (
                <TableRow key={r.seq}>
                  <TableCell className="text-sm text-muted-foreground">
                    <time dateTime={r.at} title={formatDateTime(r.at)}>
                      {formatAgo(r.at)}
                    </time>
                  </TableCell>
                  <TableCell className="hidden sm:table-cell">
                    <SettingBadge tone={severityTone[r.severity] ?? "muted"}>{severityLabel[r.severity] ? t(severityLabel[r.severity]) : r.severity}</SettingBadge>
                  </TableCell>
                  <TableCell className="min-w-40 text-sm leading-relaxed whitespace-normal text-pretty">
                    <span className="flex flex-col items-start gap-1">
                      <span className="sm:hidden">
                        <SettingBadge tone={severityTone[r.severity] ?? "muted"}>{severityLabel[r.severity] ? t(severityLabel[r.severity]) : r.severity}</SettingBadge>
                      </span>
                      {ts(r.message)}
                      {eventLink(r.kind) ? (
                        <Link href={eventLink(r.kind)?.href ?? "/"} className="text-muted-foreground underline underline-offset-4 hover:text-foreground">
                          {t(eventLink(r.kind)?.label ?? "")}
                        </Link>
                      ) : null}
                    </span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </ListTable>
        )}
      </DiagSectionState>
    </DetailSection>
  )
}
