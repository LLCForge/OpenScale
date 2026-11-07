"use client"

import useSWR from "swr"

import { DetailSection } from "@/components/devices/detail-card"
import { DiagSectionState } from "@/components/diag/diag-errors"
import { headCell, ListTable } from "@/components/settings/list-table"
import { EmptyNote, SettingBadge } from "@/components/settings/settings-layout"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { fetcher } from "@/lib/api"
import type { EventsReply } from "@/lib/diag"
import { formatAgo, formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

const kindLabels: Record<string, { label: string; tone: "muted" | "warning" | "danger" | "success" }> = {
  peer_online: { label: msg("Çevrimiçi"), tone: "success" },
  peer_offline: { label: msg("Çevrimdışı"), tone: "muted" },
  peer_relayed: { label: msg("Aktarıcıya düştü"), tone: "warning" },
  peer_direct: { label: msg("Doğrudan"), tone: "success" },
  tunnel_up: { label: msg("Tünel"), tone: "success" },
  tunnel_down: { label: msg("Tünel"), tone: "danger" },
  captive_portal: { label: msg("Giriş sayfası"), tone: "danger" },
  captive_portal_cleared: { label: msg("Giriş sayfası"), tone: "muted" },
  coordinator_lost: { label: msg("Koordinatör"), tone: "danger" },
  coordinator_back: { label: msg("Koordinatör"), tone: "success" },
}

/**
 * The service's event list (F-017): online/offline peers, relay fallbacks,
 * the tunnel and the coordinator. It is kept in memory only and holds no
 * addresses.
 */
export function EventsCard() {
  const { t, ts } = useI18n()
  const { data, error, isLoading } = useSWR<EventsReply>("/api/app/diag/events", fetcher, { refreshInterval: 10_000 })
  const events = data?.events ?? []
  return (
    <DetailSection
      id="olaylar"
      title={t("Olaylar")}
      description={t("Servis çalıştığı sürece son 200 bağlantı olayı. Yalnızca bellekte tutulur; adres içermez.")}
      framed={false}
    >
      <DiagSectionState section={t("Olaylar")} error={error} isLoading={isLoading}>
        {events.length === 0 ? (
          <EmptyNote>{t("Henüz olay yok. Bir eş çevrimiçi olduğunda, düştüğünde veya aktarıcıya geçtiğinde burada görünür.")}</EmptyNote>
        ) : (
          <ListTable label={t("Olaylar")} className="max-h-[28rem] overflow-y-auto">
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className={cn(headCell, "w-32")}>{t("Zaman")}</TableHead>
                <TableHead className={cn(headCell, "hidden w-40 sm:table-cell")}>{t("Tür")}</TableHead>
                <TableHead className={headCell}>{t("Olay")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {events.map((e, i) => {
                const known = kindLabels[e.kind]
                const k = known ? { label: t(known.label), tone: known.tone } : { label: e.kind, tone: "muted" as const }
                return (
                  <TableRow key={`${e.at}-${i}`}>
                    <TableCell className="text-sm text-muted-foreground">
                      <time dateTime={e.at} title={formatDateTime(e.at)}>
                        {formatAgo(e.at)}
                      </time>
                    </TableCell>
                    <TableCell className="hidden sm:table-cell">
                      <SettingBadge tone={k.tone}>{k.label}</SettingBadge>
                    </TableCell>
                    <TableCell className="min-w-40 text-sm leading-relaxed whitespace-normal text-pretty">
                      <span className="flex flex-col items-start gap-1">
                        <span className="sm:hidden">
                          <SettingBadge tone={k.tone}>{k.label}</SettingBadge>
                        </span>
                        {ts(e.message)}
                      </span>
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </ListTable>
        )}
      </DiagSectionState>
    </DetailSection>
  )
}
