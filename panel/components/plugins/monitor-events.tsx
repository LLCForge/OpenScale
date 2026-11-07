"use client"

import useSWR from "swr"

import { EmptyNote, SettingBadge, SettingRow, SettingsSection } from "@/components/settings/settings-layout"
import { fetcher } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"

interface DiagEvent {
  at: string
  kind: string
  peer?: string
  message: string
}

type Tone = "success" | "warning" | "danger" | "muted"

/** Event kinds the service's monitor (w4_monitor.go) adds to the event list. */
const monitorKinds: Record<string, { label: string; tone: Tone }> = {
  service_down: { label: msg("Servis düştü"), tone: "danger" },
  service_up: { label: msg("Servis döndü"), tone: "success" },
  device_offline: { label: msg("Cihaz çevrimdışı"), tone: "warning" },
  device_online: { label: msg("Cihaz döndü"), tone: "success" },
  device_joined: { label: msg("Cihaz katıldı"), tone: "muted" },
  device_left: { label: msg("Cihaz ayrıldı"), tone: "muted" },
  device_renamed: { label: msg("Ad değişti"), tone: "muted" },
  disk_low: { label: msg("Disk doluyor"), tone: "warning" },
  disk_ok: { label: msg("Disk düzeldi"), tone: "success" },
  battery_worn: { label: msg("Pil yıpranmış"), tone: "warning" },
  battery_low: { label: msg("Pil azaldı"), tone: "warning" },
  lan_device_new: { label: msg("Yeni LAN cihazı"), tone: "warning" },
  port_open: { label: msg("Açık port"), tone: "danger" },
  port_closed: { label: msg("Port kapandı"), tone: "success" },
  ids_alert: { label: msg("Saldırı belirtisi"), tone: "danger" },
  blocklist_error: { label: msg("Engel listesi"), tone: "warning" },
}

/** İzleme olayları: the monitoring subset of the service's in-memory event list. */
export function MonitorEventsSection() {
  const { t, ts } = useI18n()
  const { data, error } = useSWR<{ events: DiagEvent[] }>("/api/app/diag/events", fetcher, { refreshInterval: 15000 })
  const events = (data?.events ?? []).filter((e) => e.kind in monitorKinds).slice(0, 50)
  return (
    <SettingsSection
      title={t("Olaylar")}
      description={t(
        "İzlemenin bulduğu son olaylar: servis ve cihaz durumu, disk ve pil, yeni LAN cihazı, internete açık port ve tünel içi tarama belirtileri. Yalnızca bellekte tutulur; adres içermez.",
      )}
    >
      {error ? (
        <EmptyNote>{t("Olaylar alınamadı.")}</EmptyNote>
      ) : events.length === 0 ? (
        <EmptyNote>{t("Henüz izleme olayı yok.")}</EmptyNote>
      ) : (
        events.map((e, i) => {
          const k = monitorKinds[e.kind]
          return (
            <SettingRow
              key={`${e.at}-${i}`}
              title={ts(e.message)}
              description={`${formatDateTime(e.at)}${e.peer ? ` · ${e.peer}` : ""}`}
              badge={<SettingBadge tone={k.tone}>{t(k.label)}</SettingBadge>}
            />
          )
        })
      )}
    </SettingsSection>
  )
}
