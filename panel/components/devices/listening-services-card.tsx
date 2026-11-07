"use client"

import useSWR from "swr"

import { DetailCard } from "@/components/devices/detail-card"
import { Badge } from "@/components/ui/badge"
import { Spinner } from "@/components/ui/spinner"
import { ApiError, fetcher } from "@/lib/api"
import { formatAgo } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"

// Listening services of a device (F-220, ADR-0108): the TCP ports the
// device's system report lists outside loopback, with what the signed
// rules allow. The report reaches only admin devices through the tunnel.

interface ListeningService {
  port: number
  name?: string
  risky: boolean
  openscale: boolean
  reachable_from: string[]
  hint?: string
}

interface ServicesReply {
  schema: number
  device: string
  reported: boolean
  at?: string
  services: ListeningService[]
}

const description = msg("Cihazın tünel dışı adreslerde dinlediği TCP portları; liste koordinatöre gönderilmez.")

export function ListeningServicesCard({ device }: { device: string }) {
  const { t, ts } = useI18n()
  const { data, error, isLoading } = useSWR<ServicesReply>(
    `/api/v1/devices/${encodeURIComponent(device)}/services`,
    fetcher,
    { refreshInterval: 60_000 },
  )

  let body: React.ReactNode
  if (isLoading) {
    body = (
      <p className="flex items-center gap-2 py-2.5 text-sm text-muted-foreground">
        <Spinner /> {t("Yükleniyor")}
      </p>
    )
  } else if (error) {
    const message =
      error instanceof ApiError && error.status === 409
        ? t("Cihaz raporları yalnızca OpenScale servisi çalışırken toplanır.")
        : t("Dinlenen servisler alınamadı.")
    body = <p className="py-2.5 text-sm text-muted-foreground">{message}</p>
  } else if (!data || !data.reported) {
    body = <p className="py-2.5 text-sm text-muted-foreground">{t("Bu cihazdan henüz rapor gelmedi.")}</p>
  } else if (data.services.length === 0) {
    body = <p className="py-2.5 text-sm text-muted-foreground">{t("Tünel dışında dinlenen TCP portu yok.")}</p>
  } else {
    body = (
      <ul className="flex flex-col divide-y" aria-label={t("Dinlenen portlar")}>
        {data.services.map((s) => (
          <li key={s.port} className="flex flex-col gap-1.5 py-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm">{s.port}</span>
              <span className="text-sm">{s.name ?? t("Bilinmeyen servis")}</span>
              {s.risky ? <Badge variant="destructive">{t("Hassas")}</Badge> : null}
              {s.openscale ? <Badge variant="secondary">OpenScale</Badge> : null}
              <span className="ml-auto text-xs text-muted-foreground">
                {s.reachable_from.length === 0
                  ? t("Tünelden erişim kuralı yok")
                  : t("Tünelden erişebilen: {names}", { names: s.reachable_from.join(", ") })}
              </span>
            </div>
            {s.hint ? <p className="text-pretty text-sm leading-relaxed text-muted-foreground">{ts(s.hint)}</p> : null}
          </li>
        ))}
      </ul>
    )
  }

  return (
    <DetailCard
      title={t("Dinlenen servisler")}
      description={data?.at ? t("{description} Son rapor: {ago}.", { description: t(description), ago: formatAgo(data.at) }) : t(description)}
    >
      {body}
    </DetailCard>
  )
}
