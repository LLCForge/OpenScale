"use client"

import { useState } from "react"
import Link from "next/link"
import useSWR from "swr"
import { UserRoundPlus } from "lucide-react"

import { Writable } from "@/components/app/read-only"
import { GuestWizard } from "@/components/devices/guest-wizard"
import { CountBadge, PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { SettingBadge } from "@/components/settings/settings-layout"
import { Button } from "@/components/ui/button"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { fetcher } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { GuestView, GuestsResponse } from "@/lib/p02-types"

// Cihazlar > Konuklar (#368): every guest the wizard created, with the
// devices that joined with its invite and the time-limited rules.

export function GuestsView() {
  const { t } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<GuestsResponse>("/api/p02/guests", fetcher, { refreshInterval: 30_000 })
  const [adding, setAdding] = useState(false)
  const guests = data?.guests ?? []
  const active = guests.filter((g) => !g.expired)

  return (
    <>
      <PageHeader
        title={msg("Konuklar")}
        badge={data ? <CountBadge>{t("{count} etkin", { count: active.length })}</CountBadge> : null}
        description={msg("Süreli konuk erişimleri: bir davet ve yalnızca seçilen cihaza, seçilen süre boyunca izin veren bir kural.")}
        actions={
          <Writable>
            <Button onClick={() => setAdding(true)}>
              <UserRoundPlus data-icon="inline-start" />
              {t("Konuk ekle")}
            </Button>
          </Writable>
        }
      />
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {guests.length === 0 ? (
          <Empty className="border">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <UserRoundPlus />
              </EmptyMedia>
              <EmptyTitle>{t("Konuk yok")}</EmptyTitle>
              <EmptyDescription className="text-pretty">
                {t(
                  "Bir misafire veya teknik servise tek cihazın tek hizmetine birkaç saatlik erişim vermek için Konuk ekle'yi kullan. Süre dolunca kural kendiliğinden çalışmaz."
                )}
              </EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <ul className="flex flex-col divide-y rounded-lg border">
            {guests.map((g) => (
              <GuestRow key={g.tag} guest={g} />
            ))}
          </ul>
        )}
      </QueryState>
      <GuestWizard open={adding} onOpenChange={setAdding} />
    </>
  )
}

function GuestRow({ guest }: { guest: GuestView }) {
  const { t } = useI18n()
  const invitePending = guest.inviteExpiresAt && guest.devices.length === 0
  return (
    <li className="flex flex-col gap-3 px-4 py-4 md:flex-row md:items-start md:justify-between md:gap-8">
      <div className="flex min-w-0 flex-col gap-1.5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium">{guest.rules[0]?.description || t("Konuk erişimi")}</span>
          {guest.expired ? <SettingBadge>{t("Süresi doldu")}</SettingBadge> : <SettingBadge tone="success">{t("Etkin")}</SettingBadge>}
        </div>
        <span className="font-mono text-[0.8125rem] text-muted-foreground">tag:{guest.tag}</span>
        <ul className="flex flex-col gap-0.5">
          {guest.rules.map((r) => (
            <li key={r.index} className="font-mono text-[0.8125rem] break-all">
              {r.text}
            </li>
          ))}
        </ul>
      </div>
      <dl className="grid shrink-0 grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm md:text-right">
        <dt className="text-muted-foreground">{t("Bitiş")}</dt>
        <dd>{guest.until ? formatDateTime(guest.until) : t("Süresiz")}</dd>
        <dt className="text-muted-foreground">{t("Cihaz")}</dt>
        <dd>
          {guest.devices.length > 0
            ? guest.devices.map((d, i) => (
                <span key={d}>
                  {i > 0 ? ", " : ""}
                  <Link href={`/devices/detail?name=${encodeURIComponent(d)}`} className="hover:underline">
                    {d}
                  </Link>
                </span>
              ))
            : invitePending
              ? t("Davet {date} tarihine kadar bekliyor", { date: formatDateTime(guest.inviteExpiresAt ?? "") })
              : t("Katılmadı")}
        </dd>
      </dl>
    </li>
  )
}
