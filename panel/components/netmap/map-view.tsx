"use client"

import Link from "next/link"
import useSWR from "swr"
import { Network, Rocket } from "lucide-react"

import { ConnectionHistoryCard } from "@/components/netmap/connection-history"
import { NetworkMap } from "@/components/netmap/network-map"
import { PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { Button } from "@/components/ui/button"
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { MapResponse } from "@/lib/p16-types"

export function MapView() {
  const { t } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<MapResponse>("/api/map", fetcher, { refreshInterval: 15_000 })
  const devices = data?.nodes.filter((n) => n.kind === "device").length ?? 0

  return (
    <>
      <PageHeader
        section={{ label: t("Ağ Haritası"), icon: Network }}
        title={t("Ağ haritası")}
        description={t("Cihazlar, koordinatör ve imzalı kurallardan gelen bağlantılar.")}
      />
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {data ? (
          devices === 0 ? (
            <Empty className="border">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <Rocket />
                </EmptyMedia>
                <EmptyTitle>{t("Haritada henüz cihaz yok")}</EmptyTitle>
                <EmptyDescription>{t("Kurulum sihirbazı koordinatörü ve ilk iki cihazını adım adım ekletir.")}</EmptyDescription>
              </EmptyHeader>
              <EmptyContent>
                <Button nativeButton={false} render={<Link href="/setup" />}>
                  {t("Kurulum sihirbazını aç")}
                </Button>
              </EmptyContent>
            </Empty>
          ) : (
            <NetworkMap data={data} />
          )
        ) : null}
      </QueryState>
      <ConnectionHistoryCard />
    </>
  )
}
