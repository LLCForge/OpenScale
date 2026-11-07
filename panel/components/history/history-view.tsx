"use client"

import useSWR from "swr"
import { CircleCheck, ShieldAlert } from "lucide-react"

import { DetailSection } from "@/components/devices/detail-card"
import { DiffList } from "@/components/diff-list"
import { diffLines } from "@/components/history/diff-lines"
import { PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { RowList } from "@/components/settings/list-table"
import { EmptyNote, SettingBadge, SettingsColumn } from "@/components/settings/settings-layout"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { fetcher } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { useI18n } from "@/lib/i18n/i18n"
import type { HistoryReport } from "@/lib/types"

/** Günlükler > Etkinlik: every signed document version, checked again on load. */
export function HistoryView() {
  const { data, error, isLoading, mutate } = useSWR<HistoryReport>("/api/history", fetcher)
  const { t, ts } = useI18n()

  return (
    <SettingsColumn className="max-w-5xl">
      <PageHeader title={t("Etkinlik")} description={t("İmzalı her belge sürümü; sayfa açılınca imzalar ve sıra yeniden doğrulanır.")} />
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {data ? (
          <DetailSection
            // i18n-ignore: bağlantı kimliği, görünmez
            id="belge-gecmisi"
            title={t("Belge geçmişi")}
            description={t("En yeni sürüm en üstte. Yeşil satırlar eklenen, kırmızılar kaldırılan, sarılar değişen öğelerdir.")}
            framed={false}
            action={
              data.problems.length === 0 ? (
                <span className="flex items-center gap-1.5 text-sm text-muted-foreground">
                  <CircleCheck className="size-4 text-success" aria-hidden="true" />
                  {t("{count} sürüm doğrulandı", { count: data.entries.length })}
                </span>
              ) : null
            }
          >
            {data.problems.length > 0 ? (
              <Alert variant="destructive">
                <ShieldAlert />
                <AlertTitle>{t("Geçmişte sorun bulundu")}</AlertTitle>
                <AlertDescription>
                  <ul className="list-disc pl-4">
                    {data.problems.map((p) => (
                      <li key={p}>{ts(p)}</li>
                    ))}
                  </ul>
                </AlertDescription>
              </Alert>
            ) : null}
            {data.entries.length === 0 ? (
              <EmptyNote>{t("Henüz imzalı belge sürümü yok.")}</EmptyNote>
            ) : (
              <RowList label={t("Belge sürümleri")}>
                {data.entries.map((e, i) => (
                  <li key={e.version} className="flex flex-col gap-3 py-4 md:flex-row md:gap-8">
                    <div className="flex shrink-0 flex-col gap-1 md:w-56">
                      <span className="flex items-center gap-2">
                        <span className="text-sm font-medium">{t("Sürüm {version}", { version: e.version })}</span>
                        {i === 0 ? <SettingBadge tone="success">{t("Güncel")}</SettingBadge> : null}
                      </span>
                      <time dateTime={e.issued_at} className="text-sm text-muted-foreground">
                        {formatDateTime(e.issued_at)}
                      </time>
                      <span className="text-xs text-muted-foreground">
                        {t("{count} cihaz", { count: e.devices })} · {t("{count} kural", { count: e.rules })}
                      </span>
                    </div>
                    <div className="min-w-0 flex-1">
                      {e.diff ? <DiffList lines={diffLines(e.diff)} bare /> : <p className="text-sm text-muted-foreground">{t("Ağ oluşturuldu.")}</p>}
                    </div>
                  </li>
                ))}
              </RowList>
            )}
          </DetailSection>
        ) : null}
      </QueryState>
    </SettingsColumn>
  )
}
