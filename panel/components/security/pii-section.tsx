"use client"

import useSWR from "swr"

import { QueryState } from "@/components/query-state"
import { EmptyNote, SettingBadge, SettingRow, SettingsSection } from "@/components/settings/settings-layout"
import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { PIIWarning } from "@/lib/pa-types"

/**
 * Ağ ayarları > Gizlilik (#688, ADR-0177): names in the signed document
 * that look like personal data. The values are already in the document;
 * the list only points at them.
 */
export function PersonalDataSection() {
  const { t, ts } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<{ warnings: PIIWarning[] }>("/api/g1/pii", fetcher)
  const warnings = data?.warnings ?? []
  return (
    <SettingsSection
      id="gizlilik"
      title={t("Adlarda kişisel veri")}
      description={t("Bu adlar her cihaza ve koordinatöre gider; nötr adlar (ör. laptop-1) önerilir.")}
    >
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {data ? (
          warnings.length === 0 ? (
            <EmptyNote framed={false}>{t("Ağ adlarında kişisel veri kalıbı bulunmadı.")}</EmptyNote>
          ) : (
            warnings.map((w) => (
              <SettingRow
                key={`${w.field}-${w.value}-${w.kind}`}
                title={<span className="font-mono">{w.value}</span>}
                badge={<SettingBadge tone="warning">{ts(w.kind)}</SettingBadge>}
                description={ts(w.field)}
              />
            ))
          )
        ) : null}
      </QueryState>
    </SettingsSection>
  )
}
