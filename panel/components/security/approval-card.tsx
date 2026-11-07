"use client"

import useSWR from "swr"

import { SettingBadge, SettingRow } from "@/components/settings/settings-layout"
import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { ApprovalResponse } from "@/lib/wave3-types"

/** k-of-n approval policy and TPM/PIV state as settings rows, read only (ADR-0121, 0123, 0124). */
export function ApprovalRows() {
  const { t, ts } = useI18n()
  const { data } = useSWR<ApprovalResponse>("/api/security/approval", fetcher, { refreshInterval: 60_000 })
  if (!data) return null
  return (
    <>
      <SettingRow
        title={t("Onay politikası")}
        badge={<SettingBadge>{t("Salt okunur")}</SettingBadge>}
        description={
          data.threshold > 0 ? (
            <>
              {t("Her yeni belge kök imzasına ek olarak {approvers} onaylayıcıdan {threshold} imza ister.", {
                approvers: data.approvers.length,
                threshold: data.threshold,
              })}
            </>
          ) : (
            <>
              {t("Politika yok; belgeyi yalnızca kök anahtar imzalar. Değiştirmek için")}{" "}
              <code className="font-mono text-[0.8125rem]">openscale network approval set</code>
            </>
          )
        }
      >
        {data.threshold > 0 ? (
          <ul className="flex flex-col divide-y rounded-lg border text-sm">
            {data.approvers.map((a) => (
              <li key={a.fingerprint} className="flex flex-col gap-0.5 px-4 py-2.5 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
                <span className="font-medium">{a.name}</span>
                <span className="font-mono text-[0.8125rem] break-all text-muted-foreground">{a.fingerprint}</span>
              </li>
            ))}
          </ul>
        ) : null}
      </SettingRow>
      {data.hardware ? (
        <SettingRow
          title={t("Donanım anahtarları")}
          badge={<SettingBadge>{t("Bu bilgisayar")}</SettingBadge>}
          description={t("TPM: {tpm}. Akıllı kart okuyucuları: {readers}.", {
            tpm: ts(data.hardware.tpm),
            readers: data.hardware.piv.length > 0 ? data.hardware.piv.join(", ") : t("yok"),
          })}
        >
          {data.hardware.tpmNote || data.hardware.pivNote ? (
            <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
              {[data.hardware.tpmNote, data.hardware.pivNote]
                .filter(Boolean)
                .map((note) => ts(note))
                .join(" ")}
            </p>
          ) : null}
        </SettingRow>
      ) : null}
    </>
  )
}
