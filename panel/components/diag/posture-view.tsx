"use client"

import useSWR from "swr"

import { optionalGet } from "@/components/auth/strict-api"
import { PageHeader } from "@/components/page-header"
import { EmptyNote, SettingBadge, SettingsSection } from "@/components/settings/settings-layout"
import { Skeleton } from "@/components/ui/skeleton"
import { formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"

// This computer's posture (ADR-0207, ADR-0208): boot and lock state, TPM
// sealing of the device key and the signed tamper log. Every value is the
// device's own statement; the disclaimer says so under each card.

interface Posture {
  disk_encryption: string
  firewall: string
  secure_boot: string
  tpm: string
  screen_lock: string
  lock_minutes: number
  max_lock_minutes: number
  grade: "strong" | "weak" | "unknown"
  reasons: string[] | null
  disclaimer: string
}

interface TPMState {
  present: boolean
  version: string
  sealed: boolean
  seal_kind?: string
  supported: boolean
  note: string
}

interface TamperEvent {
  device: string
  seq: number
  at: string
  path: string
  kind: "changed" | "removed" | "added" | string
  old?: string
  new?: string
}

const gradeBadge = {
  strong: { text: msg("Güçlü"), tone: "success" },
  weak: { text: msg("Zayıf"), tone: "danger" },
  unknown: { text: msg("Bilinmiyor"), tone: "muted" },
} as const

const kindText: Record<string, string> = { changed: msg("değişti"), removed: msg("silindi"), added: msg("eklendi") }

function Line({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 py-2.5 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-right">{value}</span>
    </div>
  )
}

function Frame({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-col divide-y rounded-lg border px-4" data-slot="card">
      {children}
    </div>
  )
}

export function PostureView() {
  const { t, ts } = useI18n()
  const posture = useSWR<Posture | null>("/api/app/posture/extended", optionalGet, { refreshInterval: 60_000 })
  const tpm = useSWR<TPMState | null>("/api/app/tpm", optionalGet, { refreshInterval: 60_000 })
  const tamper = useSWR<{ events: TamperEvent[] | null } | null>("/api/app/tamper", optionalGet, { refreshInterval: 30_000 })

  const p = posture.data
  const grade = p ? gradeBadge[p.grade] ?? gradeBadge.unknown : null

  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        title={t("Cihaz duruşu")}
        description={t("Önyükleme, disk şifreleme, ekran kilidi ve TPM durumu. Kurallar bu bilgilere göre bir cihaza daha az erişim verebilir.")}
      />

      {posture.isLoading ? (
        <Skeleton className="h-48 w-full" />
      ) : p ? (
        <SettingsSection id="onyukleme" title={t("Önyükleme ve kilit")} action={grade ? <SettingBadge tone={grade.tone}>{t(grade.text)}</SettingBadge> : null}>
          <Frame>
            <Line label="Secure Boot" value={ts(p.secure_boot)} />
            <Line label={t("Disk şifreleme")} value={ts(p.disk_encryption)} />
            <Line label={t("Güvenlik duvarı")} value={ts(p.firewall)} />
            <Line label="TPM" value={ts(p.tpm)} />
            <Line
              label={t("Ekran kilidi")}
              value={
                p.lock_minutes > 0
                  ? t("{lock} ({minutes} dk, en çok {max} dk önerilir)", { lock: ts(p.screen_lock), minutes: p.lock_minutes, max: p.max_lock_minutes })
                  : ts(p.screen_lock)
              }
            />
          </Frame>
          {p.grade === "weak" && (p.reasons ?? []).length > 0 ? (
            <ul className="flex list-disc flex-col gap-1 pl-5 text-sm text-pretty">
              {(p.reasons ?? []).map((r) => (
                <li key={r}>{ts(r)}</li>
              ))}
            </ul>
          ) : null}
          <p className="text-xs text-muted-foreground text-pretty">{ts(p.disclaimer)}</p>
        </SettingsSection>
      ) : (
        <EmptyNote>{t("Bu sürümde genişletilmiş duruş bilgisi yok.")}</EmptyNote>
      )}

      {tpm.data ? (
        <SettingsSection id="tpm" title="TPM">
          <Frame>
            <Line
              label="TPM"
              value={tpm.data.present ? (tpm.data.version ? t("Var ({version})", { version: tpm.data.version }) : t("Var")) : t("Yok")}
            />
            <Line
              label={t("Cihaz anahtarı")}
              value={tpm.data.sealed ? (tpm.data.seal_kind ? t("TPM'e bağlı ({kind})", { kind: tpm.data.seal_kind }) : t("TPM'e bağlı")) : t("Bağlı değil")}
            />
          </Frame>
          {tpm.data.sealed ? null : <p className="text-sm text-pretty">{t("Cihaz anahtarı bu bilgisayarın TPM'ine bağlı değil.")}</p>}
          <p className="text-xs text-muted-foreground text-pretty">{ts(tpm.data.note)}</p>
        </SettingsSection>
      ) : null}

      {tamper.data ? (
        <SettingsSection
          id="kurcalama"
          title={t("Kurcalama günlüğü")}
          description={t("OpenScale dosyalarında dışarıdan yapılan değişiklikler imzalı ve zincirli olarak kaydedilir.")}
        >
          {(tamper.data.events ?? []).length === 0 ? (
            <EmptyNote>{t("Dışarıdan değişiklik görülmedi.")}</EmptyNote>
          ) : (
            <ul className="flex flex-col divide-y rounded-lg border" data-slot="card">
              {(tamper.data.events ?? []).map((e) => (
                <li key={`${e.device}-${e.seq}`} className="flex flex-col gap-1 px-4 py-3 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <SettingBadge tone={e.kind === "removed" ? "danger" : "warning"}>{kindText[e.kind] ? t(kindText[e.kind]) : e.kind}</SettingBadge>
                    <span className="min-w-0 flex-1 font-mono text-xs break-all">{e.path}</span>
                    <time dateTime={e.at} className="text-xs text-muted-foreground tabular-nums">
                      {formatDateTime(e.at)}
                    </time>
                  </div>
                  {e.device ? <span className="text-xs text-muted-foreground">{e.device}</span> : null}
                </li>
              ))}
            </ul>
          )}
        </SettingsSection>
      ) : null}
    </div>
  )
}
