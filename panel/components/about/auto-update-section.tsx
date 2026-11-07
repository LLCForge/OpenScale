"use client"

import { useState } from "react"
import useSWR from "swr"
import { toast } from "sonner"

import { useReadOnly } from "@/components/app/read-only"
import { UpdateRingsRow, type UpdateRollout } from "@/components/about/update-rings-row"
import { SettingBadge, SettingRow, SettingsSection } from "@/components/settings/settings-layout"
import { Switch } from "@/components/ui/switch"
import { errorMessage, fetcher, post } from "@/lib/api"
import { dateFormat } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"

/** Last installation reported by the installer (ADR-0225). */
interface AutoUpdateAttempt {
  version: string
  at: string
  ok: boolean
  rolledBack?: boolean
  message?: string
}

/** Reply of /api/app/auto-update (ADR-0225). */
interface AutoUpdateStatus {
  supported: boolean
  enabled: boolean
  state: string
  message: string
  action?: string
  channel: string
  current: string
  latest?: string
  latestVerified: boolean
  lastCheck?: string
  nextCheck?: string
  scheduledAt?: string
  source?: string
  sourceChecked?: string
  lastAttempt?: AutoUpdateAttempt
  ring?: string
  rollout?: UpdateRollout
}

type Tone = "muted" | "warning" | "danger" | "success"

const stateLabels: Record<string, { label: string; tone: Tone }> = {
  off: { label: msg("Kapalı"), tone: "muted" },
  unsupported: { label: msg("Desteklenmiyor"), tone: "muted" },
  "waiting-key": { label: msg("İmza anahtarı bekleniyor"), tone: "warning" },
  "no-release": { label: msg("Yayımlanmış sürüm yok"), tone: "muted" },
  unreachable: { label: msg("Koordinatöre ulaşılamadı"), tone: "warning" },
  "up-to-date": { label: msg("Güncel"), tone: "success" },
  rejected: { label: msg("Sürüm reddedildi"), tone: "danger" },
  scheduled: { label: msg("Planlandı"), tone: "warning" },
  downloading: { label: msg("İndiriliyor"), tone: "warning" },
  installing: { label: msg("Kuruluyor"), tone: "warning" },
  failed: { label: msg("Başarısız"), tone: "danger" },
  pending: { label: msg("Bekliyor"), tone: "muted" },
  "ring-wait": { label: msg("Halka sırası bekleniyor"), tone: "warning" },
  halted: { label: msg("Sürüm durduruldu"), tone: "danger" },
}

function when(iso?: string): string | null {
  if (!iso) return null
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return null
  return dateFormat("short-datetime", { dateStyle: "short", timeStyle: "short" }).format(d)
}

/**
 * Automatic update card: the per-device switch and what the device last
 * learnt from the coordinator's release mirror. The coordinator only
 * announces; the device installs nothing whose signature it cannot verify.
 */
export function AutoUpdateSection() {
  const { t, ts } = useI18n()
  const { data, error, mutate } = useSWR<AutoUpdateStatus>("/api/app/auto-update", fetcher, {
    refreshInterval: 15000,
    shouldRetryOnError: false,
  })
  const readOnly = useReadOnly()
  const [busy, setBusy] = useState(false)
  // An older service without the endpoint, or a panel outside the service.
  if (error || !data) return null

  async function toggle(on: boolean) {
    setBusy(true)
    try {
      await mutate(await post<AutoUpdateStatus>("/api/app/auto-update", { on }), { revalidate: true })
      toast.success(on ? t("Otomatik güncelleme açıldı.") : t("Otomatik güncelleme kapatıldı."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const known = stateLabels[data.state]
  const state = known ? { label: t(known.label), tone: known.tone } : { label: data.state, tone: "muted" as Tone }
  const lastCheck = when(data.lastCheck)
  const scheduled = when(data.scheduledAt)
  const sourceChecked = when(data.sourceChecked)
  const attempt = data.lastAttempt

  return (
    <SettingsSection
      id="otomatik-guncelleme"
      title={t("Otomatik güncelleme")}
      description={t(
        "Koordinatör yalnızca dağıtır; bu cihaz imzalı sürümü kendisi doğrular, cihazlar aynı anda yeniden başlamasın diye rastgele bir gecikmeyle kurar.",
      )}
    >
      <SettingRow
        title={t("Bu cihazı otomatik güncelle")}
        htmlFor="g-auto-update"
        badge={<SettingBadge tone={state.tone}>{state.label}</SettingBadge>}
        description={
          <>
            <span className="block">{ts(data.message)}</span>
            {data.action ? (
              <code className="mt-1 block font-mono text-xs break-all text-foreground">{data.action}</code>
            ) : null}
          </>
        }
        action={
          <Switch
            id="g-auto-update"
            checked={data.enabled}
            disabled={readOnly || busy || !data.supported}
            onCheckedChange={(c) => void toggle(c)}
          />
        }
      />
      <SettingRow
        title={t("Sürümler")}
        description={
          <>
            <span className="block">
              {t("Kurulu:")} <span className="font-mono tabular-nums">{data.current}</span> ·{" "}
              {data.channel === "beta" ? t("kanal beta") : t("kanal kararlı")}
            </span>
            {data.latest ? (
              <span className="block">
                {t("Koordinatördeki en yeni:")} <span className="font-mono tabular-nums">{data.latest}</span>{" "}
                {data.latestVerified ? t("(imzası doğrulandı)") : t("(henüz doğrulanmadı)")}
              </span>
            ) : null}
            {scheduled ? <span className="block">{t("Planlanan kurulum: {when}", { when: scheduled })}</span> : null}
          </>
        }
        action={
          lastCheck ? (
            <SettingBadge>{t("Son denetim: {when}", { when: lastCheck })}</SettingBadge>
          ) : (
            <SettingBadge>{t("Henüz denetlenmedi")}</SettingBadge>
          )
        }
      />
      <UpdateRingsRow ring={data.ring} rollout={data.rollout} />
      <SettingRow
        title={t("Koordinatörün kaynağı")}
        description={
          data.source ? (
            <>
              <span className="block font-mono text-xs break-all">{data.source}</span>
              <span className="block">
                {sourceChecked
                  ? t("Koordinatörün son denetimi: {when}", { when: sourceChecked })
                  : t("Koordinatör henüz denetlemedi.")}{" "}
                {t("Bu cihaz kaynağa hiç bağlanmaz; sürümü yalnızca koordinatörden tünel içinden alır.")}
              </span>
            </>
          ) : (
            t("Sürümler koordinatöre elle yayımlanıyor (openscale update publish).")
          )
        }
      />
      {attempt ? (
        <SettingRow
          title={t("Son kurulum")}
          badge={
            <SettingBadge tone={attempt.ok ? "success" : "danger"}>
              {attempt.ok ? t("Başarılı") : attempt.rolledBack ? t("Geri dönüldü") : t("Başarısız")}
            </SettingBadge>
          }
          description={`${attempt.version} · ${when(attempt.at) ?? ""}${attempt.message ? ` · ${ts(attempt.message)}` : ""}`}
        />
      ) : null}
    </SettingsSection>
  )
}
