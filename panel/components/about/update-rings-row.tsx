"use client"

import { TriangleAlert } from "lucide-react"

import { SettingBadge, SettingRow } from "@/components/settings/settings-layout"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { dateFormat } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"

/** One ring's numbers as the coordinator reports them (ADR-0235). */
export interface UpdateRingCount {
  ring: string
  members: number
  updated: number
  healthy: number
  rolledBack: number
}

/** Ring progress of the announced release; soak times in seconds. */
export interface UpdateRollout {
  announced: boolean
  open?: string
  halted?: boolean
  haltRing?: string
  canarySoak: number
  earlySoak: number
  since?: string
  earlyAt?: string
  mainAt?: string
  firstSeen?: string
  notBefore?: string
  rings?: UpdateRingCount[]
}

const ringLabels: Record<string, string> = {
  canary: msg("canary"),
  early: msg("early"),
  main: msg("main"),
}

function when(iso?: string): string | null {
  if (!iso) return null
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return null
  return dateFormat("short-datetime", { dateStyle: "short", timeStyle: "short" }).format(d)
}

function hours(seconds: number): number {
  return Math.round((seconds / 3600) * 10) / 10
}

interface UpdateRingsRowProps {
  ring?: string
  rollout?: UpdateRollout
}

/**
 * Update rings (#827): this device's ring comes from its signed tags; the
 * coordinator only announces which ring is open, and the device keeps its
 * own minimum wait. A rollback halts the release everywhere.
 */
export function UpdateRingsRow({ ring, rollout }: UpdateRingsRowProps) {
  const { t } = useI18n()
  if (!ring) return null
  const label = (r?: string) => (r && ringLabels[r] ? t(ringLabels[r]) : (r ?? "-"))
  const notBefore = when(rollout?.notBefore)

  return (
    <SettingRow
      title={t("Güncelleme halkası")}
      badge={
        rollout?.halted ? (
          <SettingBadge tone="danger">{t("Sürüm durduruldu")}</SettingBadge>
        ) : (
          <SettingBadge>{label(ring)}</SettingBadge>
        )
      }
      description={
        <>
          <span className="block">
            {t("Bu cihaz {ring} halkasında. Halka cihazın imzalı etiketinden gelir: ring-canary önce, ring-early sonra kurar; etiketsiz cihazlar main halkasındadır.", { ring: label(ring) })}
          </span>
          {rollout ? (
            <>
              {rollout.announced ? (
                <span className="block">{t("Koordinatöre göre açık halka: {ring}", { ring: label(rollout.open) })}</span>
              ) : (
                <span className="block">
                  {t("Koordinatör halka ilerlemesi göndermiyor (eski sürüm); bu cihaz yalnızca kendi bekleme süresini uygular.")}
                </span>
              )}
              <span className="block">
                {t("Bekleme süreleri: canary → early {canary} sa, early → main {early} sa", {
                  canary: hours(rollout.canarySoak),
                  early: hours(rollout.earlySoak),
                })}
              </span>
              {notBefore ? <span className="block">{t("Bu cihazın kendi bekleme sınırı: {when}", { when: notBefore })}</span> : null}
              {rollout.rings?.map((c) => (
                <span key={c.ring} className="block font-mono text-xs tabular-nums">
                  {t("{ring}: üye {members} · yeni sürümde {updated} · sağlıklı {healthy} · geri dönen {rolledBack}", {
                    ring: label(c.ring),
                    members: c.members,
                    updated: c.updated,
                    healthy: c.healthy,
                    rolledBack: c.rolledBack,
                  })}
                </span>
              ))}
            </>
          ) : null}
        </>
      }
    >
      {rollout?.halted ? (
        <Alert variant="destructive">
          <TriangleAlert aria-hidden="true" />
          <AlertTitle>{t("Sürüm otomatik olarak durduruldu")}</AlertTitle>
          <AlertDescription>
            {t("{ring} halkasındaki bir cihaz yeni sürümde sağlıklı başlamadı ve önceki sürüme döndü. Henüz kurmamış cihazlar beklemede. Sahip sorunu inceleyip koordinatör sunucusunda openscale update rings resume ile sürdürebilir ya da düzeltilmiş bir sürüm yayımlayabilir.", { ring: label(rollout.haltRing) })}
          </AlertDescription>
        </Alert>
      ) : null}
    </SettingRow>
  )
}
