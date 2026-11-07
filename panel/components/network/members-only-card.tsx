"use client"

import { useState } from "react"
import useSWR from "swr"
import { TriangleAlert } from "lucide-react"

import { Writable } from "@/components/app/read-only"
import { QueryState } from "@/components/query-state"
import { SettingRow, SettingsSection } from "@/components/settings/settings-layout"
import { SignChangeDialog } from "@/components/sign-change"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Switch } from "@/components/ui/switch"
import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"

const statusKey = "/api/g1/members-only"

interface MembersOnlyStatus {
  enabled: boolean
  sealed: boolean
  minClientVersion: string
  requiredClientVersion: string
  raisesMinClient: boolean
  blockers: string[]
  warnings: string[]
}

/**
 * Ağ > Koordinatörler (#629, ADR-0178): the blind coordinator switch. The
 * version that follows the choice is signed in the usual dialog; turning it on
 * warns about the minimum client version first.
 */
export function MembersOnlyCard() {
  const { t, ts } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<MembersOnlyStatus>(statusKey, fetcher)
  const [target, setTarget] = useState<boolean | null>(null)
  const canEnable = data ? data.blockers.length === 0 : false

  return (
    <SettingsSection
      id="kor-koordinator"
      title={t("Kör koordinatör")}
      description={t("Cihaz adları, etiketler, kurallar ve DNS ayarları belgede yalnızca üyelerin açabileceği şekilde şifrelenir; koordinatör bunları göremez.")}
    >
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {data ? (
          <>
            <SettingRow
              title={t("Belgeyi üyelere mühürle")}
              description={
                data.minClientVersion
                  ? t("Asgari istemci sürümü şu an {version}.", { version: data.minClientVersion })
                  : t("Asgari istemci sürümü belirlenmemiş.")
              }
              action={
                <Writable>
                  <Switch
                    aria-label={t("Belgeyi üyelere mühürle")}
                    checked={data.enabled}
                    disabled={!data.enabled && !canEnable}
                    onCheckedChange={(next) => setTarget(next)}
                  />
                </Writable>
              }
            />
            {data.blockers.length > 0 && !data.enabled ? (
              <div data-slot="setting-row" className="flex flex-col gap-2 py-5">
                {data.blockers.map((b) => (
                  <p key={b} className="rounded-lg bg-secondary px-3 py-2 text-sm text-pretty text-muted-foreground">
                    {ts(b)}
                  </p>
                ))}
              </div>
            ) : null}
            <SignChangeDialog
              open={target !== null}
              onOpenChange={(open) => {
                if (!open) {
                  setTarget(null)
                  void mutate()
                }
              }}
              title={target ? t("Kör koordinatör kipini aç") : t("Kör koordinatör kipini kapat")}
              description={
                target
                  ? t("Yeni sürüm üyelere mühürlenmiş olarak imzalanır. Koordinatörün de kör çalışması için sunucuda 'openscale coordinator harden --blind on' çalıştırın.")
                  : t("Yeni sürüm mühürsüz imzalanır; cihaz adları, etiketler ve kurallar yeniden koordinatöre görünür.")
              }
              extra={
                target && data.warnings.length > 0 ? (
                  <Alert>
                    <TriangleAlert />
                    <AlertTitle>{t("İmzalamadan önce")}</AlertTitle>
                    <AlertDescription className="flex flex-col gap-1 text-pretty">
                      {data.warnings.map((w) => (
                        <span key={w}>{ts(w)}</span>
                      ))}
                    </AlertDescription>
                  </Alert>
                ) : null
              }
              endpoint={statusKey}
              payload={{ enabled: target === true }}
              confirmLabel={target ? t("İmzala ve aç") : t("İmzala ve kapat")}
            />
          </>
        ) : null}
      </QueryState>
    </SettingsSection>
  )
}
