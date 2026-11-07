"use client"

import { useState } from "react"
import useSWR from "swr"
import { toast } from "sonner"

import { CodeLine } from "@/components/copy-field"
import { NetPlacesRow } from "@/components/settings/net-places-row"
import { SettingBadge, SettingRow, SettingsSection } from "@/components/settings/settings-layout"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { errorMessage, fetcher, post } from "@/lib/api"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { AutostartInfo, DiscreetInfo } from "@/lib/pa-types"

const nameRule = msg("Ad 1-40 karakter olmalı; OpenScale, VPN, WireGuard, tünel ve mesh sözcüklerini içeremez.")
const forbidden = /openscale|vpn|wireguard|t[üu]nel|mesh/i
const allowed = /^[\p{L}\p{N} .-]{1,40}$/u

/**
 * Ayarlar > Bu bilgisayar: start at sign-in (ADR-0194) and the discreet
 * name mode (ADR-0196). Both are local, unsigned settings.
 */
export function DesktopSection() {
  const { t } = useI18n()
  return (
    <SettingsSection
      id="masaustu"
      title={t("Başlangıç ve görünüm")}
      description={t("Masaüstü uygulamasının bu bilgisayardaki davranışı; imza gerekmez.")}
    >
      <AutostartRow />
      <DiscreetRow />
      <NetPlacesRow />
    </SettingsSection>
  )
}

function AutostartRow() {
  const { t } = useI18n()
  const { data } = useSWR<AutostartInfo>("/api/desktop/autostart", fetcher, { shouldRetryOnError: false })
  const all = data?.entries.find((e) => e.scope === "all")
  return (
    <SettingRow
      title={t("Oturum açılınca başlat")}
      badge={all?.installed ? <SettingBadge tone="success">{t("Bütün kullanıcılar")}</SettingBadge> : null}
      description={
        <span className="flex flex-col gap-1">
          <span>{t("Bu bilgisayarda oturum açtığınızda OpenScale simgesi bildirim alanında başlar. Arka plan servisi her zaman açılışta çalışır.")}</span>
          {all?.installed ? <span>{t("Bütün kullanıcılar için kayıt var; bu kullanıcı kapatırsa simge yine başlamaz.")}</span> : null}
        </span>
      }
    >
      <CodeLine value="openscale autostart off" className="max-w-md" />
    </SettingRow>
  )
}

function DiscreetRow() {
  const { t } = useI18n()
  const { data, mutate } = useSWR<DiscreetInfo>("/api/desktop/discreet", fetcher, { shouldRetryOnError: false })
  const [name, setName] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [nameError, setNameError] = useState<string | null>(null)
  if (!data?.supported) return null
  const current = name ?? data.name

  async function save(enabled: boolean, value: string) {
    const trimmed = value.trim()
    if (!allowed.test(trimmed) || forbidden.test(trimmed)) {
      setNameError(nameRule)
      return
    }
    setNameError(null)
    setBusy(true)
    try {
      const res = await post<DiscreetInfo>("/api/desktop/discreet", { enabled, name: trimmed })
      await mutate(res, { revalidate: false })
      setName(null)
      toast.success(enabled ? t("Göze çarpmayan ad kipi açıldı.") : t("Göze çarpmayan ad kipi kapatıldı."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <SettingRow
      title={t("Göze çarpmayan ad kipi")}
      htmlFor="discreet-switch"
      description={t("Bildirim alanı simgesi, pencere başlığı ve servis görünen adı nötr bir adla görünür. Korumalar ve servis adı değişmez.")}
      action={<Switch id="discreet-switch" checked={data.enabled} disabled={busy} onCheckedChange={(on) => void save(on, current)} />}
    >
      <div className="flex flex-col gap-1.5">
        <label htmlFor="discreet-name" className="text-sm font-medium">
          {t("Görünen ad")}
        </label>
        <div className="flex max-w-md gap-2">
          <Input
            id="discreet-name"
            value={current}
            placeholder={t("Ağ Yardımcısı")}
            maxLength={40}
            aria-invalid={nameError ? true : undefined}
            aria-describedby={nameError ? "discreet-name-error" : undefined}
            onChange={(e) => {
              setName(e.target.value)
              setNameError(null)
            }}
          />
          <Button variant="outline" disabled={busy || name === null} onClick={() => void save(data.enabled, current)}>
            {busy ? <Spinner data-icon="inline-start" /> : null}
            {t("Kaydet")}
          </Button>
        </div>
        {nameError ? (
          <p id="discreet-name-error" role="alert" className="text-sm text-destructive">
            {t(nameError)}
          </p>
        ) : null}
      </div>
    </SettingRow>
  )
}
