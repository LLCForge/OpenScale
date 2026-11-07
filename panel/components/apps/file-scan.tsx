"use client"

import useSWR from "swr"
import { toast } from "sonner"

import { EmptyNote, SettingBadge, SettingRow, SettingsSection } from "@/components/settings/settings-layout"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Switch } from "@/components/ui/switch"
import { ApiError, errorMessage, fetcher, post } from "@/lib/api"
import { tx, useI18n } from "@/lib/i18n/i18n"
import type { FileScanResult, FileScanStatus } from "@/lib/p07-types"

// Antivirus scan of received files (#458, ADR-0161): Microsoft Defender on
// Windows, ClamAV elsewhere. The scanner only reports; it never deletes.

const KEY = "/api/app/files/scan"

export function useFileScan() {
  const { data, error, mutate } = useSWR<FileScanStatus>(KEY, fetcher, {
    refreshInterval: 15_000,
    shouldRetryOnError: (err: unknown) => !(err instanceof ApiError && err.status === 404),
  })
  const missing = error instanceof ApiError && error.status === 404
  return { scan: missing ? null : data, mutate }
}

/** The last scan result of an inbox file. */
export function scanResult(scan: FileScanStatus | null | undefined, name: string): FileScanResult | undefined {
  return scan?.results?.find((r) => r.name === name)
}

export function ScanBadge({ result }: { result: FileScanResult | undefined }) {
  const { t } = useI18n()
  if (!result) return null
  switch (result.verdict) {
    case "clean":
      return <SettingBadge tone="success">{t("Temiz ({scanner})", { scanner: result.scanner })}</SettingBadge>
    case "infected":
      return <SettingBadge tone="danger">
          {result.detail ? t("Tehdit: {detail}", { detail: result.detail }) : t("Tehdit: bulundu")}
        </SettingBadge>
    case "error":
      return <SettingBadge>{t("Taranamadı")}</SettingBadge>
    default:
      return <SettingBadge>{t("Tarayıcı yok")}</SettingBadge>
  }
}

/** Starts a scan of one file; it may take minutes. */
export async function rescan(name: string, onDone: (s: FileScanStatus) => void) {
  const id = toast.loading(tx("{name} taranıyor…", { name }))
  try {
    const res = await post<FileScanStatus>(`${KEY}/run`, { name })
    onDone(res)
    const r = scanResult(res, name)
    toast.success(r?.verdict === "infected" ? tx("Tehdit bulundu: {detail}", { detail: r.detail ?? name }) : tx("Tarama bitti."), { id })
  } catch (err) {
    toast.error(errorMessage(err), { id })
  }
}

export function ScanSection({ scan, readOnly, onChange }: { scan: FileScanStatus; readOnly: boolean; onChange: (s: FileScanStatus) => void }) {
  const { t, ts } = useI18n()
  async function toggle(enabled: boolean) {
    try {
      onChange(await post<FileScanStatus>(KEY, { enabled }))
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }
  return (
    <SettingsSection
      id="antivirus"
      title={t("Antivirüs taraması")}
      description={t("Gelen dosyalar bu bilgisayardaki antivirüsle taranır. Tarayıcı dosyayı silmez, yalnızca bildirir; karar senin.")}
    >
      <SettingRow
        title={t("Gelen dosyaları yerel antivirüsle tara")}
        htmlFor="scan-enabled"
        badge={scan.enabled ? null : <SettingBadge>{t("Varsayılan kapalı")}</SettingBadge>}
        description={
          scan.available
            ? scan.scanner
              ? t("Tarayıcı: {scanner}.", { scanner: scan.scanner })
              : t("Tarayıcı: bilinmiyor.")
            : t("Bu cihazda Defender veya ClamAV bulunamadı.")
        }
        action={<Switch id="scan-enabled" checked={scan.enabled} disabled={readOnly || !scan.available} onCheckedChange={toggle} />}
      >
        {scan.cloud_note ? (
          <Alert>
            <AlertDescription className="text-pretty">{ts(scan.cloud_note)}</AlertDescription>
          </Alert>
        ) : null}
      </SettingRow>
      {scan.enabled && (scan.results ?? []).length === 0 ? <EmptyNote framed={false}>{t("Henüz taranan dosya yok.")}</EmptyNote> : null}
    </SettingsSection>
  )
}
