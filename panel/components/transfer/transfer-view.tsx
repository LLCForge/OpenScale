"use client"

import { useId, useRef, useState } from "react"
import { BadgeCheck, Download, FileUp, TriangleAlert } from "lucide-react"
import { toast } from "sonner"

import { DetailGroup, DetailItem, DetailSection } from "@/components/devices/detail-card"
import { DiffList } from "@/components/diff-list"
import { PageHeader } from "@/components/page-header"
import { SettingBadge, SettingRow, SettingsColumn, SettingsSection } from "@/components/settings/settings-layout"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { ApiError, errorMessage, post } from "@/lib/api"
import { errorAction } from "@/lib/error-help"
import { formatDateTime } from "@/lib/format"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import type { ImportResult } from "@/lib/p16-types"

// Document export and import (#234). Export hands out the signed network
// document every device already holds. Import only verifies a file against
// this network's root key and shows how it differs; nothing is signed or
// written, so an old file can never roll the network back.

/** Same limit as trust.MaxEnvelopeSize. */
const MAX_FILE = 2 * 1024 * 1024

async function downloadDocument(): Promise<void> {
  const res = await fetch("/api/network/export", { credentials: "same-origin", cache: "no-store" })
  if (!res.ok) {
    let message: string = msg("Beklenmeyen bir hata oluştu.")
    try {
      const data: unknown = await res.json()
      if (data && typeof data === "object" && "error" in data && typeof data.error === "string") message = data.error
    } catch {
      // Not JSON; keep the generic message.
    }
    throw new ApiError(message, res.status)
  }
  const disposition = res.headers.get("Content-Disposition") ?? ""
  const name = /filename="([^"]+)"/.exec(disposition)?.[1] ?? tx("openscale-belge.json")
  const url = URL.createObjectURL(await res.blob())
  const a = document.createElement("a")
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}

export function TransferView() {
  const { t } = useI18n()
  const inputId = useId()
  const inputRef = useRef<HTMLInputElement>(null)
  const [exporting, setExporting] = useState(false)
  const [checking, setChecking] = useState(false)
  const [result, setResult] = useState<ImportResult | null>(null)
  const [failure, setFailure] = useState<unknown>(null)

  async function onExport() {
    setExporting(true)
    try {
      await downloadDocument()
      toast.success(t("İmzalı ağ belgesi indirildi."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setExporting(false)
    }
  }

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ""
    setResult(null)
    setFailure(null)
    if (!file) return
    if (file.size > MAX_FILE) {
      setFailure(new ApiError(t("Dosya bir ağ belgesi için çok büyük."), 413))
      return
    }
    setChecking(true)
    try {
      const text = await file.text()
      setResult(await post<ImportResult>("/api/network/import/inspect", { document: text }))
    } catch (err) {
      setFailure(err)
    } finally {
      setChecking(false)
    }
  }

  return (
    <SettingsColumn>
      <PageHeader title={t("Belge aktarımı")} description={t("İmzalı ağ belgesini dosya olarak al veya bir belge dosyasının imzasını doğrula.")} />
      <SettingsSection id="disa-aktar" title={t("Dışa aktar")} description={t("Her cihazın zaten tuttuğu imzalı belgeyi indirir: cihaz listesi, kurallar ve ayarlar. Gizli anahtar içermez.")}>
        <SettingRow
          title={t("İmzalı ağ belgesi")}
          badge={<SettingBadge tone="warning">{t("Bu bir yedek değil")}</SettingBadge>}
          description={t("Belge, kök anahtar olmadan ağı geri getiremez. Kök anahtarın yedeğini Güvenlik ve Ayarlar sayfasından ayrı parolayla al.")}
          action={
            <Button variant="outline" onClick={onExport} disabled={exporting}>
              {exporting ? <Spinner data-icon="inline-start" /> : <Download data-icon="inline-start" />}
              {t("İmzalı belgeyi indir")}
            </Button>
          }
        />
      </SettingsSection>

      <SettingsSection
        id="ice-aktar"
        title={t("İçe aktar ve doğrula")}
        description={t("Daha önce dışa aktarılmış bir belgeyi seç: imzası bu ağın kök anahtarıyla denetlenir ve şu anki sürümle farkı gösterilir.")}
      >
        <SettingRow
          title={t("Belge dosyası")}
          description={t("Eski bir sürüm geri yüklenmez: iptal edilmiş cihazları geri getirebilirdi. Kök anahtarın kendisini geri yüklemek için 'openscale network restore' kullanılır.")}
          action={
            <>
              <label htmlFor={inputId} className="sr-only">
                {t("Belge dosyası")}
              </label>
              <input
                ref={inputRef}
                id={inputId}
                type="file"
                accept="application/json,.json"
                className="sr-only"
                tabIndex={-1}
                onChange={onFile}
                disabled={checking}
              />
              <Button variant="outline" disabled={checking} onClick={() => inputRef.current?.click()}>
                {checking ? <Spinner data-icon="inline-start" /> : <FileUp data-icon="inline-start" />}
                {t("Belge dosyası seç")}
              </Button>
            </>
          }
        />
      </SettingsSection>

      <div aria-live="polite" className="flex flex-col gap-4 empty:hidden">
        {failure ? (
          <Alert variant="destructive">
            <TriangleAlert />
            <AlertTitle>{t("Belge doğrulanamadı")}</AlertTitle>
            <AlertDescription className="flex flex-col gap-1">
              <span>{errorMessage(failure)}</span>
              {errorAction(failure) ? <span>{t(errorAction(failure))}</span> : null}
            </AlertDescription>
          </Alert>
        ) : null}
        {result ? <ImportReport result={result} /> : null}
      </div>
    </SettingsColumn>
  )
}

const relationText: Record<ImportResult["relation"], string> = {
  same: msg("Belge şu anki sürümün aynısı."),
  older: msg("Bu eski bir sürüm. O sürümden bu yana değişenler aşağıda."),
  newer: msg("Belge bu bilgisayardakinden yeni. Ağ başka bir kopyadan yönetilmiş olabilir; 'openscale network verify' çalıştır."),
  different: msg("Sürüm numarası aynı ama içerik farklı. Bu beklenmez; belge geçmişini doğrula."),
}

function ImportReport({ result }: { result: ImportResult }) {
  const { t } = useI18n()
  const suspicious = result.relation === "newer" || result.relation === "different"
  return (
    <DetailSection
      id="dogrulama-sonucu"
      title={t("İmza geçerli: belge bu ağın kök anahtarıyla imzalanmış")}
      description={t(relationText[result.relation])}
      framed={false}
    >
      {suspicious ? (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertTitle>{t("Dikkat")}</AlertTitle>
          <AlertDescription>{t(relationText[result.relation])}</AlertDescription>
        </Alert>
      ) : null}
      <div className="flex flex-col gap-5 border-y py-5">
        <DetailGroup>
          <DetailItem label={t("Sürüm")}>{t("{v} (şu anki: {c})", { v: result.version, c: result.currentVersion })}</DetailItem>
          <DetailItem label={t("İmzalandı")}>{formatDateTime(result.issuedAt)}</DetailItem>
          <DetailItem label={t("Geçerlilik sonu")}>
            {formatDateTime(result.expiresAt)}
            {result.expired ? <SettingBadge tone="warning">{t("süresi dolmuş")}</SettingBadge> : null}
          </DetailItem>
          <DetailItem label={t("Cihaz / kural")}>{`${result.devices.length} / ${result.rules}`}</DetailItem>
          {result.displayName ? <DetailItem label={t("Ağ adı")}>{result.displayName}</DetailItem> : null}
          <DetailItem label="SHA-256">
            <span className="font-mono text-xs break-all">{result.sha256}</span>
          </DetailItem>
        </DetailGroup>
        {result.devices.length > 0 ? (
          <div className="flex flex-col gap-2">
            <h3 className="text-sm font-medium">{t("Belgedeki cihazlar")}</h3>
            <div className="flex flex-wrap gap-1.5">
              {result.devices.map((d) => (
                <SettingBadge key={d}>{d}</SettingBadge>
              ))}
            </div>
          </div>
        ) : null}
        {result.changes.length > 0 ? (
          <div className="flex flex-col gap-2">
            <h3 className="text-sm font-medium">{t("Farklar")}</h3>
            <DiffList lines={result.changes} />
          </div>
        ) : null}
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <BadgeCheck className="size-3.5 text-success" aria-hidden="true" />
          {t("Hiçbir şey imzalanmadı veya yazılmadı.")}
        </p>
      </div>
    </DetailSection>
  )
}
