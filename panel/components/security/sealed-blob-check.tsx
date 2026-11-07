"use client"

import { useId, useState } from "react"
import { FileCheck } from "lucide-react"

import { fileToBase64 } from "@/components/security/file-base64"
import { SettingRow, SettingsSection } from "@/components/settings/settings-layout"
import { Spinner } from "@/components/ui/spinner"
import { errorMessage, post } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { useI18n } from "@/lib/i18n/i18n"
import type { SealedBlobReply } from "@/lib/pa-types"
import { cn } from "@/lib/utils"

/** Verifies a sealed administrator blob's signature (ADR-0180); its content is never shown. */
export function SealedBlobCheck() {
  const { t, ts } = useI18n()
  const id = useId()
  const [busy, setBusy] = useState(false)
  // The reply is kept rather than its text so a language change re-renders it.
  const [result, setResult] = useState<{ reply: SealedBlobReply } | { failure: string } | null>(null)

  async function onFile(file: File | undefined) {
    if (!file) return
    setBusy(true)
    setResult(null)
    try {
      const blob = await fileToBase64(file)
      const r = await post<SealedBlobReply>("/api/g2/sealed-blob/verify", { blob })
      setResult({ reply: r })
    } catch (err) {
      setResult({ failure: errorMessage(err) })
    } finally {
      setBusy(false)
    }
  }

  const ok = result !== null && "reply" in result && result.reply.valid
  let resultText = ""
  if (result !== null) {
    if ("failure" in result) {
      resultText = result.failure
    } else {
      const r = result.reply
      if (!r.valid) {
        resultText = r.error ? ts(r.error) : t("Doğrulanamadı.")
      } else {
        const vars = { kind: r.kind ?? "?", seq: r.seq ?? 0, signer: r.signer ?? "?", size: r.size ?? 0 }
        resultText = r.issuedAt
          ? t("Mühürlü veri doğrulandı: {kind}, sıra {seq}, imzalayan {signer}, {size} bayt, {date}.", {
              ...vars,
              date: formatDateTime(r.issuedAt),
            })
          : t("Mühürlü veri doğrulandı: {kind}, sıra {seq}, imzalayan {signer}, {size} bayt.", vars)
      }
    }
  }

  return (
    <SettingsSection
      id="muhurlu"
      title={t("Mühürlü veri")}
      description={t("Koordinatörde saklanan mühürlü yönetici verisinin imzasını denetler; içerik gösterilmez.")}
    >
      <SettingRow
        title={t("Dosyayı doğrula")}
        description={t("Koordinatörden veya yedekten aldığınız mühürlü dosyayı seçin.")}
        action={
          <label
            htmlFor={id}
            className="inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-lg border bg-background px-2.5 text-sm font-medium hover:bg-muted focus-within:ring-3 focus-within:ring-ring/50"
          >
            {busy ? <Spinner /> : <FileCheck className="size-4" aria-hidden="true" />}
            {t("Dosya seç")}
            <input
              id={id}
              type="file"
              className="sr-only"
              disabled={busy}
              onChange={(e) => {
                void onFile(e.target.files?.[0])
                e.target.value = ""
              }}
            />
          </label>
        }
      >
        {result ? (
          <p role="status" className={cn("text-sm text-pretty", ok ? "text-success" : "text-destructive")}>
            {resultText}
          </p>
        ) : null}
      </SettingRow>
    </SettingsSection>
  )
}
