"use client"

import { Download } from "lucide-react"

import { Button } from "@/components/ui/button"
import { useI18n } from "@/lib/i18n/i18n"

/** Saves the join bundle as openscale-bundle.txt for `openscale join --bundle @file`. */
export function BundleDownload({ bundle, variant = "outline" }: { bundle: string; variant?: "outline" | "default" }) {
  const { t } = useI18n()
  function download() {
    const url = URL.createObjectURL(new Blob([bundle + "\n"], { type: "text/plain" }))
    const a = document.createElement("a")
    a.href = url
    a.download = "openscale-bundle.txt"
    a.click()
    URL.revokeObjectURL(url)
  }
  return (
    <Button type="button" variant={variant} onClick={download}>
      <Download data-icon="inline-start" />
      {t("Katılım paketini indir")}
    </Button>
  )
}
