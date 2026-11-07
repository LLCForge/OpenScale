"use client"

import { Info } from "lucide-react"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { useI18n } from "@/lib/i18n/i18n"

/** Constraints of the network DNS section, shown on the card and the dialog. */
export function DnsNote() {
  const { t } = useI18n()
  return (
    <Alert>
      <Info />
      <AlertDescription className="text-pretty">
        {t("Genel internet çözücüleri (ör. 1.1.1.1) kabul edilmez; çözücü olarak yalnızca ağdaki bir cihazın tünel adresi seçilebilir ve o cihaza 53. port için erişim kuralı gerekir. Eski sürümlü cihazlar DNS bölümü olan belgeyi reddeder; önce bütün cihazları güncelleyin.")}
      </AlertDescription>
    </Alert>
  )
}
