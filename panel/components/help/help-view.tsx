"use client"

import { LifeBuoy } from "lucide-react"

import { Troubleshooting } from "@/components/help/troubleshooting"
import { PageHeader } from "@/components/page-header"
import { useI18n } from "@/lib/i18n/i18n"

// Yardım sayfası yalnızca sorun gidermeyi gösterir: kararlı hata kodları,
// belirtiden ilk bakılacak yere tablo ve panelsiz çalışan komutlar. Belgeler
// panelden kaldırıldı; terminalde 'openscale docs' ile okunmaya devam eder.

export function HelpView() {
  const { t, locale } = useI18n()
  return (
    <>
      <PageHeader
        section={{ label: t("Yardım"), icon: LifeBuoy }}
        title={t("Sorun giderme")}
        description={t("Hata kodları, belirtiye göre ilk bakılacak yer ve panel açılmadığında çalışan komutlar; internet gerekmez.")}
      />
      <div lang={locale}>
        <Troubleshooting />
      </div>
    </>
  )
}
