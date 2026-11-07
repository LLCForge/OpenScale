"use client"

import { useEffect, useRef } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import useSWR from "swr"
import { FileDown } from "lucide-react"
import { toast } from "sonner"

import { NoticeBar } from "@/components/notice-bar"
import { Button } from "@/components/ui/button"
import { optionalFetcher, type AppsStatus } from "@/lib/apps"
import { useI18n } from "@/lib/i18n/i18n"

/**
 * Panel notification for file offers waiting for the owner (ADR-0031). It
 * polls the desktop service; the CLI panel has no services and shows
 * nothing.
 */
export function OfferBanner() {
  const { t } = useI18n()
  const { data } = useSWR<AppsStatus | null>("/api/app/apps", optionalFetcher, { refreshInterval: 4_000 })
  const pending = data?.pendingOffers ?? 0
  const seen = useRef(0)
  const router = useRouter()
  useEffect(() => {
    if (pending > seen.current) {
      toast.info(t("Bir cihaz bu bilgisayara dosya göndermek istiyor."), {
        action: { label: t("Gelen kutusu"), onClick: () => router.push("/inbox") },
      })
    }
    seen.current = pending
  }, [pending, router, t])
  if (pending === 0) return null
  return (
    <NoticeBar
      icon={<FileDown />}
      action={
        <Button size="sm" variant="outline" nativeButton={false} render={<Link href="/inbox" />}>
          {t("Gelen kutusu")}
        </Button>
      }
    >
      <span className="font-medium text-foreground">{t("Onay bekleyen {count} dosya var.", { count: pending })}</span>{" "}
      {t("Kabul edilmezse iki dakika içinde reddedilir.")}
    </NoticeBar>
  )
}
