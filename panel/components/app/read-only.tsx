"use client"

import useSWR from "swr"
import { Eye } from "lucide-react"

import { NoticeBar } from "@/components/notice-bar"
import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"

interface SessionInfo {
  csrfToken: string
  readOnly: boolean
  remote?: boolean
}

/**
 * Whether the panel is read-only (F-180). The server refuses every change
 * anyway; this only hides the controls. Until the answer arrives the panel
 * counts as read-only, so no button flashes up and disappears again.
 */
export function useReadOnly(): boolean {
  const { data } = useSWR<SessionInfo>("/api/session", fetcher, { refreshInterval: 15_000 })
  return data ? data.readOnly : true
}

/** Renders its children only while the panel accepts changes. */
export function Writable({ children }: { children: React.ReactNode }) {
  return useReadOnly() ? null : <>{children}</>
}

/** One calm, dismissible line shown on every page while the panel is read-only. */
export function ReadOnlyBanner() {
  const { t } = useI18n()
  const { data } = useSWR<SessionInfo>("/api/session", fetcher, { refreshInterval: 15_000 })
  if (!data?.readOnly) return null
  if (data.remote) {
    return (
      <NoticeBar id="read-only-remote" icon={<Eye />}>
        <span className="font-medium text-foreground">{t("Uzak panel, salt okunur.")}</span>{" "}
        {t("Değişiklikleri kök anahtarın bulunduğu yönetici bilgisayarda yap.")}
      </NoticeBar>
    )
  }
  return (
    <NoticeBar id="read-only" icon={<Eye />}>
      <span className="font-medium text-foreground">{t("Panel salt okunur.")}</span> {t("Kapatmak için")}{" "}
      <code className="font-mono text-xs">openscale panel readonly off</code>
    </NoticeBar>
  )
}
