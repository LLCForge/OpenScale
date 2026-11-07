"use client"

import { useRef, useState } from "react"
import useSWR from "swr"
import { RefreshCwOff } from "lucide-react"

import { useAppStatus } from "@/components/app/use-app-status"
import { SettingBadge } from "@/components/settings/settings-layout"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { PrefMetaReply } from "@/lib/p2-diag-types"

// Settings that restart the connection (#799). The service marks them
// (internal/service/pref_meta.go); the panel shows a label next to them
// and, when the person using the panel may itself be connected through
// OpenScale (a remote panel or an active remote desktop session), asks
// again before saving, because the restart cuts that session off.

const metaKey = "/api/app/prefs/meta"

/** Panel form fields whose name differs from the setting key. */
const fieldAliases: Record<string, string> = {
  keepaliveSec: "keepalive",
  lazyIdleSec: "lazy-idle",
}

/** "forceRelay" -> "force-relay"; setting keys pass unchanged. */
export function prefKeyOf(field: string): string {
  return fieldAliases[field] ?? field.replace(/[A-Z]/g, (c) => `-${String.fromCharCode(c.charCodeAt(0) + 32)}`)
}

function usePrefMeta() {
  const { isApp } = useAppStatus()
  const { data } = useSWR<PrefMetaReply>(isApp ? metaKey : null, fetcher, { refreshInterval: 30_000 })
  const restart = new Set((data?.prefs ?? []).filter((p) => p.restarts_connection).map((p) => p.key))
  return { restart, remote: data?.remote_session === true, loaded: data !== undefined }
}

/** "Bağlantıyı yeniden başlatır" next to a setting (or a card of them). */
export function RestartsConnectionBadge({ prefKey }: { prefKey: string }) {
  const { t } = useI18n()
  const { restart } = usePrefMeta()
  if (!restart.has(prefKeyOf(prefKey))) return null
  return (
    <span title={t("Bu ayar değişince tünel birkaç saniyeliğine yeniden başlar; açık bağlantılar kopar.")}>
      <SettingBadge tone="warning">{t("Bağlantıyı yeniden başlatır")}</SettingBadge>
    </span>
  )
}

/**
 * ask(fields) resolves true when saving may go on: at once when nothing in
 * fields restarts the connection or the session is local, otherwise after
 * the person confirms in the dialog. Render `dialog` once in the form.
 */
export function useRestartConfirm(): { ask: (fields: string[]) => Promise<boolean>; dialog: React.ReactNode } {
  const { t } = useI18n()
  const { restart, remote } = usePrefMeta()
  const [open, setOpen] = useState(false)
  const pending = useRef<((ok: boolean) => void) | null>(null)

  function settle(ok: boolean) {
    const fn = pending.current
    pending.current = null
    setOpen(false)
    fn?.(ok)
  }

  function ask(fields: string[]): Promise<boolean> {
    if (!remote || !fields.some((f) => restart.has(prefKeyOf(f)))) return Promise.resolve(true)
    pending.current?.(false)
    return new Promise<boolean>((resolve) => {
      pending.current = resolve
      setOpen(true)
    })
  }

  const dialog = (
    <AlertDialog open={open} onOpenChange={(next) => (next ? undefined : settle(false))}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <RefreshCwOff className="size-4 text-warning" aria-hidden="true" />
            {t("Bağlantı yeniden başlayacak")}
          </AlertDialogTitle>
          <AlertDialogDescription className="text-pretty">
            {t(
              "Bu bilgisayara OpenScale üzerinden uzaktan bağlısınız. Bu ayar tüneli yeniden başlatır; uzak oturumunuz kopabilir ve tünel geri gelince yeniden bağlanmanız gerekir.",
            )}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={() => settle(false)}>{t("Vazgeç")}</AlertDialogCancel>
          <AlertDialogAction onClick={() => settle(true)}>{t("Yine de kaydet")}</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )

  return { ask, dialog }
}
