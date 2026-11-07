import { X } from "lucide-react"

import { formatAgo, formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { DeviceLiveStatus } from "@/lib/types"
import { cn } from "@/lib/utils"

const labels: Record<DeviceLiveStatus, string> = {
  this: msg("Bu bilgisayar"),
  online: msg("Çevrimiçi"),
  offline: msg("Çevrimdışı"),
  unknown: msg("Durum bilinmiyor"),
}

/** Small dot plus label for a device's connection state. */
export function DeviceStatus({ status, lastSeen, className }: { status: DeviceLiveStatus; lastSeen: string | null; className?: string }) {
  const { t } = useI18n()
  const text = status === "offline" && lastSeen ? t("Son görülme {ago}", { ago: formatAgo(lastSeen) }) : t(labels[status])
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-xs text-muted-foreground", className)}>
      <span
        aria-hidden="true"
        className={cn(
          "size-2 rounded-full",
          status === "online" || status === "this" ? "bg-success" : status === "offline" ? "bg-muted-foreground/50" : "border border-muted-foreground/50"
        )}
      />
      {text}
    </span>
  )
}

export function DeviceRoleBadges({
  admin,
  exitNode,
  className,
  onRemoveExit,
}: {
  admin: boolean
  exitNode: boolean
  className?: string
  /** When set, the exit node badge gets a button that removes the role. */
  onRemoveExit?: () => void
}) {
  const { t } = useI18n()
  if (!admin && !exitNode) {
    return <span className={cn("text-sm text-muted-foreground", className)}>{t("Cihaz")}</span>
  }
  return (
    <span className={cn("flex flex-wrap gap-1.5", className)}>
      {admin ? <span className="rounded-md border px-2 py-0.5 text-xs font-medium">{t("Yönetici")}</span> : null}
      {exitNode ? (
        <span className="inline-flex items-center gap-1 rounded-md bg-primary py-0.5 pr-1 pl-2 text-xs font-medium text-primary-foreground">
          {t("Çıkış düğümü")}
          {onRemoveExit ? (
            <button
              type="button"
              onClick={onRemoveExit}
              aria-label={t("Çıkış düğümü rolünü kaldır")}
              title={t("Çıkış düğümü rolünü kaldır")}
              className="rounded-sm p-0.5 hover:bg-primary-foreground/20 focus-visible:ring-2 focus-visible:ring-primary-foreground focus-visible:outline-none"
            >
              <X className="size-3" />
            </button>
          ) : null}
        </span>
      ) : null}
    </span>
  )
}

/** "Son görülme" cell: a green dot and "Bağlı", or a gray dot and the last time seen. */
export function LastSeen({ status, lastSeen, className }: { status: DeviceLiveStatus; lastSeen: string | null; className?: string }) {
  const { t } = useI18n()
  const connected = status === "online" || status === "this"
  const text =
    status === "this"
      ? t("Bu bilgisayar")
      : status === "online"
        ? t("Bağlı")
        : status === "offline"
          ? lastSeen
            ? formatDateTime(lastSeen)
            : t("Çevrimdışı")
          : t("Bilinmiyor")
  return (
    <span className={cn("inline-flex items-center gap-2 text-sm whitespace-nowrap", connected ? "text-foreground" : "text-muted-foreground", className)}>
      <span
        aria-hidden="true"
        className={cn(
          "size-2 shrink-0 rounded-full",
          connected ? "bg-success" : status === "offline" ? "bg-muted-foreground/50" : "border border-muted-foreground/50"
        )}
      />
      {text}
    </span>
  )
}
