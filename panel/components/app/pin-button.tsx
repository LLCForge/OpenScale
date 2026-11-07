"use client"

import { useState } from "react"
import { Pin, PinOff } from "lucide-react"
import { toast } from "sonner"

import { useReadOnly } from "@/components/app/read-only"
import { useAppStatus } from "@/components/app/use-app-status"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { errorMessage, post } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { AppStatus } from "@/lib/types"
import { cn } from "@/lib/utils"

/** Pinned device names of this computer (a local setting, F-159). */
export function usePinned(): { pinned: string[]; available: boolean } {
  const { status, isApp } = useAppStatus()
  return { pinned: status?.device?.pinned ?? [], available: isApp && !!status?.device?.name }
}

/** Sorts pinned items first, keeping the order within each group. */
export function pinnedFirst<T>(items: T[], pinned: string[], name: (item: T) => string): T[] {
  const set = new Set(pinned)
  return [...items].sort((a, b) => Number(set.has(name(b))) - Number(set.has(name(a))))
}

/** Pins or unpins a device. Hidden in the command-line and read-only panel. */
export function PinButton({ name, pinned, className }: { name: string; pinned: boolean; className?: string }) {
  const { t } = useI18n()
  const { isApp, status, mutate } = useAppStatus()
  const readOnly = useReadOnly()
  const [busy, setBusy] = useState(false)
  if (!isApp || !status?.device?.name || readOnly) return null

  async function toggle() {
    setBusy(true)
    try {
      const res = await post<AppStatus>("/api/app/pin", { name, pinned: !pinned })
      await mutate(res, { revalidate: false })
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const label = pinned ? t("{name} sabitlemesini kaldır", { name }) : t("{name} cihazını üste sabitle", { name })
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label={label}
            aria-pressed={pinned}
            disabled={busy}
            onClick={toggle}
            className={cn(pinned ? "text-foreground" : "text-muted-foreground", className)}
          />
        }
      >
        {busy ? <Spinner /> : pinned ? <PinOff /> : <Pin />}
      </TooltipTrigger>
      <TooltipContent>{pinned ? t("Sabitlemeyi kaldır") : t("Üste sabitle")}</TooltipContent>
    </Tooltip>
  )
}
