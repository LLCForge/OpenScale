"use client"

import { Monitor, MonitorSmartphone } from "lucide-react"

import { Button } from "@/components/ui/button"
import { useI18n } from "@/lib/i18n/i18n"

// Monitor picker of the remote desktop viewer (#120). The target lists
// its monitors in the "ready" and "monitors" messages
// (internal/panel/f3_rdesk_monitors.go); choosing one sends
// {"type": "monitor", "index": n}, and -1 shows every monitor together.

export interface RemoteMonitor {
  index: number
  width: number
  height: number
  x: number
  y: number
  primary: boolean
}

export const allMonitors = -1

interface MonitorPickerProps {
  monitors: RemoteMonitor[]
  selected: number | undefined
  onSelect: (index: number) => void
}

export function MonitorPicker({ monitors, selected, onSelect }: MonitorPickerProps) {
  const { t } = useI18n()
  if (monitors.length < 2) return null
  return (
    <div role="group" aria-label={t("Monitör seçimi")} className="flex flex-wrap items-center gap-1">
      {monitors.map((m) => (
        <Button
          key={m.index}
          variant={selected === m.index ? "secondary" : "ghost"}
          size="sm"
          aria-pressed={selected === m.index}
          title={`${m.width}×${m.height}`}
          onClick={() => onSelect(m.index)}
        >
          <Monitor data-icon="inline-start" />
          {m.primary ? t("Monitör {n} (birincil)", { n: m.index + 1 }) : t("Monitör {n}", { n: m.index + 1 })}
        </Button>
      ))}
      <Button variant={selected === allMonitors ? "secondary" : "ghost"} size="sm" aria-pressed={selected === allMonitors} onClick={() => onSelect(allMonitors)}>
        <MonitorSmartphone data-icon="inline-start" />
        {t("Tüm monitörler")}
      </Button>
    </div>
  )
}
