"use client"

import { Monitor, ShieldCheck } from "lucide-react"

import { useI18n } from "@/lib/i18n/i18n"
import type { Device } from "@/lib/types"

function DeviceCard({ device }: { device: Device }) {
  return (
    <div className="flex items-center gap-3">
      <span className="flex size-11 items-center justify-center rounded-lg border bg-secondary text-muted-foreground">
        <Monitor className="size-5" />
      </span>
      <span className="flex flex-col">
        <span className="font-medium">{device.name}</span>
        <span className="font-mono text-sm text-muted-foreground">{device.ipv4}</span>
      </span>
    </div>
  )
}

/** Right-hand illustration of the wizard: the devices and the rule between them. */
export function DevicePreview({ first, second, connected }: { first?: Device; second?: Device; connected: boolean }) {
  const { t } = useI18n()
  if (!first) {
    return (
      <div className="flex flex-col items-center gap-6 text-center">
        <Pulse />
        <p className="text-sm text-muted-foreground">{t("İlk cihazın bekleniyor")}</p>
      </div>
    )
  }
  return (
    <div className="flex flex-col items-center gap-3">
      <DeviceCard device={first} />
      {second ? (
        <>
          <span aria-hidden="true" className="h-8 border-l border-dashed border-success/60" />
          <span
            className={connected ? "text-success" : "text-muted-foreground"}
            aria-label={connected ? t("Aralarında kural var") : t("Henüz kural yok")}
          >
            <ShieldCheck className="size-5" />
          </span>
          <span aria-hidden="true" className="h-8 border-l border-dashed border-success/60" />
          <DeviceCard device={second} />
        </>
      ) : (
        <div className="mt-8 flex flex-col items-center gap-6 text-center">
          <Pulse />
          <p className="text-sm text-muted-foreground">{t("İkinci cihazın bekleniyor")}</p>
        </div>
      )}
    </div>
  )
}

function Pulse() {
  return (
    <span className="relative flex size-16 items-center justify-center" aria-hidden="true">
      <span className="absolute inline-flex size-full animate-ping rounded-full bg-primary/20" />
      <span className="relative inline-flex size-16 items-center justify-center rounded-full border border-primary/40 bg-primary/10">
        <span className="size-4 rounded-full bg-primary" />
      </span>
    </span>
  )
}
