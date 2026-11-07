"use client"

import { useState } from "react"
import {
  Box,
  Cctv,
  HardDrive,
  Laptop,
  Monitor,
  Printer,
  Router,
  Server,
  Smartphone,
  Tablet,
  Tv,
  type LucideIcon,
} from "lucide-react"

import { SignChange } from "@/components/sign-change"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { msg, useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

/** The signed device types (#233, ADR-0232), in the server's order. */
export const DEVICE_ICONS: { id: string; label: string; Icon: LucideIcon }[] = [
  { id: "laptop", label: msg("Dizüstü bilgisayar"), Icon: Laptop },
  { id: "desktop", label: msg("Masaüstü bilgisayar"), Icon: Monitor },
  { id: "phone", label: msg("Telefon"), Icon: Smartphone },
  { id: "tablet", label: msg("Tablet"), Icon: Tablet },
  { id: "server", label: msg("Sunucu"), Icon: Server },
  { id: "nas", label: msg("NAS"), Icon: HardDrive },
  { id: "printer", label: msg("Yazıcı"), Icon: Printer },
  { id: "camera", label: msg("Kamera"), Icon: Cctv },
  { id: "tv", label: msg("Televizyon"), Icon: Tv },
  { id: "router", label: msg("Yönlendirici"), Icon: Router },
  { id: "other", label: msg("Diğer"), Icon: Box },
]

function iconEntry(icon: string | undefined) {
  return DEVICE_ICONS.find((x) => x.id === icon)
}

/** The device's signed type icon, or nothing when none is set. */
export function DeviceTypeIcon({ icon, className }: { icon?: string; className?: string }) {
  const { t } = useI18n()
  const entry = iconEntry(icon)
  if (!entry) return null
  const { Icon } = entry
  return <Icon role="img" aria-label={t(entry.label)} className={cn("size-4 shrink-0 text-muted-foreground", className)} />
}

interface DeviceIconDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  name: string
  current?: string
}

/** Picks the device type and signs it into the document. */
export function DeviceIconDialog({ open, onOpenChange, name, current }: DeviceIconDialogProps) {
  const { t } = useI18n()
  const [next, setNext] = useState<string | null>(null)

  function handleOpenChange(value: boolean) {
    if (!value) setNext(null)
    onOpenChange(value)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("{name} simgesi", { name })}</DialogTitle>
          <DialogDescription className="text-pretty">
            {next !== null
              ? t("Değişikliği kontrol et ve kök anahtarınla imzala.")
              : t("Simge imzalı ağ belgesine yazılır; panel ve tepsi cihazı bu türle gösterir. İlk simge asgari istemci sürümünü 1.0.0-beta.2 yapar.")}
          </DialogDescription>
        </DialogHeader>
        {open && next === null ? <IconPicker current={current ?? ""} onNext={setNext} /> : null}
        {open && next !== null ? (
          <SignChange
            endpoint="/api/devices/icon"
            payload={{ name, icon: next }}
            confirmLabel={t("İmzala ve kaydet")}
            onBack={() => setNext(null)}
            onDone={() => handleOpenChange(false)}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

function IconPicker({ current, onNext }: { current: string; onNext: (icon: string) => void }) {
  const { t } = useI18n()
  const [choice, setChoice] = useState(current)
  return (
    <div className="flex flex-col gap-4">
      <div role="radiogroup" aria-label={t("Cihaz türü")} className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        {DEVICE_ICONS.map(({ id, label, Icon }) => {
          const selected = choice === id
          return (
            <button
              key={id}
              type="button"
              role="radio"
              aria-checked={selected}
              onClick={() => setChoice(id)}
              className={cn(
                "flex items-center gap-2 rounded-md border px-3 py-2 text-left text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring",
                selected ? "border-primary bg-primary/10 text-foreground" : "border-border text-muted-foreground hover:text-foreground",
              )}
            >
              <Icon aria-hidden="true" className="size-4 shrink-0" />
              <span className="truncate">{t(label)}</span>
            </button>
          )
        })}
      </div>
      <DialogFooter className="gap-2">
        {current ? (
          <Button type="button" variant="outline" onClick={() => onNext("")}>
            {t("Simgeyi kaldır")}
          </Button>
        ) : null}
        <Button type="button" disabled={choice === current || choice === ""} onClick={() => onNext(choice)}>
          {t("Değişikliği göster")}
        </Button>
      </DialogFooter>
    </div>
  )
}
