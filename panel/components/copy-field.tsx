"use client"

import { useState } from "react"
import { Check, Copy } from "lucide-react"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import { tx, useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

/** How long a copied secret (an invite code) stays on the clipboard (#47). */
const SECRET_CLIPBOARD_MS = 60_000

/**
 * Empties the clipboard if it still holds the secret. The clipboard is read
 * only when the browser already granted clipboard-read, so the owner never
 * sees a permission prompt; without it nothing is cleared, because text the
 * owner copied later from another program must never be lost.
 */
async function clearSecretIfUnchanged(text: string): Promise<boolean> {
  try {
    const perm = await navigator.permissions.query({ name: "clipboard-read" as PermissionName })
    if (perm.state !== "granted") return false
    if ((await navigator.clipboard.readText()) !== text) return false
    await navigator.clipboard.writeText("")
    return true
  } catch {
    return false
  }
}

function scheduleSecretClear(text: string) {
  window.setTimeout(() => {
    void clearSecretIfUnchanged(text).then((cleared) => {
      if (cleared) toast.info(tx("Kopyalanan kod güvenlik için panodan silindi."))
    })
  }, SECRET_CLIPBOARD_MS)
}

interface CopyButtonProps {
  value: string
  label: string
  className?: string
  /** Secret values are removed from the clipboard after a minute when the browser allows it. */
  secret?: boolean
}

/** Icon button that copies text and confirms with a check mark. */
export function CopyButton({ value, label, className, secret }: CopyButtonProps) {
  const [copied, setCopied] = useState(false)
  return (
    <Button
      type="button"
      variant="ghost"
      size="icon-sm"
      className={className}
      aria-label={label}
      onClick={async () => {
        if (await copyText(value)) {
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
          if (secret) {
            scheduleSecretClear(value)
            toast.info(tx("Kod panoda. İşiniz bitince panoyu temizleyin; tarayıcı izin verirse 1 dakika sonra kendiliğinden silinir."))
          }
        } else {
          toast.error(tx("Panoya kopyalanamadı."))
        }
      }}
    >
      {copied ? <Check className="text-success" /> : <Copy />}
    </Button>
  )
}

interface CodeLineProps {
  value: string
  label?: string
  className?: string
  /** Shows a long value on one line with horizontal scroll instead of wrapping. */
  nowrap?: boolean
  /** Marks the value as a secret: see CopyButton. */
  secret?: boolean
}

/** A monospace box with a copy button, like a terminal snippet. */
export function CodeLine({ value, label, className, nowrap, secret }: CodeLineProps) {
  const { t } = useI18n()
  return (
    <div className={cn("flex items-start gap-2 rounded-lg border bg-muted/60 py-2 pr-1.5 pl-3", className)}>
      <code className={cn("min-w-0 flex-1 py-1 font-mono text-sm leading-relaxed", nowrap ? "overflow-x-auto whitespace-pre" : "wrap-anywhere")}>
        {value}
      </code>
      <CopyButton value={value} label={label ?? t("Kopyala")} secret={secret} />
    </div>
  )
}
