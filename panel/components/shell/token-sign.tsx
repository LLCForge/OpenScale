"use client"

import { useEffect, useState } from "react"
import useSWR from "swr"
import { KeyRound } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"

/** GET /api/admin-mode/token (ADR-0223): the tray's YubiKey session. */
export interface TokenModeStatus {
  /** The tray reported within the last 15 seconds. */
  tray: boolean
  open: boolean
  /** A token with an OpenScale key is plugged in, no session yet. */
  offer: boolean
  role?: "root" | "admin"
  name?: string
  /** First 8 bytes of SHA-256 of the token key, hex. */
  key?: string
  reader?: string
  ends?: string
  idle_until?: string
  /** Why the last session ended. */
  reason?: string
  /** A root session is open: "YubiKey ile imzala" works. */
  can_sign: boolean
  left_sec: number
}

export function useTokenMode() {
  return useSWR<TokenModeStatus>("/api/admin-mode/token", fetcher, { refreshInterval: 5_000, shouldRetryOnError: false })
}

function mmss(sec: number): string {
  const s = Math.max(0, Math.floor(sec))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`
}

function useCountdown(active: boolean, sec: number): number {
  const [left, setLeft] = useState(sec)
  useEffect(() => {
    if (!active) return
    const end = Date.now() + sec * 1000
    const tick = () => setLeft(Math.max(0, Math.round((end - Date.now()) / 1000)))
    tick()
    const t = setInterval(tick, 1000)
    return () => clearInterval(t)
  }, [active, sec])
  return left
}

/**
 * Top bar chip for the YubiKey administrator mode: shown while the tray
 * holds an open token session, with the time until it closes (idle or
 * end). The tray closes it when the token is pulled; the next poll hides
 * the chip.
 */
export function TokenModeChip() {
  const { t } = useI18n()
  const { data } = useTokenMode()
  const open = Boolean(data?.open)
  const left = useCountdown(open, data?.left_sec ?? 0)
  if (!data?.open || left <= 0) return null
  const who = data.role === "admin" ? t("yönetici yetkisi: {name}", { name: data.name ?? "" }) : t("kök anahtar")
  const text = t("YubiKey yönetici kipi açık ({who}, anahtar {key}), {left} sonra kapanır", {
    who,
    key: data.key ?? "?",
    left: mmss(left),
  })
  return (
    <span
      role="status"
      title={text}
      className="hidden h-7 items-center gap-1.5 rounded-full bg-success/15 px-2.5 text-xs font-medium text-success sm:inline-flex [&>svg]:size-3.5"
    >
      <KeyRound aria-hidden="true" />
      <span className="tabular-nums">{`YubiKey · ${mmss(left)}`}</span>
      <span className="sr-only">{text}</span>
    </span>
  )
}

interface TokenSignOptionProps {
  disabled?: boolean
  signing: boolean
  onSign: () => void
}

/**
 * "YubiKey ile imzala" in the sign dialog: offered only while a root
 * token session is open in the tray. The tray shows the change and asks
 * before the token signs; the passphrase is not needed.
 */
export function TokenSignOption({ disabled, signing, onSign }: TokenSignOptionProps) {
  const { t } = useI18n()
  const { data } = useTokenMode()
  if (!data?.can_sign) {
    if (data?.offer) {
      return (
        <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
          {t('YubiKey takılı. Tepsi menüsünden "Yönetici kipini aç" seçerseniz bu değişikliği parola yerine anahtarla imzalayabilirsiniz.')}
        </p>
      )
    }
    return null
  }
  return (
    <div className="flex flex-col gap-2 rounded-md border border-border p-3 sm:flex-row sm:items-center sm:justify-between">
      <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
        {t("YubiKey yönetici kipi açık (anahtar")} <span className="font-mono text-foreground">{data.key}</span>).{" "}
        {t("Onay tepside istenir; jetona dokunmanız gerekebilir.")}
      </p>
      <Button type="button" variant="outline" onClick={onSign} disabled={disabled || signing} className="shrink-0">
        {signing ? <Spinner data-icon="inline-start" /> : <KeyRound data-icon="inline-start" />}
        {t("YubiKey ile imzala")}
      </Button>
    </div>
  )
}
