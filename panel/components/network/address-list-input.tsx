"use client"

import { useState } from "react"
import { Plus, X } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useI18n } from "@/lib/i18n/i18n"
import type { ResolverChoice } from "@/lib/types"

const ipv4Pattern = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
const ipv6Pattern = /^[0-9a-fA-F:]+$/

/** A bare IPv4 or IPv6 address (no port, no zone). */
export function isIpAddress(value: string): boolean {
  if (ipv4Pattern.test(value)) return true
  if (!ipv6Pattern.test(value) || !value.includes(":") || value.length > 39) return false
  const doubleColons = value.split("::").length - 1
  if (doubleColons > 1) return false
  const groups = value.split(":").filter((g) => g.length > 0)
  if (groups.some((g) => g.length > 4)) return false
  return doubleColons === 1 ? groups.length <= 7 : groups.length === 8
}

interface AddressListInputProps {
  id: string
  value: string[]
  onChange: (value: string[]) => void
  resolvers: ResolverChoice[]
  max: number
  invalid?: boolean
}

/**
 * Picks resolver addresses: one click for a device's tunnel address, or
 * free text. The server accepts only tunnel addresses of the network's
 * devices; an unknown address is flagged here and refused at the dry run.
 */
export function AddressListInput({ id, value, onChange, resolvers, max, invalid }: AddressListInputProps) {
  const { t } = useI18n()
  const [text, setText] = useState("")
  const [error, setError] = useState<string | null>(null)
  const known = new Map<string, string>()
  for (const r of resolvers) {
    if (r.ipv4) known.set(r.ipv4, r.name)
    if (r.ipv6) known.set(r.ipv6, r.name)
  }
  const full = value.length >= max

  function add(address: string) {
    const a = address.trim()
    if (!isIpAddress(a)) {
      setError(t("Geçerli bir IPv4 veya IPv6 adresi gir (port olmadan)"))
      return
    }
    if (value.includes(a)) {
      setError(t("Bu adres zaten listede"))
      return
    }
    if (full) {
      setError(t("En fazla {max} adres", { max }))
      return
    }
    setError(null)
    setText("")
    onChange([...value, a])
  }

  const unknown = value.filter((a) => !known.has(a))

  return (
    <div className="flex flex-col gap-2">
      {value.length > 0 ? (
        <ul aria-label={t("Seçili çözücüler")} className="flex flex-wrap gap-1.5">
          {value.map((a) => (
            <li key={a}>
              <Badge variant={known.has(a) ? "secondary" : "destructive"} className="h-6 gap-1 pr-0.5 font-mono">
                {a}
                {known.has(a) ? <span className="font-sans text-muted-foreground">({known.get(a)})</span> : null}
                <Button
                  type="button"
                  variant="ghost"
                  size="icon-xs"
                  className="size-5"
                  aria-label={t("{address} adresini çıkar", { address: a })}
                  onClick={() => onChange(value.filter((v) => v !== a))}
                >
                  <X />
                </Button>
              </Badge>
            </li>
          ))}
        </ul>
      ) : (
        <span className="text-xs text-muted-foreground">{t("Seçili çözücü yok.")}</span>
      )}
      {resolvers.length > 0 ? (
        <div className="flex flex-wrap gap-1.5" aria-label={t("Cihaz adresleri")}>
          {resolvers.flatMap((r) =>
            [r.ipv4, r.ipv6]
              .filter((a) => a && !value.includes(a))
              .map((a) => (
                <Button key={a} type="button" variant="outline" size="xs" disabled={full} onClick={() => add(a)}>
                  <Plus data-icon="inline-start" />
                  {r.name} <span className="font-mono">{a}</span>
                </Button>
              ))
          )}
        </div>
      ) : null}
      <div className="flex gap-2">
        <Input
          id={id}
          value={text}
          disabled={full}
          placeholder="100.64.0.5"
          autoComplete="off"
          spellCheck={false}
          className="font-mono"
          aria-invalid={invalid || error ? true : undefined}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault()
              add(text)
            }
          }}
        />
        <Button type="button" variant="outline" disabled={full || text.trim() === ""} onClick={() => add(text)}>
          {t("Ekle")}
        </Button>
      </div>
      {error ? <p className="text-xs text-destructive">{error}</p> : null}
      {unknown.length > 0 ? (
        <p className="text-xs text-destructive text-pretty">
          {t("{addresses} ağdaki bir cihazın tünel adresi değil; sunucu bu adresi kabul etmez.", { addresses: unknown.join(", ") })}
        </p>
      ) : null}
    </div>
  )
}
