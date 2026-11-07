"use client"

import { ShieldCheck } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { msg, useI18n } from "@/lib/i18n/i18n"

interface PostQuantumBadgeProps {
  /** Post-quantum PSK state (ADR-0033): pq, negotiating, classical, unsupported or off. */
  state?: string
}

const labels: Record<string, { text: string; title: string; variant: "default" | "secondary" | "outline" }> = {
  pq: {
    text: msg("Kuantum sonrası"),
    title: msg("Bu eşle WireGuard ek olarak ML-KEM-768 ile anlaşılmış bir ön paylaşımlı anahtar kullanıyor."),
    variant: "default",
  },
  negotiating: { text: msg("Anlaşılıyor"), title: msg("Kuantum sonrası anahtar anlaşması sürüyor."), variant: "outline" },
  classical: { text: msg("Klasik"), title: msg("Bu eşle yalnızca klasik WireGuard şifrelemesi kullanılıyor."), variant: "secondary" },
  unsupported: {
    text: msg("Klasik"),
    title: msg("Eş kuantum sonrası anahtara yanıt vermedi: eski sürüm veya ayarı kapalı. Bağlantı klasik WireGuard ile şifreli."),
    variant: "secondary",
  },
  off: {
    text: msg("Klasik (kapalı)"),
    title: msg("Kuantum sonrası anahtar bu bilgisayarda kapalı (Gelişmiş ayarlar)."),
    variant: "outline",
  },
}

/** Per-peer post-quantum or classical badge (ADR-0033). Nothing while the tunnel is down. */
export function PostQuantumBadge({ state }: PostQuantumBadgeProps) {
  const { t } = useI18n()
  if (!state) return null
  const l = labels[state]
  if (!l) return null
  return (
    <Badge variant={l.variant} title={t(l.title)} className="gap-1">
      {state === "pq" ? <ShieldCheck aria-hidden="true" /> : null}
      {t(l.text)}
      <span className="sr-only">{`: ${t(l.title)}`}</span>
    </Badge>
  )
}
