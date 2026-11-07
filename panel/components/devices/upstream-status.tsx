import { SettingBadge } from "@/components/settings/settings-layout"
import { formatAgo, formatDateTime } from "@/lib/format"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import type { UpstreamInfo, UpstreamKind, UpstreamMode } from "@/lib/inventory-types"

const modeText: Record<UpstreamMode, { text: string; tone: "success" | "danger" | "warning" | "muted"; hint: string }> = {
  tunnel: { text: msg("Bağlı"), tone: "success", hint: msg("Üyelerin internet trafiği sağlayıcının tünelinden çıkıyor.") },
  blocked: {
    text: msg("Kesik, trafik engelli"),
    tone: "danger",
    hint: msg("Sağlayıcı tüneli düştü; üyelerin internet trafiği sızmasın diye engelleniyor."),
  },
  direct: {
    text: msg("Doğrudan çıkış"),
    tone: "warning",
    hint: msg("Sağlayıcı tüneli düştü; üyelerin trafiği sunucunun kendi adresinden çıkıyor ve sitelere bu adres görünüyor."),
  },
  off: { text: msg("Kurulmadı"), tone: "muted", hint: msg("Üst çıkış seçili ama yönlendirme kurulamadı.") },
}

// The Tor exit has no provider tunnel or handshake; its states read differently.
const torModeText: Record<UpstreamMode, { text: string; tone: "success" | "danger" | "warning" | "muted"; hint: string }> = {
  tunnel: { text: msg("Tor'a bağlı"), tone: "success", hint: msg("Üyelerin internet trafiği ve DNS'i sunucudaki Tor istemcisinden çıkıyor.") },
  blocked: {
    text: msg("Tor yanıt vermiyor, trafik engelli"),
    tone: "danger",
    hint: msg("Tor istemcisinin TransPort veya DNSPort'u dinlemiyor; üyelerin internet trafiği sızmasın diye engelleniyor."),
  },
  direct: modeText.direct,
  off: { text: msg("Kurulmadı"), tone: "muted", hint: msg("Tor çıkışı seçili ama yönlendirme kurulamadı.") },
}

function modeInfo(mode: UpstreamMode, kind?: UpstreamKind) {
  const table = kind === "tor" ? torModeText : modeText
  return table[mode] ?? table.off
}

/** Display name of an upstream exit: "Tor", "Cloudflare WARP" or "Mullvad · İsveç". Call during render. */
export function upstreamName(upstream: UpstreamInfo): string {
  const label = upstream.label.trim()
  switch (upstream.kind) {
    case "tor":
      return "Tor"
    case "warp":
      return "Cloudflare WARP"
    case "mullvad":
      if (!label) return "Mullvad"
      return label.toLocaleLowerCase("en").startsWith("mullvad") ? label : `Mullvad · ${label}`
    default:
      return label || tx("Üst çıkış")
  }
}

/** Short description of the upstream kind for the device detail row. Call during render. */
export function upstreamKindText(kind?: UpstreamKind): string {
  switch (kind) {
    case "tor":
      return tx("Sunucuda kurulu Tor istemcisi")
    case "warp":
      return "Cloudflare WARP (WireGuard)"
    case "mullvad":
      return "Mullvad (WireGuard)"
    default:
      return tx("Harici WireGuard sağlayıcısı")
  }
}

/** Badge for an upstream exit's mode (ADR-0142). */
export function UpstreamBadge({ mode, kind }: { mode: UpstreamMode; kind?: UpstreamKind }) {
  const { t } = useI18n()
  const m = modeInfo(mode, kind)
  return (
    <span title={t(m.hint)}>
      <SettingBadge tone={m.tone}>{t(m.text)}</SettingBadge>
    </span>
  )
}

/** "Mullvad · İsveç" with its state; the explanation only when it matters. */
export function UpstreamSummary({ upstream, detailed = false }: { upstream: UpstreamInfo; detailed?: boolean }) {
  const { t } = useI18n()
  const m = modeInfo(upstream.mode, upstream.kind)
  const tor = upstream.kind === "tor"
  return (
    <span className="flex min-w-0 flex-col gap-1">
      <span className="flex flex-wrap items-center gap-1.5">
        <span className="font-medium break-words">{upstreamName(upstream)}</span>
        <UpstreamBadge mode={upstream.mode} kind={upstream.kind} />
      </span>
      {detailed ? (
        <span className="text-xs text-muted-foreground text-pretty">
          {upstream.mode === "tunnel" ? null : `${t(m.hint)} `}
          {tor ? (
            upstream.mode === "tunnel" ? t(m.hint) : null
          ) : upstream.lastHandshake ? (
            <span title={formatDateTime(upstream.lastHandshake)}>{t("Son el sıkışma {ago}.", { ago: formatAgo(upstream.lastHandshake) })}</span>
          ) : (
            t("Sağlayıcıyla henüz el sıkışılmadı.")
          )}
        </span>
      ) : null}
    </span>
  )
}
