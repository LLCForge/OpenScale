import { msg, tx } from "@/lib/i18n/i18n"
import type { Diff } from "@/lib/types"

/**
 * One line per change of a document version, as the history list shows it.
 * The lines keep the server's diff format ("+ cihaz x"); DiffList shows
 * them in the interface language.
 */
export function diffLines(d: Diff): string[] {
  const lines = [
    // i18n-ignore: sunucunun fark satırı biçimi; DiffList çevirir
    ...d.added_devices.map((n) => "+ cihaz " + n),
    // i18n-ignore: sunucunun fark satırı biçimi; DiffList çevirir
    ...d.removed_devices.map((n) => "- cihaz " + n + " (iptal)"),
    // i18n-ignore: sunucunun fark satırı biçimi; DiffList çevirir
    ...d.changed_devices.map((n) => "~ cihaz " + n),
    // Per-device details (renames, key rotations, tags) right under the
    // changed devices; older entries do not carry them.
    ...(d.device_changes ?? []).map((line) => `~   ${line}`),
    // i18n-ignore: sunucunun fark satırı biçimi; DiffList çevirir
    ...d.added_rules.map((r) => "+ kural " + r),
    // i18n-ignore: sunucunun fark satırı biçimi; DiffList çevirir
    ...d.removed_rules.map((r) => "- kural " + r),
    ...d.settings_changes,
  ]
  return lines.length > 0 ? lines : [msg("Yalnızca geçerlilik süresi yenilendi")]
}

/** A short plain sentence for a version's changes ("2 cihaz eklendi, 1 kural silindi"). */
export function diffSummary(d: Diff | undefined): string {
  if (!d) return tx("Ağ oluşturuldu")
  const parts: string[] = []
  const add = (count: number, text: string) => {
    if (count > 0) parts.push(tx(text, { count }))
  }
  add(d.added_devices.length, msg("{count} cihaz eklendi"))
  add(d.removed_devices.length, msg("{count} cihaz çıkarıldı"))
  add(d.changed_devices.length, msg("{count} cihaz değişti"))
  add(d.added_rules.length, msg("{count} kural eklendi"))
  add(d.removed_rules.length, msg("{count} kural silindi"))
  add(d.settings_changes.length, msg("{count} ayar değişti"))
  return parts.length > 0 ? parts.join(", ") : tx("Geçerlilik süresi yenilendi")
}
