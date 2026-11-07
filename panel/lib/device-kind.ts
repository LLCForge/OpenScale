// Device type for icons (#233). The signed document has no type field, so
// the panel infers it from the operating system the device reports and,
// failing that, from common words in its name. It is only a picture: no
// decision depends on it.

import { msg } from "@/lib/i18n/i18n"

export type DeviceKind = "coordinator" | "phone" | "server" | "laptop" | "desktop" | "unknown"

const phoneWords = ["phone", "telefon", "iphone", "android", "pixel", "galaxy", "tablet", "ipad"]
const serverWords = ["server", "sunucu", "vps", "nas", "pi", "raspberry", "router", "homelab", "srv"]
const laptopWords = ["laptop", "notebook", "macbook", "dizustu", "dizüstü", "thinkpad", "book"] // i18n-ignore: ad içinde aranan sözcük
const desktopWords = ["desktop", "masaustu", "masaüstü", "pc", "workstation", "imac"] // i18n-ignore: ad içinde aranan sözcük

function nameHas(name: string, words: string[]): boolean {
  const parts = name.toLowerCase().split(/[^a-z0-9çğıöşü]+/)
  return words.some((w) => parts.includes(w) || (w.length > 4 && name.toLowerCase().includes(w)))
}

export function deviceKind(input: { name: string; os?: string; coordinator?: boolean }): DeviceKind {
  if (input.coordinator) return "coordinator"
  const os = (input.os ?? "").toLowerCase()
  if (os === "android" || os === "ios") return "phone"
  if (nameHas(input.name, phoneWords)) return "phone"
  if (nameHas(input.name, serverWords)) return "server"
  if (os === "freebsd" || os === "openbsd" || os === "netbsd") return "server"
  if (nameHas(input.name, laptopWords)) return "laptop"
  if (nameHas(input.name, desktopWords)) return "desktop"
  if (os === "linux") return "server"
  if (os === "windows" || os === "darwin") return "laptop"
  return "unknown"
}

export const deviceKindLabels: Record<DeviceKind, string> = {
  coordinator: msg("Koordinatör"),
  phone: msg("Telefon veya tablet"),
  server: msg("Sunucu"),
  laptop: msg("Dizüstü bilgisayar"),
  desktop: msg("Masaüstü bilgisayar"),
  unknown: msg("Cihaz"),
}
