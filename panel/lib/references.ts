import { z } from "zod"

import { msg, tx } from "@/lib/i18n/i18n"

// Name, tag and reference rules shared by the device, rule, group, invite and
// network forms. They mirror the server limits; the server checks them again.

/** A lowercase DNS label: device, tag and group names. */
export const LABEL_PATTERN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/

/** Turkish source text; translate with t() where it is shown. */
export const LABEL_MESSAGE = msg("Küçük harf, rakam ve tire kullan; tire ile başlayıp bitemez (en fazla 63 karakter)")

/** Control characters (C0 and DEL) are refused in free text. */
export const CONTROL_CHARS = /[\u0000-\u001f\u007f]/

export const MAX_TAGS = 16

export function isLabel(value: string): boolean {
  return value.length >= 1 && value.length <= 63 && LABEL_PATTERN.test(value)
}

export const labelSchema = z
  .string()
  .trim()
  .min(1, msg("Ad gerekli"))
  .max(63, msg("En fazla 63 karakter"))
  .regex(LABEL_PATTERN, LABEL_MESSAGE)

/** Splits "ofis, tag:sunucu  ev" into ["ofis", "sunucu", "ev"]. */
export function parseTagText(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0)
    .map((t) => (t.startsWith("tag:") ? t.slice(4) : t))
}

/** Free-text tag list as typed in a form, validated like the server does. */
export const tagTextSchema = z
  .string()
  .max(2048, msg("Çok uzun"))
  .superRefine((text, ctx) => {
    const tags = parseTagText(text)
    if (tags.length > MAX_TAGS) {
      ctx.addIssue({ code: "custom", message: tx("En fazla {count} etiket verilebilir", { count: MAX_TAGS }) })
      return
    }
    const bad = tags.find((t) => !isLabel(t))
    if (bad !== undefined) {
      ctx.addIssue({ code: "custom", message: tx("\"{tag}\" geçersiz. {rule}", { tag: bad, rule: tx(LABEL_MESSAGE) }) })
      return
    }
    if (new Set(tags).size !== tags.length) {
      ctx.addIssue({ code: "custom", message: msg("Aynı etiket iki kez yazılmış") })
    }
  })

/** True when two tag lists hold the same tags in any order. */
export function sameTags(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false
  const set = new Set(a)
  return b.every((t) => set.has(t))
}

export type ReferenceKind = "all" | "group" | "tag" | "device"

export function referenceKind(ref: string): ReferenceKind {
  if (ref === "*") return "all"
  if (ref.startsWith("group:")) return "group"
  if (ref.startsWith("tag:")) return "tag"
  return "device"
}

/** Human label for a rule, group or exit user reference (current language). */
export function referenceLabel(ref: string): string {
  return ref === "*" ? tx("tüm cihazlar") : ref
}

/** Free text without control characters and with a bounded rune count. */
export function textWithin(max: number) {
  return z
    .string()
    .refine((v) => Array.from(v).length <= max, { error: () => tx("En fazla {count} karakter", { count: max }) })
    .refine((v) => !CONTROL_CHARS.test(v), msg("Kontrol karakteri kullanılamaz"))
}
