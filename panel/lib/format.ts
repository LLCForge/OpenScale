import { getLocale, intlLocale, tx, type Locale } from "@/lib/i18n/i18n"

// Dates, sizes and durations in the interface language. Formatters are
// built once per language; call these during render of a component that
// uses useI18n() so a language change re-renders the text.

const cache = new Map<string, Intl.DateTimeFormat | Intl.RelativeTimeFormat | Intl.NumberFormat>()

function cached<F extends Intl.DateTimeFormat | Intl.RelativeTimeFormat | Intl.NumberFormat>(key: string, make: (tag: string) => F): F {
  const locale: Locale = getLocale()
  const id = `${locale}:${key}`
  let f = cache.get(id) as F | undefined
  if (!f) {
    f = make(intlLocale(locale))
    cache.set(id, f)
  }
  return f
}

/** Date and time formatter in the interface language, cached per options. */
export function dateFormat(key: string, options: Intl.DateTimeFormatOptions): Intl.DateTimeFormat {
  return cached(`date:${key}`, (tag) => new Intl.DateTimeFormat(tag, options))
}

/** Number formatter in the interface language, cached per options. */
export function numberFormat(key: string, options: Intl.NumberFormatOptions = {}): Intl.NumberFormat {
  return cached(`num:${key}`, (tag) => new Intl.NumberFormat(tag, options))
}

/** "1.234" / "1,234" style whole or decimal number. */
export function formatNumber(n: number, maximumFractionDigits = 0): string {
  return numberFormat(`n${maximumFractionDigits}`, { maximumFractionDigits }).format(n)
}

export function formatDate(iso: string): string {
  return dateFormat("long", { day: "numeric", month: "long", year: "numeric" }).format(new Date(iso))
}

/** "25 Eki 2026" style date for compact badges and table cells. */
export function formatShortDate(iso: string): string {
  return dateFormat("short", { day: "numeric", month: "short", year: "numeric" }).format(new Date(iso))
}

export function formatDateTime(iso: string): string {
  return dateFormat("datetime", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" }).format(new Date(iso))
}

/** "14:05:09" style clock time. */
export function formatTime(iso: string | number | Date): string {
  return dateFormat("time", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(iso))
}

export function daysLabel(days: number): string {
  if (days <= 0) {
    return tx("süresi doldu")
  }
  return tx("{count} gün kaldı", { count: days })
}

const units = ["B", "KB", "MB", "GB", "TB"]

export function formatBytes(n: number): string {
  let v = n
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

/** "2 dakika önce" style time for recent events. */
export function formatAgo(iso: string, now = Date.now()): string {
  const relative = cached("relative", (tag) => new Intl.RelativeTimeFormat(tag, { numeric: "auto" }))
  const seconds = Math.round((new Date(iso).getTime() - now) / 1000)
  const abs = Math.abs(seconds)
  if (abs < 60) return relative.format(seconds, "second")
  if (abs < 3600) return relative.format(Math.round(seconds / 60), "minute")
  if (abs < 86400) return relative.format(Math.round(seconds / 3600), "hour")
  return relative.format(Math.round(seconds / 86400), "day")
}

/** "3 gün 4 sa" style duration for uptime. */
export function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return tx("{d} gün {h} sa", { d, h })
  if (h > 0) return tx("{h} sa {m} dk", { h, m })
  return tx("{m} dk", { m })
}
