"use client"

// Dictionary-based interface language (#224). Turkish is the source: every
// text is written in Turkish and looked up in the English dictionary by
// that same text, so a missing translation falls back to Turkish instead
// of showing a key (tools/i18ncheck fails the build when one is missing).
//
// The choice is a per-browser convenience kept in localStorage and in a
// cookie (no server state); without a stored choice the browser language
// decides: English when it prefers English, Turkish otherwise.
//
// Texts:
//   t(text)       in components, from useI18n(); the component re-renders
//                 when the language changes.
//   T element     the same for plain text children.
//   tx(text)      outside React (lib helpers, toasts, formatters); uses the
//                 current language. Call it during render of a component
//                 that itself uses useI18n(), or in an event handler.
//   msg(text)     marks a Turkish text that is translated later with t()
//                 (label tables, options); it returns the text unchanged.
//
// Context: a key may start with "context|" (lower-case ASCII) when one
// Turkish text needs two English texts: t("recording|Kaydediliyor").
//
// English plurals: when the key has {count}, the English text may give the
// singular and plural forms separated by "|": "{count} device|{count} devices".

import { useEffect, useSyncExternalStore } from "react"

import { en, serverPatterns } from "@/lib/i18n/dictionary"

export type Locale = "tr" | "en"

export const locales: { id: Locale; label: string }[] = [
  { id: "tr", label: "Türkçe" },
  { id: "en", label: "English" },
]

const storageKey = "openscale.locale"
const cookieName = "openscale_locale"
const listeners = new Set<() => void>()
// Used when the browser refuses storage (private mode, blocked site data).
let memory: Locale | null = null
// The static export is rendered in Turkish; until the first client effect
// runs, every reader says Turkish so hydration markup matches.
let hydrated = false

function isLocale(v: unknown): v is Locale {
  return v === "tr" || v === "en"
}

function storedLocale(): Locale | null {
  try {
    const v = window.localStorage.getItem(storageKey)
    if (isLocale(v)) return v
  } catch {
    // Storage blocked; try the cookie.
  }
  try {
    const m = /(?:^|;\s*)openscale_locale=(tr|en)(?:;|$)/.exec(document.cookie)
    if (m && isLocale(m[1])) return m[1]
  } catch {
    // Cookies blocked.
  }
  return null
}

/** English when the browser's first language is English, Turkish otherwise. */
export function browserLocale(): Locale {
  try {
    const langs = navigator.languages && navigator.languages.length > 0 ? navigator.languages : [navigator.language]
    const first = (langs[0] ?? "").slice(0, 2)
    return first === "en" || first === "EN" ? "en" : "tr"
  } catch {
    return "tr"
  }
}

function readLocale(): Locale {
  if (!hydrated) return "tr"
  if (memory) return memory
  memory = storedLocale() ?? browserLocale()
  return memory
}

/** The language in use right now (Turkish before hydration). */
export function getLocale(): Locale {
  if (typeof window === "undefined") return "tr"
  return readLocale()
}

function notify(): void {
  for (const l of listeners) l()
}

function subscribe(onChange: () => void): () => void {
  listeners.add(onChange)
  const onStorage = (e: StorageEvent) => {
    if (e.key === storageKey) {
      memory = isLocale(e.newValue) ? e.newValue : null
      onChange()
    }
  }
  window.addEventListener("storage", onStorage)
  return () => {
    listeners.delete(onChange)
    window.removeEventListener("storage", onStorage)
  }
}

export function setLocale(locale: Locale): void {
  memory = locale
  try {
    window.localStorage.setItem(storageKey, locale)
  } catch {
    // Storage blocked: the cookie below or memory keeps the choice.
  }
  try {
    // The panel is served on loopback over plain HTTP, so no Secure flag.
    document.cookie = `${cookieName}=${locale}; Path=/; Max-Age=31536000; SameSite=Strict`
  } catch {
    // Cookies blocked: the choice lasts until the page is closed.
  }
  notify()
}

export type Vars = Record<string, string | number>

/** Replaces {name} placeholders. */
function interpolate(text: string, vars?: Vars): string {
  if (!vars) return text
  return text.replace(/\{(\w+)\}/g, (whole, name: string) => (name in vars ? String(vars[name]) : whole))
}

/** Picks the singular or plural form of "one|other" by vars.count. */
function plural(text: string, vars?: Vars): string {
  if (!vars || !("count" in vars) || !text.includes("|")) return text
  const parts = text.split("|")
  if (parts.length !== 2) return text
  return Number(vars.count) === 1 ? parts[0] : parts[1]
}

// A key may start with a lower-case ASCII context, "recording|Kaydediliyor",
// when one Turkish text needs two English texts (Kaydediliyor: "Saving" or
// "Recording"). The context is never shown; Turkish shows the text after it.
const contextPrefix = /^[a-z][a-z-]*\|/

export function translate(locale: Locale, text: string, vars?: Vars): string {
  const ctx = contextPrefix.exec(text)
  const source = ctx ? text.slice(ctx[0].length) : text
  const found = locale === "en" ? (en[text] ?? (ctx ? en[source] : undefined)) : undefined
  if (found === undefined) return interpolate(source, vars)
  return interpolate(plural(found, vars), vars)
}

/** Translates with the current language; for code outside components. */
export function tx(text: string, vars?: Vars): string {
  return translate(getLocale(), text, vars)
}

/** Marks a Turkish text for the dictionary; translate it with t() where it is shown. */
export function msg<S extends string>(text: S): S {
  return text
}

/**
 * Translates a text that came from the server (an error message, a
 * catalog entry). Exact texts are looked up first, then the dictionary's
 * server patterns such as "Cihaz {name} bulunamadı."; anything else stays
 * as the server wrote it.
 */
export function translateServer(locale: Locale, text: string): string {
  if (locale !== "en" || text === "") return text
  const exact = en[text]
  if (exact !== undefined) return exact
  for (const p of serverPatterns) {
    const m = p.re.exec(text)
    if (!m) continue
    const vars: Vars = {}
    p.names.forEach((name, i) => {
      const value = m[i + 1] ?? ""
      // A captured part may itself be a known server text ("...: <reason>").
      vars[name] = en[value] ?? value
    })
    return interpolate(p.en, vars)
  }
  return text
}

/** Locale tag for Intl formatters. */
export function intlLocale(locale: Locale = getLocale()): string {
  return locale === "en" ? "en-GB" : "tr-TR"
}

export function useI18n() {
  const locale = useSyncExternalStore<Locale>(subscribe, readLocale, () => "tr")
  return {
    locale,
    setLocale,
    t: (text: string, vars?: Vars) => translate(locale, text, vars),
    /** Translates a server-provided text (see translateServer). */
    ts: (text: string) => translateServer(locale, text),
  }
}

/** Translates a Turkish text; usable from server components' children. */
export function T({ children, vars }: { children: string; vars?: Vars }) {
  const { t } = useI18n()
  return <>{t(children, vars)}</>
}

// Page titles come from static metadata ("Cihazlar · OpenScale"). The
// original Turkish title is remembered so it can be translated back and
// forth whenever Next.js or the language changes it.
const titleSource = new Map<string, string>()

function syncTitle(locale: Locale): void {
  const current = document.title
  const source = titleSource.get(current) ?? current
  const next = translate(locale, source)
  titleSource.set(next, source)
  if (next !== current) document.title = next
}

/**
 * Applies the chosen language to the document: <html lang> (so screen
 * readers use the right pronunciation) and the page title.
 */
export function LocaleSync() {
  const { locale } = useI18n()
  useEffect(() => {
    if (!hydrated) {
      hydrated = true
      notify()
    }
  }, [])
  useEffect(() => {
    document.documentElement.lang = locale
    syncTitle(locale)
    const head = document.head
    const observer = new MutationObserver(() => syncTitle(locale))
    observer.observe(head, { subtree: true, childList: true, characterData: true })
    return () => observer.disconnect()
  }, [locale])
  return null
}
