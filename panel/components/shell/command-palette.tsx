"use client"

// Command palette (Ctrl K / Cmd K) for the whole panel: jump to any page of
// the menu, or run a few shell commands (theme, language, presentation
// mode). It follows the ARIA combobox + listbox pattern: the text field
// keeps focus, arrow keys move the active option, Enter runs it, Escape
// closes the dialog and returns focus to whatever opened it.

import { useCallback, useEffect, useId, useMemo, useRef, useState, useSyncExternalStore } from "react"
import { usePathname, useRouter } from "next/navigation"
import { Dialog as DialogPrimitive } from "@base-ui/react/dialog"
import { useTheme } from "next-themes"
import { CornerDownLeft, Eye, EyeOff, FileText, Languages, Moon, Search, Sun } from "lucide-react"

import { setPresentationMode, usePresentationMode } from "@/components/shell/presentation-mode"
import { Button } from "@/components/ui/button"
import { Kbd } from "@/components/ui/kbd"
import { locales, useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"
import { navPages, type NavGroup } from "@/components/shell/nav"

interface Command {
  id: string
  label: string
  /** Shown after the label in muted text, e.g. the page's area. */
  detail?: string
  section: "page" | "action"
  icon: React.ComponentType<{ className?: string }>
  run: () => void
}

/** Lower case, Turkish dotted/dotless i folded, accents dropped: "Ağ" matches "ag". */
function fold(text: string): string {
  return text
    .toLocaleLowerCase("tr")
    .replace(/ı/g, "i")
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
}

function matches(command: Command, query: string): boolean {
  if (!query) return true
  const haystack = fold(`${command.label} ${command.detail ?? ""}`)
  return fold(query)
    .split(/\s+/)
    .filter(Boolean)
    .every((word) => haystack.includes(word))
}

const isMac = () => /Mac|iPhone|iPad/.test(navigator.platform)
const noSubscribe = () => () => {}

export function CommandPalette({ groups }: { groups: NavGroup[] }) {
  const { t, locale, setLocale } = useI18n()
  const router = useRouter()
  const pathname = usePathname()
  const { resolvedTheme, setTheme } = useTheme()
  const presenting = usePresentationMode()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState("")
  const [active, setActive] = useState(0)
  const listRef = useRef<HTMLUListElement>(null)
  const listId = useId()
  // The static export renders "Ctrl K"; Apple keyboards get Cmd after hydration.
  const mac = useSyncExternalStore(noSubscribe, isMac, () => false)
  const shortcut = mac ? "⌘ K" : "Ctrl K"

  // Ctrl K / Cmd K anywhere in the panel. Registered in the capture phase
  // so the palette owns the shortcut on every page, including pages that
  // used to bind it to their own search field.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && (e.key === "k" || e.key === "K")) {
        e.preventDefault()
        e.stopPropagation()
        setOpen((o) => !o)
      }
    }
    window.addEventListener("keydown", onKey, { capture: true })
    return () => window.removeEventListener("keydown", onKey, { capture: true })
  }, [])

  const commands = useMemo<Command[]>(() => {
    const pages: Command[] = navPages(groups).map((page) => ({
      id: `page:${page.href}`,
      label: t(page.label),
      detail: page.area && page.area !== page.label ? t(page.area) : undefined,
      section: "page",
      icon: FileText,
      run: () => router.push(page.href),
    }))
    const dark = resolvedTheme === "dark"
    const actions: Command[] = [
      {
        id: "theme",
        label: dark ? t("Açık temaya geç") : t("Koyu temaya geç"),
        section: "action",
        icon: dark ? Sun : Moon,
        run: () => setTheme(dark ? "light" : "dark"),
      },
      {
        id: "presentation",
        label: presenting ? t("Sunum kipini kapat") : t("Sunum kipini aç"),
        detail: t("Adresleri ve anahtarları bulanıklaştırır"),
        section: "action",
        icon: presenting ? Eye : EyeOff,
        run: () => setPresentationMode(!presenting),
      },
      ...locales
        .filter((l) => l.id !== locale)
        .map<Command>((l) => ({
          id: `locale:${l.id}`,
          label: l.label,
          detail: t("Arayüz dili"),
          section: "action",
          icon: Languages,
          run: () => setLocale(l.id),
        })),
    ]
    return [...pages, ...actions]
  }, [groups, t, router, resolvedTheme, setTheme, presenting, locale, setLocale])

  const visible = useMemo(() => commands.filter((c) => matches(c, query)), [commands, query])
  const activeIndex = Math.min(active, Math.max(visible.length - 1, 0))
  const optionId = (i: number) => `${listId}-opt-${i}`

  const onOpenChange = useCallback((next: boolean) => {
    setOpen(next)
    if (next) {
      setQuery("")
      setActive(0)
    }
  }, [])

  // Keep the active option in view while moving with the arrow keys.
  useEffect(() => {
    if (!open) return
    const el = listRef.current?.querySelector<HTMLElement>(`[data-index="${activeIndex}"]`)
    el?.scrollIntoView({ block: "nearest" })
  }, [activeIndex, open])

  function runCommand(command: Command | undefined) {
    if (!command) return
    setOpen(false)
    command.run()
  }

  function onInputKey(e: React.KeyboardEvent<HTMLInputElement>) {
    const count = visible.length
    if (count === 0) return
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault()
        setActive((activeIndex + 1) % count)
        break
      case "ArrowUp":
        e.preventDefault()
        setActive((activeIndex - 1 + count) % count)
        break
      case "Home":
        e.preventDefault()
        setActive(0)
        break
      case "End":
        e.preventDefault()
        setActive(count - 1)
        break
      case "Enter":
        e.preventDefault()
        runCommand(visible[activeIndex])
        break
    }
  }

  const sections: { id: Command["section"]; label: string }[] = [
    { id: "page", label: t("Sayfalar") },
    { id: "action", label: t("Komutlar") },
  ]

  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Trigger
        render={
          <Button
            variant="outline"
            className="hidden h-8 w-52 justify-start gap-2 bg-background px-2.5 font-normal text-muted-foreground lg:inline-flex"
          />
        }
      >
        <Search />
        <span className="min-w-0 flex-1 truncate text-left">{t("Sayfa veya komut ara")}</span>
        <Kbd data-presentation-safe className="shrink-0">{shortcut}</Kbd>
      </DialogPrimitive.Trigger>
      <DialogPrimitive.Trigger
        render={
          <Button variant="ghost" size="icon" className="pointer-coarse:size-11 lg:hidden" aria-label={t("Sayfa veya komut ara")} />
        }
      >
        <Search />
      </DialogPrimitive.Trigger>

      <DialogPrimitive.Portal>
        <DialogPrimitive.Backdrop className="fixed inset-0 z-50 bg-black/20 duration-100 data-open:animate-in data-open:fade-in-0 data-closed:animate-out data-closed:fade-out-0" />
        <DialogPrimitive.Popup
          lang={locale}
          className="fixed top-4 left-1/2 z-50 flex max-h-[min(32rem,calc(100svh-2rem))] w-[calc(100%-2rem)] max-w-lg -translate-x-1/2 flex-col overflow-hidden rounded-xl bg-popover text-sm text-popover-foreground shadow-lg ring-1 ring-foreground/10 outline-none duration-100 data-open:animate-in data-open:fade-in-0 data-open:zoom-in-95 data-closed:animate-out data-closed:fade-out-0 data-closed:zoom-out-95 sm:top-[12vh]"
        >
          <DialogPrimitive.Title className="sr-only">{t("Komut paleti")}</DialogPrimitive.Title>
          <DialogPrimitive.Description className="sr-only">
            {t("Sayfa adı veya komut yaz; ok tuşlarıyla seç, Enter ile aç.")}
          </DialogPrimitive.Description>
          <div className="flex items-center gap-2 border-b px-3">
            <Search className="size-4 shrink-0 text-muted-foreground" aria-hidden />
            <input
              type="text"
              role="combobox"
              aria-expanded="true"
              aria-controls={listId}
              aria-autocomplete="list"
              aria-activedescendant={visible.length > 0 ? optionId(activeIndex) : undefined}
              aria-label={t("Sayfa veya komut ara")}
              placeholder={t("Sayfa veya komut ara")}
              autoComplete="off"
              spellCheck={false}
              value={query}
              onChange={(e) => {
                setQuery(e.target.value)
                setActive(0)
              }}
              onKeyDown={onInputKey}
              className="h-12 min-w-0 flex-1 bg-transparent text-base outline-none placeholder:text-muted-foreground sm:text-sm"
            />
          </div>

          <ul ref={listRef} id={listId} role="listbox" aria-label={t("Sonuçlar")} className="min-h-0 flex-1 overflow-y-auto p-1.5">
            {visible.length === 0 ? (
              <li role="presentation" className="px-3 py-8 text-center text-muted-foreground">
                {t("Eşleşen sayfa veya komut yok.")}
              </li>
            ) : (
              sections.map((section) => {
                const items = visible.filter((c) => c.section === section.id)
                if (items.length === 0) return null
                return (
                  <li key={section.id} role="presentation">
                    <p
                      aria-hidden
                      className="px-2.5 pt-2 pb-1 text-xs font-medium tracking-[0.04em] text-muted-foreground uppercase"
                    >
                      {section.label}
                    </p>
                    <ul role="group" aria-label={section.label}>
                      {items.map((command) => {
                        const index = visible.indexOf(command)
                        const selected = index === activeIndex
                        const current = command.id === `page:${pathname}`
                        const Icon = command.icon
                        return (
                          <li
                            key={command.id}
                            id={optionId(index)}
                            role="option"
                            aria-selected={selected}
                            aria-current={current ? "page" : undefined}
                            data-index={index}
                            onPointerMove={() => {
                              if (!selected) setActive(index)
                            }}
                            onClick={() => runCommand(command)}
                            className={cn(
                              "flex min-h-9 cursor-default items-center gap-3 rounded-lg px-2.5 py-1.5 pointer-coarse:min-h-11",
                              selected && "bg-accent text-accent-foreground"
                            )}
                          >
                            <Icon className="size-4 shrink-0 text-muted-foreground" />
                            <span className="min-w-0 flex-1 truncate">
                              {command.label}
                              {command.detail ? <span className="ml-2 text-muted-foreground">{command.detail}</span> : null}
                            </span>
                            {current ? <span className="shrink-0 text-muted-foreground">{t("Buradasın")}</span> : null}
                            {selected ? <CornerDownLeft className="size-4 shrink-0 text-muted-foreground" aria-hidden /> : null}
                          </li>
                        )
                      })}
                    </ul>
                  </li>
                )
              })
            )}
          </ul>

          <div className="hidden items-center gap-3 border-t px-3 py-2 text-sm text-muted-foreground sm:flex" aria-hidden>
            <span className="flex items-center gap-1">
              <Kbd data-presentation-safe>↑</Kbd>
              <Kbd data-presentation-safe>↓</Kbd>
              {t("seç")}
            </span>
            <span className="flex items-center gap-1">
              <Kbd data-presentation-safe>Enter</Kbd>
              {t("aç")}
            </span>
            <span className="flex items-center gap-1">
              <Kbd data-presentation-safe>Esc</Kbd>
              {t("kapat")}
            </span>
          </div>
        </DialogPrimitive.Popup>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  )
}
