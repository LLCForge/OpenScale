"use client"

// Mobile main menu (DESIGN.md, Navigation): below md the side menu becomes a
// sheet that slides in from the left, opened from the header. The header
// itself names the active area, so the current place is always visible
// without a second horizontal scroller. Built on the Base UI dialog the
// panel already ships, so focus is trapped, Escape closes it and focus
// returns to the menu button.

import { useState } from "react"
import Link from "next/link"
import { Dialog as DialogPrimitive } from "@base-ui/react/dialog"
import { Menu, XIcon } from "lucide-react"

import { BrandWordmark } from "@/components/brand"
import { Button } from "@/components/ui/button"
import { useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"
import type { NavGroup } from "@/components/shell/nav"

interface MobileNavProps {
  groups: NavGroup[]
  current: NavGroup | undefined
  networkName: string
  documentVersion: number | undefined
  panelVersion: string | undefined
}

export function MobileNav({ groups, current, networkName, documentVersion, panelVersion }: MobileNavProps) {
  const { t, locale } = useI18n()
  const [open, setOpen] = useState(false)

  return (
    <DialogPrimitive.Root open={open} onOpenChange={setOpen}>
      <DialogPrimitive.Trigger
        render={
          <Button
            variant="ghost"
            size="icon"
            className="size-11 shrink-0 text-sidebar-foreground md:hidden"
            aria-label={t("Ana menüyü aç")}
          />
        }
      >
        <Menu className="size-5" />
      </DialogPrimitive.Trigger>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Backdrop className="fixed inset-0 z-50 bg-black/30 duration-150 data-open:animate-in data-open:fade-in-0 data-closed:animate-out data-closed:fade-out-0 md:hidden" />
        <DialogPrimitive.Popup
          lang={locale}
          className="fixed inset-y-0 left-0 z-50 flex w-72 max-w-[calc(100vw-3rem)] flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground shadow-lg outline-none duration-200 data-open:animate-in data-open:slide-in-from-left data-closed:animate-out data-closed:slide-out-to-left md:hidden"
        >
          <div className="flex h-16 shrink-0 items-center justify-between gap-3 border-b border-sidebar-border px-4">
            <DialogPrimitive.Title className="min-w-0">
              <BrandWordmark className="h-7" />
              <span className="sr-only">{t("Ana menü")}</span>
            </DialogPrimitive.Title>
            <DialogPrimitive.Close
              render={<Button variant="ghost" size="icon" className="size-11 -mr-2 text-sidebar-foreground" />}
            >
              <XIcon className="size-5" />
              <span className="sr-only">{t("Menüyü kapat")}</span>
            </DialogPrimitive.Close>
          </div>

          {networkName ? (
            <p className="truncate border-b border-sidebar-border px-4 py-3 text-sm font-medium" title={networkName}>
              <span className="sr-only">{t("Ağ adı:")} </span>
              {networkName}
            </p>
          ) : null}

          <nav aria-label={t("Ana menü")} className="min-h-0 flex-1 overflow-y-auto p-3">
            <ul className="flex flex-col gap-1">
              {groups.map((item) => {
                const active = item === current
                const Icon = item.icon
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      aria-current={active ? "page" : undefined}
                      onClick={() => setOpen(false)}
                      className={cn(
                        "flex min-h-11 items-center gap-3 rounded-lg px-3 text-sm transition-colors",
                        active
                          ? "bg-sidebar-accent font-medium text-sidebar-accent-foreground"
                          : "text-sidebar-foreground hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground"
                      )}
                    >
                      <Icon className="size-4 shrink-0" />
                      <span className="truncate">{t(item.label)}</span>
                    </Link>
                  </li>
                )
              })}
            </ul>
          </nav>

          <dl className="flex flex-col gap-1 border-t border-sidebar-border px-4 py-3 text-sm text-muted-foreground">
            <div className="flex justify-between gap-2">
              <dt>{t("Ağ belgesi")}</dt>
              <dd className="font-mono" data-presentation-safe>
                v{documentVersion ?? "-"}
              </dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt>Panel</dt>
              <dd className="font-mono" data-presentation-safe>
                {panelVersion ? `v${panelVersion}` : "-"}
              </dd>
            </div>
          </dl>
        </DialogPrimitive.Popup>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  )
}
