"use client"

import { Tabs as TabsPrimitive } from "@base-ui/react/tabs"
import { MoreHorizontal } from "lucide-react"

import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Table } from "@/components/ui/table"
import { cn } from "@/lib/utils"

// Shared list building blocks of the panel pages, after the Tailscale admin
// console: plain tables between two thin lines (no card frame), small gray
// uppercase column titles, a "…" menu at the end of each row, and a line
// tab strip for the parts of one page.

/** Class of a column title: small, gray, uppercase. */
export const headCell = "h-10 text-xs font-medium tracking-wide text-muted-foreground uppercase"

/**
 * A plain table between two thin lines. On phones it reaches the screen
 * edges and scrolls sideways inside itself, never the page.
 */
export function ListTable({ className, label, children }: { className?: string; label?: string; children: React.ReactNode }) {
  return (
    <div
      className={cn(
        "-mx-4 border-y md:mx-0",
        "[&_tr>*:first-child]:pl-4 md:[&_tr>*:first-child]:pl-2 [&_tr>*:last-child]:pr-4 md:[&_tr>*:last-child]:pr-2",
        "[&_td]:py-3 [&_td]:align-top",
        className
      )}
    >
      <Table aria-label={label}>{children}</Table>
    </div>
  )
}

/** The "…" menu at the end of a table row. */
export function RowMenu({ label, children, className }: { label: string; children: React.ReactNode; className?: string }) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger render={<Button variant="ghost" size="icon-sm" aria-label={label} />}>
        <MoreHorizontal />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className={cn("w-56", className)}>
        {children}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/** A list of plain rows between two thin lines (events, alerts, recent changes). */
export function RowList({ className, children, label }: { className?: string; children: React.ReactNode; label?: string }) {
  return (
    <ul aria-label={label} className={cn("flex flex-col divide-y border-y", className)}>
      {children}
    </ul>
  )
}

interface PageTabsProps<T extends string> {
  value: T
  onValueChange: (value: T) => void
  tabs: { value: T; label: string }[]
  label: string
  children: React.ReactNode
}

/** Line tab strip for the parts of one page; looks like the area tabs above it. */
export function PageTabs<T extends string>({ value, onValueChange, tabs, label, children }: PageTabsProps<T>) {
  return (
    <TabsPrimitive.Root value={value} onValueChange={(v) => onValueChange(v as T)} className="flex flex-col gap-8">
      <div className="-mx-4 overflow-x-auto overflow-y-hidden border-b px-4 md:mx-0 md:px-0">
        <TabsPrimitive.List aria-label={label} className="flex gap-1">
          {tabs.map((t) => (
            <TabsPrimitive.Tab
              key={t.value}
              value={t.value}
              className={cn(
                "relative inline-flex h-10 items-center px-3 text-sm whitespace-nowrap text-muted-foreground transition-colors outline-none hover:text-foreground",
                "after:absolute after:inset-x-2 after:bottom-0 after:h-0.5 after:rounded-full after:bg-transparent",
                "focus-visible:rounded-md focus-visible:ring-3 focus-visible:ring-ring/50",
                "data-active:font-medium data-active:text-foreground data-active:after:bg-foreground"
              )}
            >
              {t.label}
            </TabsPrimitive.Tab>
          ))}
        </TabsPrimitive.List>
      </div>
      {children}
    </TabsPrimitive.Root>
  )
}

/** The content of one page tab. */
export function PageTab({ value, className, children }: { value: string; className?: string; children: React.ReactNode }) {
  return (
    <TabsPrimitive.Panel value={value} className={cn("flex flex-col gap-10 outline-none", className)}>
      {children}
    </TabsPrimitive.Panel>
  )
}
