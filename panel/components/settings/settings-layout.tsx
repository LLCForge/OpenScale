"use client"

import { useId, useState } from "react"
import { ChevronDown, PenLine } from "lucide-react"

import { CopyButton } from "@/components/copy-field"
import { Button } from "@/components/ui/button"
import { msg, useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

// Building blocks of the settings pages, after the Tailscale admin console:
// a narrow centered column, sections with a title and one line of text,
// and settings as rows (title and gray description on the left, a single
// button or switch on the right) separated only by thin lines.
//
// Older settings cards (components/ui/card) placed inside a section are
// drawn flat, as rows: no frame, no background, title like a row title.

/** Narrow centered column for a settings page. */
export function SettingsColumn({ className, children }: { className?: string; children: React.ReactNode }) {
  return <div className={cn("mx-auto flex w-full max-w-3xl flex-col gap-10", className)}>{children}</div>
}

/**
 * Flattens cards placed directly in a settings list. Important flags
 * outrank the card's own spacing classes, whatever their order in the CSS.
 */
const flatCards = [
  "[&>[data-slot=card]]:rounded-none! [&>[data-slot=card]]:bg-transparent! [&>[data-slot=card]]:ring-0! [&>[data-slot=card]]:shadow-none!",
  "[&>[data-slot=card]]:overflow-visible! [&>[data-slot=card]]:border-0! [&>[data-slot=card]]:py-5! [&>[data-slot=card]]:gap-4!",
  "[&>[data-slot=card]]:[--card-spacing:0px]",
  "[&_[data-slot=card-title]>svg]:hidden",
  "[&_[data-slot=card-description]]:text-sm [&_[data-slot=card-description]]:leading-relaxed",
  "[&_[data-slot=card-footer]]:border-0! [&_[data-slot=card-footer]]:bg-transparent! [&_[data-slot=card-footer]]:p-0!",
  // Cards whose header and content sit inside a form keep the form's gap.
  "[&>[data-slot=card]>form]:gap-4!",
].join(" ")

/** Card titles drawn like setting row titles. */
const rowTitles = "[&_[data-slot=card-title]]:text-sm! [&_[data-slot=card-title]]:font-medium!"
/** Card titles drawn like section titles, for a card standing alone on a page. */
const sectionTitles = "[&_[data-slot=card-title]]:text-base! [&_[data-slot=card-title]]:font-semibold!"

interface SettingsSectionProps {
  id?: string
  title: string
  description?: React.ReactNode
  /** "danger" draws the title in the destructive color (Tehlikeli bölge). */
  tone?: "default" | "danger"
  /** A control for the whole section, at the right of its title ("Ad sunucusu ekle"). */
  action?: React.ReactNode
  /** Changes in this section are signed into the network document with the root key. */
  signed?: boolean
  className?: string
  children: React.ReactNode
}

/**
 * Section of settings rows. A section whose rows all render nothing (for
 * example app-only settings in the command line panel) hides itself.
 */
export function SettingsSection({ id, title, description, tone = "default", action, signed, className, children }: SettingsSectionProps) {
  const headingId = id ? `${id}-baslik` : undefined
  return (
    <section
      id={id}
      aria-labelledby={headingId}
      className={cn("flex scroll-mt-24 flex-col gap-2 [&:not(:has([data-slot=card],[data-slot=setting-row],[data-slot=setting-empty]))]:hidden", className)}
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div className="flex min-w-0 flex-col gap-1">
          <div className="flex flex-wrap items-center gap-2">
            <h2 id={headingId} className={cn("text-base font-semibold", tone === "danger" && "text-destructive")}>
              {title}
            </h2>
            {signed ? <SignatureBadge /> : null}
          </div>
          {description ? <p className="text-sm text-muted-foreground text-pretty">{description}</p> : null}
        </div>
        {action ? <div className="flex shrink-0 flex-wrap gap-2">{action}</div> : null}
      </div>
      <div className={cn("flex flex-col divide-y border-y", tone === "danger" && "border-destructive/30 divide-destructive/20", flatCards, rowTitles)}>
        {children}
      </div>
    </section>
  )
}

interface SettingRowProps {
  title: React.ReactNode
  description?: React.ReactNode
  /** Small badges after the title ("Deneysel", "Varsayılan kapalı"). */
  badge?: React.ReactNode
  /** The single control on the right: a button, a link or a switch. */
  action?: React.ReactNode
  /** id of the control the title labels (for switches). */
  htmlFor?: string
  /** Extra content below the row, such as a list or a value box. */
  children?: React.ReactNode
  className?: string
}

/** One setting: title and description on the left, its control on the right. */
export function SettingRow({ title, description, badge, action, htmlFor, children, className }: SettingRowProps) {
  const Title = htmlFor ? "label" : "span"
  return (
    <div data-slot="setting-row" className={cn("flex flex-col gap-3 py-5", className)}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between sm:gap-8">
        <div className="flex min-w-0 flex-col gap-1">
          <div className="flex flex-wrap items-center gap-2">
            <Title htmlFor={htmlFor} className="text-sm font-medium">
              {title}
            </Title>
            {badge}
          </div>
          {description ? <div className="text-sm leading-relaxed text-muted-foreground text-pretty">{description}</div> : null}
        </div>
        {action ? <div className="flex shrink-0 flex-wrap items-center gap-2">{action}</div> : null}
      </div>
      {children}
    </div>
  )
}

/** Small gray badge next to a setting title. */
export function SettingBadge({ children, tone = "muted" }: { children: React.ReactNode; tone?: "muted" | "warning" | "danger" | "success" }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 items-center rounded-md px-1.5 text-xs font-medium",
        tone === "muted" && "bg-secondary text-muted-foreground",
        tone === "warning" && "bg-warning/15 text-warning-foreground dark:text-warning",
        tone === "danger" && "bg-destructive/10 text-destructive",
        tone === "success" && "bg-success/15 text-success"
      )}
    >
      {children}
    </span>
  )
}

/**
 * Marks a section whose changes are signed into the network document: the
 * owner sees the diff first and types the root key passphrase.
 */
export function SignatureBadge() {
  const { t } = useI18n()
  return (
    <span
      title={t("Bu bölümdeki değişiklikler önce farkı gösterir, sonra kök anahtar parolasıyla imzalanır.")}
      className="inline-flex h-5 items-center gap-1 rounded-md bg-secondary px-1.5 text-xs font-medium text-muted-foreground [&>svg]:size-3"
    >
      <PenLine aria-hidden="true" />
      {t("İmza gerekir")}
    </span>
  )
}

/** Gray centered text for a section with nothing to show; framed unless it sits in a settings list. */
export function EmptyNote({ children, framed = true }: { children: React.ReactNode; framed?: boolean }) {
  return (
    <p
      data-slot="setting-empty"
      className={cn("px-4 py-8 text-center text-sm text-muted-foreground text-pretty", framed && "rounded-lg border")}
    >
      {children}
    </p>
  )
}

interface SettingDisclosureProps extends Omit<SettingRowProps, "action" | "htmlFor"> {
  openLabel?: string
  closeLabel?: string
  defaultOpen?: boolean
}

/** A setting row whose details (long lists, commands, forms) open on demand. */
export function SettingDisclosure({
  openLabel = msg("Göster"),
  closeLabel = msg("Gizle"),
  defaultOpen = false,
  children,
  ...row
}: SettingDisclosureProps) {
  const { t } = useI18n()
  const [open, setOpen] = useState(defaultOpen)
  const id = useId()
  return (
    <SettingRow
      {...row}
      action={
        <Button variant="outline" aria-expanded={open} aria-controls={id} onClick={() => setOpen((o) => !o)}>
          {open ? t(closeLabel) : t(openLabel)}
          <ChevronDown data-icon="inline-end" className={cn("transition-transform", open && "rotate-180")} />
        </Button>
      }
    >
      <div id={id} hidden={!open} className="pt-1">
        {children}
      </div>
    </SettingRow>
  )
}

/** A value in a small framed monospace box with a copy button, for the right side of a row. */
export function ValueBox({ value, label = msg("Kopyala"), children }: { value: string; label?: string; children?: React.ReactNode }) {
  const { t } = useI18n()
  return (
    <span className="flex max-w-full min-w-0 items-center gap-1 rounded-md border bg-muted/40 py-0.5 pr-0.5 pl-3">
      <span className="min-w-0 truncate font-mono text-sm" title={value}>
        {children ?? value}
      </span>
      <CopyButton value={value} label={t(label)} />
    </span>
  )
}

/** Draws the older cards inside it flat, like the rows of a settings section. */
export function FlatCards({ className, children, titles = "row" }: { className?: string; children: React.ReactNode; titles?: "row" | "section" }) {
  return <div className={cn("flex flex-col divide-y", flatCards, titles === "section" ? sectionTitles : rowTitles, className)}>{children}</div>
}
