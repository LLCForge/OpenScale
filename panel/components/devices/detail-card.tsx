"use client"

import { Fragment, useState } from "react"
import { toast } from "sonner"

import { CopyButton } from "@/components/copy-field"
import { SignatureBadge } from "@/components/settings/settings-layout"
import { useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

/**
 * Fills {name} placeholders of an already translated text with React
 * nodes (a bold number, a link), so a sentence stays one dictionary key.
 */
export function withNodes(text: string, nodes: Record<string, React.ReactNode>): React.ReactNode {
  return text.split(/(\{\w+\})/g).map((part, i) => {
    const m = /^\{(\w+)\}$/.exec(part)
    return <Fragment key={i}>{m && m[1] in nodes ? nodes[m[1]] : part}</Fragment>
  })
}

/** A label/value line inside a framed detail section. */
export function Row({ label, value, copy, mono = true }: { label: string; value: string; copy?: boolean; mono?: boolean }) {
  const { t } = useI18n()
  return (
    <div className="flex flex-col gap-1 py-2.5 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
      <span className="shrink-0 text-sm text-muted-foreground">{label}</span>
      <span className="flex min-w-0 items-center gap-1">
        <span className={mono ? "font-mono text-xs break-all" : "text-sm"}>{value}</span>
        {copy && value !== "-" ? <CopyButton value={value} label={t("{label} kopyala", { label })} /> : null}
      </span>
    </div>
  )
}

interface DetailSectionProps {
  id?: string
  title: string
  /** One calm line under the title. */
  description?: React.ReactNode
  /** Link or button at the right of the title. */
  action?: React.ReactNode
  /** Draws the content in a thin frame with rows separated by lines (default). */
  framed?: boolean
  /** Changes here are signed into the network document ("İmza gerekir"). */
  signed?: boolean
  className?: string
  children: React.ReactNode
}

/**
 * Section of the device detail page: a level 2 title, one line of
 * description and the content. A framed section whose content renders
 * nothing hides itself, so app-only sections vanish in the command line panel.
 */
export function DetailSection({ id, title, description, action, framed = true, signed, className, children }: DetailSectionProps) {
  const headingId = id ? `${id}-baslik` : undefined
  return (
    <section
      id={id}
      aria-labelledby={headingId}
      className={cn("flex scroll-mt-24 flex-col gap-3 has-[[data-detail-frame]:empty]:hidden", className)}
    >
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div className="flex min-w-0 flex-col gap-1">
          <div className="flex flex-wrap items-center gap-2">
            <h2 id={headingId} className="text-base font-semibold">
              {title}
            </h2>
            {signed ? <SignatureBadge /> : null}
          </div>
          {description ? <p className="text-sm text-muted-foreground text-pretty">{description}</p> : null}
        </div>
        {action ? <div className="flex shrink-0 flex-wrap gap-2">{action}</div> : null}
      </div>
      {framed ? (
        <div data-detail-frame="" className="flex flex-col divide-y rounded-lg border px-4">
          {children}
        </div>
      ) : (
        children
      )}
    </section>
  )
}

/** Kept for the cards that still pass an icon; drawn as a framed section. */
export function DetailCard({
  title,
  description,
  action,
  children,
}: {
  icon?: React.ComponentType<{ className?: string }>
  title: string
  description?: string
  action?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <DetailSection title={title} description={description} action={action}>
      {children}
    </DetailSection>
  )
}

/** Small uppercase heading over a group of details ("ADRESLER"). */
export function DetailGroup({ title, children }: { title?: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-3">
      {title ? <h3 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">{title}</h3> : null}
      <dl className="grid grid-cols-1 gap-x-4 gap-y-3 sm:grid-cols-[minmax(0,9.5rem)_minmax(0,1fr)]">{children}</dl>
    </div>
  )
}

/** One detail: gray label, then the value with an optional "Kopyala" link. */
export function DetailItem({ label, children, copy }: { label: string; children: React.ReactNode; copy?: string }) {
  return (
    <>
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="-mt-2 flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-sm sm:mt-0">
        {children}
        {copy ? <CopyLink value={copy} label={label} /> : null}
      </dd>
    </>
  )
}

/** "Kopyala" text button, as in the Tailscale machine page. */
export function CopyLink({ value, label }: { value: string; label: string }) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      aria-label={t("{label} kopyala", { label })}
      className="rounded-sm text-xs font-medium text-muted-foreground underline-offset-3 hover:text-foreground hover:underline focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value)
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        } catch {
          toast.error(t("Panoya kopyalanamadı."))
        }
      }}
    >
      {copied ? t("Kopyalandı") : t("Kopyala")}
    </button>
  )
}

/** Shortens a long key for display ("abcd1234…wxyz"); the full value is copied. */
export function shortKey(value: string, head = 10, tail = 6): string {
  return value.length > head + tail + 1 ? `${value.slice(0, head)}…${value.slice(-tail)}` : value
}
