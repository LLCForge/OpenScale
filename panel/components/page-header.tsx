import type { LucideIcon } from "lucide-react"

import { T } from "@/lib/i18n/i18n"

interface PageHeaderProps {
  /**
   * Area of the page. Not shown any more: the side menu and the tab strip
   * already say where the page is. Kept so the pages need no change.
   */
  section?: { label: string; icon: LucideIcon }
  title: string
  description: string
  /** Small element next to the title, such as a count badge. */
  badge?: React.ReactNode
  actions?: React.ReactNode
}

/** Page title (level 1) with one calm line of description and the page's main actions. */
export function PageHeader({ title, description, badge, actions }: PageHeaderProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div className="flex max-w-3xl min-w-0 flex-col gap-1">
        <div className="flex flex-wrap items-center gap-2.5">
          <h1 className="text-xl leading-tight font-semibold text-balance">
            <T>{title}</T>
          </h1>
          {badge}
        </div>
        <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
          <T>{description}</T>
        </p>
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap gap-2">{actions}</div> : null}
    </div>
  )
}

/** Small round count badge for a page or section title ("6 cihaz"). */
export function CountBadge({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex h-6 items-center rounded-full bg-secondary px-2.5 text-xs font-medium text-secondary-foreground tabular-nums">
      {children}
    </span>
  )
}
