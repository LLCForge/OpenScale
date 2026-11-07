"use client"

import { CircleDashed } from "lucide-react"

import { useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

export interface MissingStep {
  id: string
  title: string
}

interface MissingStepsProps {
  steps: MissingStep[]
  /** The step shown now; it is marked in the list. */
  current: string
  onSelect: (id: string) => void
}

/**
 * The setup steps that are still open (#792). The list is derived from the
 * signed document and the backup records every time, so it never stores
 * anything of its own and holds no secret.
 */
export function MissingSteps({ steps, current, onSelect }: MissingStepsProps) {
  const { t } = useI18n()
  if (steps.length === 0) {
    return null
  }
  return (
    <nav aria-label={t("Eksik adımlar")} className="flex flex-col items-center gap-2">
      <p className="text-sm text-muted-foreground">{t("Eksik adımlar ({count})", { count: steps.length })}</p>
      <ul className="flex flex-wrap justify-center gap-2">
        {steps.map((s) => (
          <li key={s.id}>
            <button
              type="button"
              onClick={() => onSelect(s.id)}
              aria-current={s.id === current ? "step" : undefined}
              className={cn(
                "flex items-center gap-1.5 rounded-full border px-3 py-1 text-sm transition-colors hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
                s.id === current ? "border-primary text-foreground" : "text-muted-foreground"
              )}
            >
              <CircleDashed className="size-4" aria-hidden="true" />
              {s.title}
            </button>
          </li>
        ))}
      </ul>
    </nav>
  )
}
