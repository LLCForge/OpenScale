"use client"

import { useRef } from "react"

import { useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

interface SegmentedRadioProps<T extends string> {
  label: string
  value: T
  options: readonly { value: T; label: string }[]
  onChange: (value: T) => void
  className?: string
}

/**
 * A row of mutually exclusive choices that behaves like a real radio
 * group: one tab stop (the checked option), arrow keys move and select,
 * Home and End jump to the ends (WAI-ARIA radio group pattern).
 */
export function SegmentedRadio<T extends string>({ label, value, options, onChange, className }: SegmentedRadioProps<T>) {
  const { t } = useI18n()
  const refs = useRef<(HTMLButtonElement | null)[]>([])
  const current = Math.max(
    0,
    options.findIndex((o) => o.value === value)
  )

  function move(to: number) {
    const n = options.length
    if (n === 0) return
    const i = ((to % n) + n) % n
    onChange(options[i].value)
    const el = refs.current[i]
    el?.focus()
    el?.scrollIntoView({ block: "nearest", inline: "nearest" })
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLButtonElement>) {
    switch (e.key) {
      case "ArrowRight":
      case "ArrowDown":
        e.preventDefault()
        move(current + 1)
        break
      case "ArrowLeft":
      case "ArrowUp":
        e.preventDefault()
        move(current - 1)
        break
      case "Home":
        e.preventDefault()
        move(0)
        break
      case "End":
        e.preventDefault()
        move(options.length - 1)
        break
    }
  }

  return (
    <div role="radiogroup" aria-label={t(label)} className={cn("flex overflow-x-auto rounded-lg border p-0.5", className)}>
      {options.map((o, i) => {
        const checked = i === current
        return (
          <button
            key={o.value}
            ref={(el) => {
              refs.current[i] = el
            }}
            type="button"
            role="radio"
            aria-checked={checked}
            tabIndex={checked ? 0 : -1}
            onClick={() => onChange(o.value)}
            onKeyDown={onKeyDown}
            className={cn(
              "rounded-md px-3 py-1 text-sm whitespace-nowrap transition-colors focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
              checked ? "bg-secondary font-medium text-foreground" : "text-muted-foreground hover:text-foreground"
            )}
          >
            {t(o.label)}
          </button>
        )
      })}
    </div>
  )
}
