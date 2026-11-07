import { logo, markDetail, markSmall } from "@/components/brand-paths"
import { cn } from "@/lib/utils"

/**
 * OpenScale mark: the mesh ring from the logo pack. Small sizes use the
 * simplified favicon geometry so the lines stay readable. Decorative; pair
 * it with text.
 */
export function BrandMark({ className, detailed = false }: { className?: string; detailed?: boolean }) {
  const m = detailed ? markDetail : markSmall
  return (
    <svg viewBox={m.viewBox} aria-hidden="true" className={cn("size-7 shrink-0 text-foreground", className)}>
      <path d={m.d} fill="currentColor" />
    </svg>
  )
}

/** Horizontal logo exactly as in the logo pack. */
export function BrandWordmark({ className, size = "md" }: { className?: string; size?: "md" | "lg" }) {
  return (
    <svg
      viewBox={logo.viewBox}
      role="img"
      aria-label="OpenScale"
      className={cn("w-auto shrink-0 text-foreground", size === "lg" ? "h-14 sm:h-16" : "h-8", className)}
    >
      <path d={logo.mark} fill="currentColor" />
      <path d={logo.divider} fill="currentColor" />
      <path d={logo.wordmark} fill="currentColor" />
    </svg>
  )
}
