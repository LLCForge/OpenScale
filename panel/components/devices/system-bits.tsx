import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { formatBytes } from "@/lib/format"
import { intlLocale, useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

// Region names in the interface language, built once per language.
const regionNames = new Map<string, Intl.DisplayNames>()

function regions(): Intl.DisplayNames {
  const tag = intlLocale()
  let names = regionNames.get(tag)
  if (!names) {
    names = new Intl.DisplayNames([tag], { type: "region" })
    regionNames.set(tag, names)
  }
  return names
}

/** Country name in the interface language; call during render of a component that uses useI18n(). */
export function countryName(code: string): string {
  try {
    return regions().of(code) ?? code
  } catch {
    return code
  }
}

/** Country flag served by the panel itself (public/flags, from flag-icons). */
export function Flag({ country, className }: { country: string; className?: string }) {
  // Re-renders the name when the language changes.
  useI18n()
  if (!/^[A-Z]{2}$/.test(country)) return null
  const name = countryName(country)
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          // eslint-disable-next-line @next/next/no-img-element -- static export, local SVG
          <img
            src={`/flags/${country.toLowerCase()}.svg`}
            alt={name}
            width={16}
            height={12}
            className={cn("h-3 w-4 shrink-0 rounded-[2px] object-cover ring-1 ring-border", className)}
          />
        }
      />
      <TooltipContent>{name}</TooltipContent>
    </Tooltip>
  )
}

/** Small usage bar with "12,3 GB / 64 GB" style text. */
export function UsageBar({ label, used, total }: { label: string; used: number; total: number }) {
  const { t } = useI18n()
  if (total <= 0) return null
  const pct = Math.min(100, Math.max(0, Math.round((used / total) * 100)))
  return (
    <div className="flex min-w-36 flex-col gap-1">
      <div className="flex justify-between gap-2 text-xs">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-mono">
          {formatBytes(used)} / {formatBytes(total)}
        </span>
      </div>
      <div
        className="h-1.5 overflow-hidden rounded-full bg-muted"
        role="meter"
        aria-label={t("{label} kullanımı", { label })}
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div className={cn("h-full rounded-full", pct >= 90 ? "bg-destructive" : pct >= 75 ? "bg-warning" : "bg-foreground/70")} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}
