"use client"

import { Languages } from "lucide-react"

import { SegmentedRadio } from "@/components/devices/segmented-radio"
import { locales, useI18n, type Locale } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

// Interface language choice (Türkçe / English). Language names are shown
// in their own language so they can be found whatever the current choice.

/** The two-option language switch; applies at once, without a reload. */
export function LanguageSwitch({ className }: { className?: string }) {
  const { t, locale, setLocale } = useI18n()
  return (
    <SegmentedRadio<Locale>
      label={t("Dil")}
      value={locale}
      options={locales.map((l) => ({ value: l.id, label: l.label }))}
      onChange={setLocale}
      className={cn("w-fit", className)}
    />
  )
}

/** Compact switch with an icon, for the sign-in and first-run screens. */
export function LanguageCorner({ className }: { className?: string }) {
  const { t } = useI18n()
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <Languages aria-hidden="true" className="size-4 text-muted-foreground" />
      <span className="sr-only">{t("Dil")}</span>
      <LanguageSwitch />
    </div>
  )
}
