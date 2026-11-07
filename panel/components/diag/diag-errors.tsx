"use client"

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react"
import { useSWRConfig } from "swr"
import { KeyRound, TriangleAlert } from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { ApiError, errorMessage } from "@/lib/api"
import { errorAction } from "@/lib/error-help"
import { useI18n } from "@/lib/i18n/i18n"

// One error state for the whole diagnostics page. The sections read from
// the same service; when it is down they all fail for the same reason, and
// five identical red boxes said one thing five times. Sections report their
// error here and show one quiet line; the page shows a single alert with
// the reason, the sections it affects and one retry for all of them.

interface DiagErrorsValue {
  report: (section: string, error: unknown) => void
}

const DiagErrorsContext = createContext<DiagErrorsValue | null>(null)

/** Wraps the diagnostics page; renders the single page-level alert above its children. */
export function DiagErrorsProvider({ children }: { children: React.ReactNode }) {
  const [errors, setErrors] = useState<ReadonlyMap<string, unknown>>(new Map())
  const report = useCallback((section: string, error: unknown) => {
    setErrors((prev) => {
      const had = prev.has(section)
      if (!error && !had) return prev
      if (error && had && prev.get(section) === error) return prev
      const next = new Map(prev)
      if (error) next.set(section, error)
      else next.delete(section)
      return next
    })
  }, [])
  const value = useMemo(() => ({ report }), [report])
  return (
    <DiagErrorsContext.Provider value={value}>
      <DiagPageError errors={errors} />
      {children}
    </DiagErrorsContext.Provider>
  )
}

function DiagPageError({ errors }: { errors: ReadonlyMap<string, unknown> }) {
  const { mutate } = useSWRConfig()
  const { t } = useI18n()
  if (errors.size === 0) return null
  const sections = [...errors.keys()]
  const first = errors.values().next().value
  const retry = () => mutate((key) => typeof key === "string" && key.startsWith("/api/app/"))

  if (first instanceof ApiError && first.status === 401) {
    return (
      <Alert>
        <KeyRound />
        <AlertTitle>{t("Oturumun süresi doldu")}</AlertTitle>
        <AlertDescription>{t("Güvenlik için oturumlar 15 dakika işlem yapılmazsa kapanır. Giriş sayfasına yönlendiriliyorsun.")}</AlertDescription>
      </Alert>
    )
  }
  const action = errorAction(first)
  return (
    <Alert variant="destructive" role="alert">
      <TriangleAlert />
      <AlertTitle>{sections.length === 1 ? t("{section} yüklenemedi", { section: sections[0] }) : t("Tanı verilerinin bir kısmı yüklenemedi")}</AlertTitle>
      <AlertDescription className="flex flex-col gap-3">
        <span className="text-pretty">
          {errorMessage(first)}
          {action ? ` ${t(action)}` : ""}
        </span>
        {sections.length > 1 ? <span className="text-pretty">{t("Etkilenen bölümler: {sections}.", { sections: sections.join(", ") })}</span> : null}
        <Button variant="outline" size="sm" className="w-fit" onClick={() => void retry()}>
          {t("Tekrar dene")}
        </Button>
      </AlertDescription>
    </Alert>
  )
}

interface DiagSectionStateProps {
  /** Section name as the page alert lists it ("Olaylar"). */
  section: string
  error: unknown
  isLoading: boolean
  children: React.ReactNode
}

/**
 * Loading and error state of one diagnostics section. The error itself is
 * shown once, at the top of the page.
 */
export function DiagSectionState({ section, error, isLoading, children }: DiagSectionStateProps) {
  const { t } = useI18n()
  const ctx = useContext(DiagErrorsContext)
  const report = ctx?.report
  useEffect(() => {
    if (!report) return
    report(section, error ?? null)
    return () => report(section, null)
  }, [report, section, error])

  if (error) {
    return <p className="py-3 text-sm text-muted-foreground">{t("Bu bölüm yüklenemedi; nedeni sayfanın üstünde.")}</p>
  }
  if (isLoading) {
    return (
      <div aria-busy="true" aria-label={t("{section} yükleniyor", { section })}>
        <Skeleton className="h-24 w-full" />
      </div>
    )
  }
  return <>{children}</>
}
