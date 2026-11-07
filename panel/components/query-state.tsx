"use client"

import { KeyRound, TriangleAlert } from "lucide-react"

import { ErrorCodeHelp } from "@/components/error-code"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import { ApiError, errorMessage } from "@/lib/api"
import { errorAction } from "@/lib/error-help"
import { useI18n } from "@/lib/i18n/i18n"

interface QueryStateProps {
  error: unknown
  isLoading: boolean
  onRetry: () => void
  children: React.ReactNode
}

/** Renders loading, session-expired and error states around page content. */
export function QueryState({ error, isLoading, onRetry, children }: QueryStateProps) {
  const { t } = useI18n()
  if (error instanceof ApiError && error.status === 401) {
    return (
      <Empty className="border">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <KeyRound />
          </EmptyMedia>
          <EmptyTitle>{t("Oturumun süresi doldu")}</EmptyTitle>
          <EmptyDescription>
            {t("Güvenlik için oturumlar 15 dakika işlem yapılmazsa kapanır. Giriş sayfasına yönlendiriliyorsun.")}
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }
  if (error) {
    return (
      <Alert variant="destructive">
        <TriangleAlert />
        <AlertTitle>{t("Veriler yüklenemedi")}</AlertTitle>
        <AlertDescription className="flex flex-col gap-3">
          <span>{errorMessage(error)}</span>
          {errorAction(error) ? <span>{t(errorAction(error))}</span> : null}
          <ErrorCodeHelp error={error} />
          <Button variant="outline" size="sm" className="w-fit" onClick={onRetry}>
            {t("Tekrar dene")}
          </Button>
        </AlertDescription>
      </Alert>
    )
  }
  if (isLoading) {
    return (
      <div className="flex flex-col gap-4" aria-busy="true" aria-label={t("Yükleniyor")}>
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    )
  }
  return <>{children}</>
}
