"use client"

import useSWR from "swr"

import { ApiError, fetcher } from "@/lib/api"
import type { AppStatus } from "@/lib/types"
import { useLiveInterval } from "@/lib/use-event-stream"

/**
 * Status of the desktop service. `isApp` is false when the panel runs from
 * the command line (`openscale panel`), which has no app endpoints.
 */
export function useAppStatus(refreshInterval = 5_000) {
  const { data, error, isLoading, mutate } = useSWR<AppStatus>("/api/app/status", fetcher, {
    refreshInterval: useLiveInterval(refreshInterval), // #328: slower while the event stream is open
    shouldRetryOnError: (err: unknown) => !(err instanceof ApiError && err.status === 404),
  })
  const isApp = !(error instanceof ApiError && error.status === 404)
  return { status: isApp ? data : undefined, isApp, error: isApp ? error : undefined, isLoading, mutate }
}
