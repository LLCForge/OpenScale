"use client"

import useSWR from "swr"

import { fetcher } from "@/lib/api"

interface SessionInfo {
  csrfToken: string
  readOnly: boolean
  /** The panel is open from another device through the tunnel (ADR-0107). */
  remote?: boolean
}

/**
 * Whether this panel session came over the tunnel from another device.
 * Such a session is always read-only and can only read the network pages
 * (overview, devices, rules, map, score); this computer's own settings and
 * diagnostics are refused by the server. Same SWR key as useReadOnly, so
 * both share one request.
 */
export function useRemoteSession(): boolean {
  const { data } = useSWR<SessionInfo>("/api/session", fetcher, { refreshInterval: 15_000 })
  return data?.remote === true
}
