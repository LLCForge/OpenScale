"use client"

import { diagStreamKeys } from "@/lib/observe"
import { useStreamRefresh } from "@/lib/use-event-stream"

/**
 * Subscribes to the service's event stream (F-182, #328) while the "Tanı"
 * page is open and refreshes its cards when something happens, instead of
 * waiting for the next poll. The shared stream reconnects with back-off
 * and pauses while the page is hidden (lib/use-event-stream.ts).
 */
export function LiveUpdates() {
  useStreamRefresh(diagStreamKeys)
  return null
}
