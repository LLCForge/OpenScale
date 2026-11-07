import type { Metadata } from "next"

import { GuestsView } from "@/components/devices/guests-view"

export const metadata: Metadata = { title: "Konuklar · OpenScale" }

export default function GuestsPage() {
  return <GuestsView />
}
