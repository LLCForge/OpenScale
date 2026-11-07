import type { Metadata } from "next"

import { HistoryView } from "@/components/history/history-view"

export const metadata: Metadata = { title: "Etkinlik · OpenScale" }

export default function ActivityPage() {
  return <HistoryView />
}
