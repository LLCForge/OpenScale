import type { Metadata } from "next"

import { MonitorView } from "@/components/plugins/monitor-view"

export const metadata: Metadata = { title: "İzleme · OpenScale" }

export default function MonitorPage() {
  return <MonitorView />
}
