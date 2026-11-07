import type { Metadata } from "next"

import { DiagView } from "@/components/diag/diag-view"

export const metadata: Metadata = { title: "Tanı · OpenScale" }

export default function DiagPage() {
  return <DiagView />
}
