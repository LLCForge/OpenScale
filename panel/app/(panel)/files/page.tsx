import type { Metadata } from "next"

import { E2ESendView } from "@/components/transfer/e2e-send-view"

export const metadata: Metadata = { title: "Uçtan Uca Gönder · OpenScale" }

export default function E2EFilesPage() {
  return <E2ESendView />
}
