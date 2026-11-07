import type { Metadata } from "next"

import { E2EQuarantineView } from "@/components/transfer/e2e-quarantine-view"

export const metadata: Metadata = { title: "Karantina · OpenScale" }

export default function E2EQuarantinePage() {
  return <E2EQuarantineView />
}
