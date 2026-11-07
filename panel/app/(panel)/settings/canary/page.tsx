import type { Metadata } from "next"

import { CanaryView } from "@/components/security/canary-view"

export const metadata: Metadata = { title: "Kanarya Beyanı · OpenScale" }

export default function CanaryPage() {
  return <CanaryView />
}
