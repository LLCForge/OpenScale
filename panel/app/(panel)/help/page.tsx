import type { Metadata } from "next"

import { HelpView } from "@/components/help/help-view"

export const metadata: Metadata = { title: "Yardım · OpenScale" }

// No Suspense boundary here: nothing on this page suspends, and the
// boundary was emitted as a streamed segment whose inline completion script
// the panel's CSP blocks, so the page body stayed hidden.
export default function HelpPage() {
  return <HelpView />
}
