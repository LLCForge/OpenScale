import type { Metadata } from "next"

import { SetupWizard } from "@/components/setup/setup-wizard"

export const metadata: Metadata = { title: "Kurulum · OpenScale" }

export default function SetupPage() {
  return <SetupWizard />
}
