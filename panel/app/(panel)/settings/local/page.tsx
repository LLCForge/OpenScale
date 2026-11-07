import type { Metadata } from "next"

import { LocalSettingsView } from "@/components/security/security-view"

export const metadata: Metadata = { title: "Bu Bilgisayar · OpenScale" }

export default function LocalSettingsPage() {
  return <LocalSettingsView />
}
