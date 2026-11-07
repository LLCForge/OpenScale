import type { Metadata } from "next"

import { SecurityView } from "@/components/security/security-view"

export const metadata: Metadata = { title: "Ağ Ayarları · OpenScale" }

export default function SettingsPage() {
  return <SecurityView />
}
