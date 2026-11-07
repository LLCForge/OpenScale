import type { Metadata } from "next"

import { EmergencyView } from "@/components/security/emergency-view"

export const metadata: Metadata = { title: "Acil Durum · OpenScale" }

export default function EmergencyPage() {
  return <EmergencyView />
}
