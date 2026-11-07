import type { Metadata } from "next"

import { AccessRequestsView } from "@/components/devices/access-requests-view"

export const metadata: Metadata = { title: "Erişim İstekleri · OpenScale" }

export default function AccessRequestsPage() {
  return <AccessRequestsView />
}
