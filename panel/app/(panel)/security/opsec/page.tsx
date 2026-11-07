import type { Metadata } from "next"

import { OpsecView } from "@/components/diag/opsec-view"

export const metadata: Metadata = { title: "Ağ Gizliliği · OpenScale" }

export default function OpsecPage() {
  return <OpsecView />
}
