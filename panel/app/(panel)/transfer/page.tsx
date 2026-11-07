import type { Metadata } from "next"

import { TransferView } from "@/components/transfer/transfer-view"

export const metadata: Metadata = { title: "Belge Aktarımı · OpenScale" }

export default function TransferPage() {
  return <TransferView />
}
