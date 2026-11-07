import type { Metadata } from "next"

import { NetworkView } from "@/components/network/network-view"

export const metadata: Metadata = { title: "Ağ · OpenScale" }

export default function NetworkPage() {
  return <NetworkView />
}
