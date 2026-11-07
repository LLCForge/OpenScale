import type { Metadata } from "next"

import { DnsView } from "@/components/network/dns-view"

export const metadata: Metadata = { title: "DNS · OpenScale" }

export default function DnsPage() {
  return <DnsView />
}
