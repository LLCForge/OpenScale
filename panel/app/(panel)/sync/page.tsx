import type { Metadata } from "next"

import { SyncView } from "@/components/sync/sync-view"

export const metadata: Metadata = { title: "Eşitleme ve Yedek · OpenScale" }

export default function SyncPage() {
  return <SyncView />
}
