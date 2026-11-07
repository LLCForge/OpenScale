import type { Metadata } from "next"

import { InboxView } from "@/components/apps/inbox-view"

export const metadata: Metadata = { title: "Gelen Dosyalar · OpenScale" }

export default function InboxPage() {
  return <InboxView />
}
