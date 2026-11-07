import { Suspense } from "react"
import type { Metadata } from "next"

import { RemoteView } from "@/components/apps/remote-view"
import { Skeleton } from "@/components/ui/skeleton"

export const metadata: Metadata = { title: "Uzak Erişim · OpenScale" }

export default function RemotePage() {
  return (
    <Suspense fallback={<Skeleton className="h-96 w-full rounded-xl" />}>
      <RemoteView />
    </Suspense>
  )
}
