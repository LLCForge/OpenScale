import { Suspense } from "react"
import type { Metadata } from "next"

import { DeviceDetailView } from "@/components/devices/device-detail-view"
import { Skeleton } from "@/components/ui/skeleton"

export const metadata: Metadata = { title: "Cihaz · OpenScale" }

export default function DeviceDetailPage() {
  return (
    <Suspense fallback={<Skeleton className="h-96 w-full rounded-xl" />}>
      <DeviceDetailView />
    </Suspense>
  )
}
