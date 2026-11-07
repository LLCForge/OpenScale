import type { Metadata } from "next"

import { PostureView } from "@/components/diag/posture-view"

export const metadata: Metadata = { title: "Cihaz Duruşu · OpenScale" }

export default function DevicePosturePage() {
  return <PostureView />
}
