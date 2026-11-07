import type { Metadata } from "next"

import { CoordinatorsView } from "@/components/network/coordinators-view"

export const metadata: Metadata = { title: "Koordinatörler · OpenScale" }

export default function CoordinatorsPage() {
  return <CoordinatorsView />
}
