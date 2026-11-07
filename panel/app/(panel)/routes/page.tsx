import type { Metadata } from "next"

import { RoutesView } from "@/components/routes/routes-view"

export const metadata: Metadata = { title: "Rotalar · OpenScale" }

export default function RoutesPage() {
  return <RoutesView />
}
