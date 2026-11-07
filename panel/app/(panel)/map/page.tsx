import type { Metadata } from "next"

import { MapView } from "@/components/netmap/map-view"

export const metadata: Metadata = { title: "Ağ Haritası · OpenScale" }

export default function MapPage() {
  return <MapView />
}
