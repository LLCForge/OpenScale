import type { Metadata } from "next"

import { BlockingView } from "@/components/plugins/blocking-view"

export const metadata: Metadata = { title: "Engelleme ve Eklentiler · OpenScale" }

export default function PluginsPage() {
  return <BlockingView />
}
