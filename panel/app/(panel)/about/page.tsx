import type { Metadata } from "next"

import { AboutView } from "@/components/about/about-view"

export const metadata: Metadata = { title: "Hakkında · OpenScale" }

export default function AboutPage() {
  return <AboutView />
}
