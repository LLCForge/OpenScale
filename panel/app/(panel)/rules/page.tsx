import type { Metadata } from "next"

import { RulesView } from "@/components/rules/rules-view"

export const metadata: Metadata = { title: "Erişim Kontrolü · OpenScale" }

export default function RulesPage() {
  return <RulesView />
}
