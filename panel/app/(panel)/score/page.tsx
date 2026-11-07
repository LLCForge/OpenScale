import type { Metadata } from "next"

import { ScoreView } from "@/components/score/score-view"

export const metadata: Metadata = { title: "Güvenlik Puanı · OpenScale" }

export default function ScorePage() {
  return <ScoreView />
}
