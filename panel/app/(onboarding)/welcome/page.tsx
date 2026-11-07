import type { Metadata } from "next"

import { WelcomeView } from "@/components/welcome/welcome-view"

export const metadata: Metadata = { title: "Hoş geldin · OpenScale" }

export default function WelcomePage() {
  return <WelcomeView />
}
