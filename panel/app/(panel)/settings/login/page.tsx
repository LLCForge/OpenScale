import type { Metadata } from "next"

import { PanelAuthSettingsView } from "@/components/auth/panel-auth-settings"

export const metadata: Metadata = { title: "Panel Girişi ve Gizlilik · OpenScale" }

export default function PanelLoginSettingsPage() {
  return <PanelAuthSettingsView />
}
