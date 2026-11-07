import { PrivacyOverlays, PrivacyStrips } from "@/components/auth/privacy-guard"
import { PanelShell } from "@/components/shell/panel-shell"
import { SupportLocalBanner } from "@/components/support/support-local-banner"

export default function PanelLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <PanelShell>
        <PrivacyStrips />
        {/* #852, ADR-0232: support requests and the "remotely connected" bar */}
        <SupportLocalBanner />
        {children}
      </PanelShell>
      <PrivacyOverlays />
    </>
  )
}
