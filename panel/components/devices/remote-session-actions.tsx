"use client"

import { useState } from "react"
import { SquareTerminal } from "lucide-react"

import { useRemoteSession } from "@/components/auth/session"
import { RDeskConnectButton } from "@/components/rdesk/rdesk-connect"
import { SSHTerminalDialog } from "@/components/terminal/ssh-terminal"
import { Button } from "@/components/ui/button"
import { useI18n } from "@/lib/i18n/i18n"

/**
 * One-click session starters on the device page: the remote desktop
 * viewer and, for Linux devices, the browser SSH terminal (ADR-0203).
 * Both work only in the local panel; a remote panel session hides them.
 */
export function RemoteSessionActions({ device, os }: { device: string; os: string }) {
  const { t } = useI18n()
  const remote = useRemoteSession()
  const [terminal, setTerminal] = useState<string | null>(null)
  if (remote) return null
  return (
    <div className="flex flex-wrap items-center gap-2 py-4">
      <RDeskConnectButton device={device} os={os} />
      {os === "linux" ? (
        <Button variant="outline" size="sm" onClick={() => setTerminal(device)}>
          <SquareTerminal data-icon="inline-start" />
          {t("Terminal aç")}
        </Button>
      ) : null}
      <SSHTerminalDialog device={terminal} onClose={() => setTerminal(null)} />
    </div>
  )
}
