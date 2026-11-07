"use client"

import { FolderOpen, SquareTerminal } from "lucide-react"

import { SFTPBrowser } from "@/components/terminal/f3-sftp-browser"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useI18n } from "@/lib/i18n/i18n"

// "Terminal" and "Files" tabs of the SSH dialog (#855). Both panels stay
// mounted, so switching tabs keeps the terminal session and the open
// folder.

export function TerminalTabs({ device, terminal }: { device: string; terminal: React.ReactNode }) {
  const { t } = useI18n()
  return (
    <Tabs defaultValue="terminal" className="min-w-0">
      <TabsList>
        <TabsTrigger value="terminal">
          <SquareTerminal data-icon="inline-start" />
          {t("Terminal")}
        </TabsTrigger>
        <TabsTrigger value="files">
          <FolderOpen data-icon="inline-start" />
          {t("Dosyalar")}
        </TabsTrigger>
      </TabsList>
      <TabsContent value="terminal" keepMounted className="pt-2 data-hidden:hidden">
        {terminal}
      </TabsContent>
      <TabsContent value="files" keepMounted className="pt-2 data-hidden:hidden">
        <SFTPBrowser device={device} />
      </TabsContent>
    </Tabs>
  )
}
