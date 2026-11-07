"use client"

import { useState } from "react"
import useSWR from "swr"
import { Pencil } from "lucide-react"

import { Writable } from "@/components/app/read-only"
import { ExitUsersDialog, exitUsersMode } from "@/components/network/exit-users-dialog"
import type { ReferenceChoices } from "@/components/rules/reference-picker"
import { SettingBadge, SettingRow } from "@/components/settings/settings-layout"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { ExitUsers, RulesResponse } from "@/lib/types"

/** Shows and edits who may use the network's exit nodes, as a settings row. */
export function ExitUsersRow({ exitUsers }: { exitUsers: ExitUsers }) {
  const { t } = useI18n()
  // Device, tag and group choices come from the rules endpoint.
  const { data: rules } = useSWR<RulesResponse>("/api/rules", fetcher)
  const [editing, setEditing] = useState(false)
  const mode = exitUsersMode(exitUsers)
  const unused = rules?.unusedTags ?? []
  const choices: ReferenceChoices = {
    devices: rules?.devices ?? [],
    tags: rules?.tags ?? [],
    groups: (rules?.groups ?? []).map((g) => g.name),
  }

  const summary =
    mode === "everyone"
      ? t("Bütün cihazlar ağdaki çıkış düğümlerini kullanabilir.")
      : mode === "nobody"
        ? t("Hiçbir cihaz çıkış düğümü kullanamaz.")
        : t("Yalnızca listedeki cihazlar çıkış düğümü seçebilir.")

  return (
    <SettingRow
      title={t("Çıkış düğümü kullanıcıları")}
      badge={mode === "nobody" ? <SettingBadge tone="danger">{t("Kimse")}</SettingBadge> : mode === "everyone" ? <SettingBadge>{t("Herkes")}</SettingBadge> : null}
      description={summary}
      action={
        <Writable>
          <Button variant="outline" disabled={!rules} onClick={() => setEditing(true)}>
            <Pencil data-icon="inline-start" />
            {t("Değiştir")}
          </Button>
        </Writable>
      }
    >
      {mode === "selected" ? (
        <>
          <ul aria-label={t("Çıkış düğümü kullanıcıları")} className="flex flex-wrap gap-1">
            {exitUsers.users.map((u) => (
              <li key={u}>
                <Badge variant={u.startsWith("tag:") && unused.includes(u.slice(4)) ? "destructive" : "secondary"} className="font-mono">
                  {u}
                </Badge>
              </li>
            ))}
          </ul>
          {exitUsers.users.some((u) => u.startsWith("tag:") && unused.includes(u.slice(4))) ? (
            <p className="text-xs text-muted-foreground text-pretty">{t("Kırmızı etiketler hiçbir cihazda yok; bu başvurular hiçbir şeyle eşleşmez.")}</p>
          ) : null}
        </>
      ) : null}
      <ExitUsersDialog open={editing} onOpenChange={setEditing} current={exitUsers} choices={choices} />
    </SettingRow>
  )
}
