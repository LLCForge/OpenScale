"use client"

import { useState } from "react"
import { Plus } from "lucide-react"

import { useReadOnly, Writable } from "@/components/app/read-only"
import { DetailSection } from "@/components/devices/detail-card"
import { GroupDialog } from "@/components/rules/group-dialog"
import type { ReferenceChoices } from "@/components/rules/reference-picker"
import { headCell, ListTable, RowMenu } from "@/components/settings/list-table"
import { EmptyNote, SettingBadge } from "@/components/settings/settings-layout"
import { SignChangeDialog } from "@/components/sign-change"
import { Button } from "@/components/ui/button"
import { DropdownMenuItem, DropdownMenuSeparator } from "@/components/ui/dropdown-menu"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { tx, useI18n } from "@/lib/i18n/i18n"
import type { Group } from "@/lib/types"
import { cn } from "@/lib/utils"

interface GroupsSectionProps {
  groups: Group[]
  unusedTags: string[]
  choices: ReferenceChoices
}

/** Named sets of devices and tags that rules can refer to as group:x. */
export function GroupsSection({ groups, unusedTags, choices }: GroupsSectionProps) {
  const { t } = useI18n()
  const readOnly = useReadOnly()
  const [editing, setEditing] = useState<{ group: Group | null } | null>(null)
  const [removing, setRemoving] = useState<Group | null>(null)

  return (
    <DetailSection
      // i18n-ignore: bağlantı kimliği, görünmez
      id="gruplar"
      title={t("Gruplar")}
      description={t("Bir grup cihazları ve etiketleri tek adla toplar; kurallarda ve çıkış düğümü kullanıcılarında group:ad olarak kullanılır.")}
      framed={false}
      action={
        <Writable>
          <Button variant="outline" onClick={() => setEditing({ group: null })}>
            <Plus data-icon="inline-start" />
            {t("Grup ekle")}
          </Button>
        </Writable>
      }
    >
      {groups.length === 0 ? (
        <EmptyNote>{t("Henüz grup yok.")}</EmptyNote>
      ) : (
        <ListTable label={t("Gruplar")}>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className={headCell}>{t("Grup")}</TableHead>
              <TableHead className={cn(headCell, "hidden sm:table-cell")}>{t("Üyeler")}</TableHead>
              <TableHead className={cn(headCell, "hidden md:table-cell")}>{t("Kullanım")}</TableHead>
              <TableHead className="w-12">
                <span className="sr-only">{t("İşlemler")}</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {groups.map((g) => (
              <TableRow key={g.name}>
                <TableCell>
                  <div className="flex min-w-0 flex-col gap-1.5">
                    <span className="font-mono text-sm font-medium">group:{g.name}</span>
                    <span className="text-sm text-muted-foreground md:hidden">{usage(g)}</span>
                    <Members group={g} unusedTags={unusedTags} className="sm:hidden" />
                  </div>
                </TableCell>
                <TableCell className="hidden whitespace-normal sm:table-cell">
                  <Members group={g} unusedTags={unusedTags} />
                </TableCell>
                <TableCell className="hidden text-sm text-muted-foreground md:table-cell">{usage(g)}</TableCell>
                <TableCell className="text-right">
                  {readOnly ? null : (
                    <RowMenu label={t("group:{name} için işlemler", { name: g.name })}>
                      <DropdownMenuItem onClick={() => setEditing({ group: g })}>{t("Düzenle…")}</DropdownMenuItem>
                      <DropdownMenuSeparator />
                      {g.usedBy > 0 ? (
                        <DropdownMenuItem disabled className="flex-col items-start gap-0.5">
                          <span>{t("Sil")}</span>
                          <span className="text-sm text-pretty text-muted-foreground">
                            {t("Kullanımdaki grup silinemez; önce ona başvuran kuralları ve çıkış düğümü kullanıcılarını değiştir.")}
                          </span>
                        </DropdownMenuItem>
                      ) : (
                        <DropdownMenuItem variant="destructive" onClick={() => setRemoving(g)}>
                          {t("Sil…")}
                        </DropdownMenuItem>
                      )}
                    </RowMenu>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </ListTable>
      )}

      <GroupDialog
        open={editing !== null}
        onOpenChange={(open) => {
          if (!open) setEditing(null)
        }}
        group={editing?.group ?? null}
        existing={groups.map((g) => g.name)}
        choices={choices}
      />
      <SignChangeDialog
        open={removing !== null}
        onOpenChange={(open) => {
          if (!open) setRemoving(null)
        }}
        title={t("group:{name} grubunu sil", { name: removing?.name ?? "" })}
        description={t("Grup belgeden kaldırılır. Üye cihazlar ve etiketler değişmez.")}
        endpoint="/api/groups/remove"
        payload={{ name: removing?.name ?? "" }}
        confirmLabel={t("İmzala ve sil")}
        destructive
      />
    </DetailSection>
  )
}

function usage(g: Group): string {
  return g.usedBy > 0 ? tx("{count} yerde kullanılıyor", { count: g.usedBy }) : tx("Kullanılmıyor")
}

function Members({ group, unusedTags, className }: { group: Group; unusedTags: string[]; className?: string }) {
  const { t } = useI18n()
  return (
    <ul aria-label={t("group:{name} üyeleri", { name: group.name })} className={cn("flex flex-wrap gap-1", className)}>
      {group.members.map((m) => (
        <li key={m}>
          <SettingBadge tone={m.startsWith("tag:") && unusedTags.includes(m.slice(4)) ? "danger" : "muted"}>
            <span className="font-mono">{m}</span>
          </SettingBadge>
        </li>
      ))}
    </ul>
  )
}
