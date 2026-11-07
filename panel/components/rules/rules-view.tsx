"use client"

import { Fragment, useState } from "react"
import useSWR from "swr"
import { ArrowRight, Plus, ShieldAlert, TriangleAlert } from "lucide-react"

import { useReadOnly, Writable } from "@/components/app/read-only"
import { useRemoteSession } from "@/components/auth/session"
import { AddRuleDialog } from "@/components/rules/add-rule-dialog"
import { AddServiceRuleDialog, serviceRuleDetail, serviceRuleLabel } from "@/components/rules/add-service-rule-dialog"
import { DetailSection } from "@/components/devices/detail-card"
import { FirewallTemplatesSection } from "@/components/rules/firewall-templates" // #243, ADR-0232
import { GroupsSection } from "@/components/rules/groups-section"
import { PolicyTestsSection, PolicyTextEditor, RuleSimulator, usePolicyReport, type PolicyWarning } from "@/components/rules/policy-tools"
import type { ReferenceChoices } from "@/components/rules/reference-picker"
import { UnusedTagsAlert } from "@/components/rules/unused-tags-alert"
import { PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { SignChangeDialog } from "@/components/sign-change"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { headCell, ListTable, PageTab, PageTabs, RowMenu } from "@/components/settings/list-table"
import { EmptyNote, SettingBadge } from "@/components/settings/settings-layout"
import { Button } from "@/components/ui/button"
import { DropdownMenuItem, DropdownMenuSeparator } from "@/components/ui/dropdown-menu"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { fetcher } from "@/lib/api"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import { referenceKind, referenceLabel } from "@/lib/references"
import type { Rule, RulesResponse } from "@/lib/types"
import { cn } from "@/lib/utils"

const protocolNames: Record<string, string> = {
  tcp: "TCP",
  udp: "UDP",
  icmp: "ICMP (ping)",
  any: msg("Tümü"),
}

function protocolLabel(protocol: Rule["protocol"]): string {
  const name = protocolNames[protocol]
  return name ? tx(name) : tx("Protokol {number}", { number: protocol })
}

/**
 * A rule's source or destination list. Device, tag and group names are
 * machine values and stay mono; "tüm cihazlar" is a sentence and does not.
 */
function Targets({ list }: { list: string[] }) {
  const { t } = useI18n()
  return (
    <span className="break-all">
      {list.map((ref, i) => (
        <Fragment key={`${ref}-${i}`}>
          {i > 0 ? ", " : null}
          {referenceKind(ref) === "all" ? (
            <span className="font-sans text-sm">{t("Tüm cihazlar")}</span>
          ) : (
            <span className="font-mono text-[0.8125rem]">{referenceLabel(ref)}</span>
          )}
        </Fragment>
      ))}
    </span>
  )
}

/** "laptop → masaüstü, TCP 22": a rule in words, for warnings that point at it. */
function ruleSummary(r: Rule): string {
  const from = r.from.map((x) => (x === "*" ? tx("tüm cihazlar") : x)).join(", ")
  const to = r.to.map((x) => (x === "*" ? tx("tüm cihazlar") : x)).join(", ")
  const what = r.service ? serviceRuleLabel(r.service) : `${protocolLabel(r.protocol)}${r.ports.length > 0 ? ` ${r.ports.join(", ")}` : ""}`
  return `${from} → ${to}, ${what}`
}

type Tab = "kurallar" | "gruplar" | "test" | "metin"

const allTabs: { value: Tab; label: string }[] = [
  { value: "kurallar", label: msg("Kurallar") },
  { value: "gruplar", label: msg("Gruplar") },
  { value: "test", label: msg("Test ve simülatör") },
  { value: "metin", label: msg("Metin düzenleyici") },
]

/**
 * A remote (tunnel) session can read the rules but not run the simulator
 * or open the policy text; those tabs are left out there.
 */
const remoteTabs = allTabs.filter((t) => t.value === "kurallar" || t.value === "gruplar")

export function RulesView() {
  const { t } = useI18n()
  const [tab, setTab] = useState<Tab>("kurallar")
  const { data, error, isLoading, mutate } = useSWR<RulesResponse>("/api/rules", fetcher)
  const readOnly = useReadOnly()
  const remote = useRemoteSession()
  const tabs = remote ? remoteTabs : allTabs
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState<Rule | null>(null)
  const [addingService, setAddingService] = useState(false)
  const [removing, setRemoving] = useState<Rule | null>(null)
  const [toggling, setToggling] = useState<Rule | null>(null)
  const noDevices = data !== undefined && data.devices.length === 0
  const choices: ReferenceChoices = {
    devices: data?.devices ?? [],
    tags: data?.tags ?? [],
    groups: (data?.groups ?? []).map((g) => g.name),
  }

  return (
    <>
      <PageHeader
        title={t("Erişim Kontrolü")}
        description={t("Cihazlar arası trafik varsayılan olarak reddedilir; kurallar neye izin verildiğini belirler.")}
        actions={
          <Writable>
            <Button variant="outline" onClick={() => setAddingService(true)} disabled={noDevices}>
              <Plus data-icon="inline-start" />
              {t("Servis kuralı ekle")}
            </Button>
            <Button onClick={() => setAdding(true)} disabled={noDevices}>
              <Plus data-icon="inline-start" />
              {t("Kural ekle")}
            </Button>
          </Writable>
        }
      />
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {data ? (
          <PageTabs
            value={tabs.some((x) => x.value === tab) ? tab : "kurallar"}
            onValueChange={setTab}
            tabs={tabs.map((x) => ({ ...x, label: t(x.label) }))}
            label={t("Erişim Kontrolü bölümleri")}
          >
            <PageTab value="kurallar">
              <DetailSection
                // i18n-ignore: bağlantı kimliği, görünmez
                id="kurallar"
                title={t("Kurallar")}
                description={t("Reddet kuralları her zaman izin kurallarından önce uygulanır; kapalı kurallar silinmeden devre dışı kalır.")}
                framed={false}
              >
                <div className="flex flex-col gap-3 empty:hidden">
                  <UnusedTagsAlert unusedTags={data.unusedTags} rules={data.rules} />
                  {remote ? null : <RuleWarnings rules={data.rules} />}
                </div>
                {data.rules.length === 0 ? (
                  <EmptyNote>
                    {noDevices
                      ? t("Kural yok, her şey kapalı. Kural ekleyebilmek için önce cihaz ekle.")
                      : t("Kural yok, her şey kapalı. Örneğin laptoptan masaüstüne Uzak Masaüstü için TCP 3389'a izin veren bir kural ekleyebilirsin.")}
                  </EmptyNote>
                ) : (
                  <RulesTable rules={data.rules} readOnly={readOnly} onEdit={setEditing} onToggle={setToggling} onRemove={setRemoving} />
                )}
              </DetailSection>
              {remote || readOnly || noDevices ? null : <FirewallTemplatesSection />}
            </PageTab>
            <PageTab value="gruplar">
              <GroupsSection groups={data.groups} unusedTags={data.unusedTags} choices={choices} />
            </PageTab>
            <PageTab value="test">
              <PolicyTestsSection />
              {data.devices.length > 0 ? (
                <RuleSimulator devices={data.devices} />
              ) : (
                <EmptyNote>{t("Kural simülatörü için önce cihaz ekle.")}</EmptyNote>
              )}
            </PageTab>
            <PageTab value="metin">
              <PolicyTextEditor />
            </PageTab>
          </PageTabs>
        ) : null}
      </QueryState>

      {data ? <AddRuleDialog open={adding} onOpenChange={setAdding} choices={choices} /> : null}
      {data ? (
        <AddRuleDialog
          open={editing !== null}
          onOpenChange={(open) => {
            if (!open) setEditing(null)
          }}
          choices={choices}
          editing={editing}
        />
      ) : null}
      {data ? <AddServiceRuleDialog open={addingService} onOpenChange={setAddingService} choices={choices} /> : null}
      <SignChangeDialog
        open={removing !== null}
        onOpenChange={(open) => {
          if (!open) setRemoving(null)
        }}
        title={removing ? t("Kural {number}: sil", { number: removing.index + 1 }) : t("Kuralı sil")}
        description={
          removing
            ? removing.action === "deny"
              ? t("{rule} reddet kuralı silinecek; izin kurallarının kapsadığı trafik bundan sonra geçer. Sonraki kuralların numarası bir azalır.", {
                  rule: ruleSummary(removing),
                })
              : t("{rule} kuralı silinecek; bu trafik bundan sonra reddedilir. Sonraki kuralların numarası bir azalır.", { rule: ruleSummary(removing) })
            : ""
        }
        endpoint="/api/rules/remove"
        payload={{ index: removing?.index ?? -1 }}
        confirmLabel={t("İmzala ve sil")}
        destructive
      />
      <SignChangeDialog
        open={toggling !== null}
        onOpenChange={(open) => {
          if (!open) setToggling(null)
        }}
        title={
          toggling
            ? toggling.disabled
              ? t("Kural {number}: aç", { number: toggling.index + 1 })
              : t("Kural {number}: kapat", { number: toggling.index + 1 })
            : t("Kuralı kapat")
        }
        description={
          toggling
            ? toggling.disabled
              ? t("{rule} kuralı yeniden uygulanır.", { rule: ruleSummary(toggling) })
              : t("{rule} kuralı silinmeden devre dışı kalır; sonradan yeniden açabilirsin.", { rule: ruleSummary(toggling) })
            : ""
        }
        endpoint="/api/rules/state"
        payload={{ index: toggling?.index ?? -1, disabled: !(toggling?.disabled ?? true) }}
        confirmLabel={toggling?.disabled ? t("İmzala ve aç") : t("İmzala ve kapat")}
      />
    </>
  )
}

interface RulesTableProps {
  rules: Rule[]
  readOnly: boolean
  onEdit: (rule: Rule) => void
  onToggle: (rule: Rule) => void
  onRemove: (rule: Rule) => void
}

function RulesTable({ rules, readOnly, onEdit, onToggle, onRemove }: RulesTableProps) {
  const { t } = useI18n()
  return (
    <ListTable label={t("Erişim kuralları")}>
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className={cn(headCell, "w-10")}>
            <span aria-hidden="true">#</span>
            <span className="sr-only">{t("Kural numarası")}</span>
          </TableHead>
          <TableHead className={headCell}>{t("Kaynak → Hedef")}</TableHead>
          <TableHead className={cn(headCell, "hidden sm:table-cell")}>{t("Port / protokol")}</TableHead>
          <TableHead className={cn(headCell, "hidden md:table-cell")}>{t("Eylem")}</TableHead>
          <TableHead className={cn(headCell, "hidden md:table-cell")}>{t("Durum")}</TableHead>
          <TableHead className="w-12">
            <span className="sr-only">{t("İşlemler")}</span>
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rules.map((r) => {
          const port = r.service ? serviceRuleDetail(r) : r.ports.length > 0 ? r.ports.join(", ") : ""
          const proto = r.service ? serviceRuleLabel(r.service) : protocolLabel(r.protocol)
          const n = r.index + 1
          return (
            <TableRow key={`${r.index}-${r.text}`} id={`kural-${n}`} className={cn("scroll-mt-24", r.disabled && "text-muted-foreground")}>
              <TableCell className="text-sm text-muted-foreground tabular-nums">{n}</TableCell>
              <TableCell className="whitespace-normal">
                <div className="flex min-w-0 flex-col gap-1">
                  <span className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                    <Targets list={r.from} />
                    <ArrowRight className="size-3.5 shrink-0 text-muted-foreground" aria-label={t("hedef")} />
                    <Targets list={r.to} />
                  </span>
                  {r.description ? <span className="text-sm text-pretty text-muted-foreground">{r.description}</span> : null}
                  <span className="text-sm text-muted-foreground sm:hidden">
                    {proto}
                    {port ? ` · ${port}` : ""}
                  </span>
                  <span className="flex flex-wrap gap-1 md:hidden">
                    <ActionBadge rule={r} />
                    <StateBadge rule={r} />
                  </span>
                </div>
              </TableCell>
              <TableCell className="hidden whitespace-normal sm:table-cell">
                <span className="flex flex-col gap-0.5">
                  <span className="text-sm">{proto}</span>
                  {port ? (
                    <span className={cn("text-sm break-all text-muted-foreground", !r.service && "font-mono text-[0.8125rem]")}>{port}</span>
                  ) : null}
                </span>
              </TableCell>
              <TableCell className="hidden md:table-cell">
                <ActionBadge rule={r} />
              </TableCell>
              <TableCell className="hidden md:table-cell">
                <StateBadge rule={r} />
              </TableCell>
              <TableCell className="text-right">
                {readOnly ? null : (
                  <RowMenu label={t("Kural {number} için işlemler", { number: n })}>
                    {r.service ? null : <DropdownMenuItem onClick={() => onEdit(r)}>{t("Düzenle…")}</DropdownMenuItem>}
                    <DropdownMenuItem onClick={() => onToggle(r)}>{r.disabled ? t("Kuralı aç…") : t("Kuralı kapat…")}</DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem variant="destructive" onClick={() => onRemove(r)}>
                      {t("Sil…")}
                    </DropdownMenuItem>
                  </RowMenu>
                )}
              </TableCell>
            </TableRow>
          )
        })}
      </TableBody>
    </ListTable>
  )
}

/** Allow is the expected case and stays neutral; only deny carries color. */
function ActionBadge({ rule }: { rule: Rule }) {
  const { t } = useI18n()
  return rule.action === "deny" ? <SettingBadge tone="danger">{t("rule-action|Reddet")}</SettingBadge> : <SettingBadge>{t("İzin ver")}</SettingBadge>
}

function StateBadge({ rule }: { rule: Rule }) {
  const { t } = useI18n()
  return rule.disabled ? <SettingBadge tone="warning">{t("Kapalı")}</SettingBadge> : <SettingBadge>{t("Etkin")}</SettingBadge>
}

/**
 * Rule warnings above the table, said once each. Broad rules get one alert
 * with the way out; the other scope warnings (shadowed, matches nothing,
 * expired, clock) are listed with the rule they are about. Unused tags have
 * their own alert, so they are left out here.
 */
function RuleWarnings({ rules }: { rules: Rule[] }) {
  const { t } = useI18n()
  const { data } = usePolicyReport()
  const warnings = data?.warnings ?? []
  const broadIndexes = new Set(warnings.filter((w) => w.code === "broad").map((w) => w.rule))
  for (const r of rules) if (isWideOpen(r)) broadIndexes.add(r.index)
  const broad = rules.filter((r) => broadIndexes.has(r.index))
  const other = warnings.filter((w) => w.code !== "broad" && w.code !== "unused_tag")
  const byIndex = new Map(rules.map((r) => [r.index, r]))

  return (
    <>
      {broad.length > 0 ? (
        <Alert>
          <ShieldAlert />
          <AlertTitle>{t("Tüm cihazlar birbirine her porttan erişebiliyor")}</AlertTitle>
          <AlertDescription className="flex flex-col gap-2 text-pretty">
            <span>
              {t(
                "Kural {rules} kolay başlangıç içindir ve varsayılan reddet ilkesini fiilen kapatır. Cihazlarından biri ele geçirilirse diğerlerinin bütün portlarına ulaşabilir.",
                { rules: broad.map((r) => r.index + 1).join(", ") }
              )}
            </span>
            <span>{t("Önce ihtiyacın olan dar kuralları ekle (örneğin laptop → masaüstü, TCP 3389), sonra bu kuralı sil.")}</span>
          </AlertDescription>
        </Alert>
      ) : null}
      {other.length > 0 ? (
        <Alert>
          <TriangleAlert />
          <AlertTitle>{t("Kural uyarıları")}</AlertTitle>
          <AlertDescription>
            <ul className="flex flex-col gap-2">
              {other.map((w, i) => (
                <WarningLine key={`${w.code}-${w.rule}-${i}`} warning={w} rule={byIndex.get(w.rule)} />
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      ) : null}
    </>
  )
}

function WarningLine({ warning, rule }: { warning: PolicyWarning; rule: Rule | undefined }) {
  const { t, ts } = useI18n()
  return (
    <li className="flex flex-col gap-0.5 text-pretty">
      <span>{ts(warning.message)}</span>
      {rule ? (
        <a href={`#kural-${rule.index + 1}`} className="w-fit text-sm text-muted-foreground underline underline-offset-4 hover:text-foreground">
          {t("Kural {number}: {rule}", { number: rule.index + 1, rule: ruleSummary(rule) })}
        </a>
      ) : null}
    </li>
  )
}

/** An enabled rule that lets every device reach every port of every other device. */
function isWideOpen(r: Rule): boolean {
  return r.action !== "deny" && !r.disabled && !r.service && r.protocol === "any" && r.from.includes("*") && r.to.includes("*")
}
