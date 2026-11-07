"use client"

import "@xyflow/react/dist/style.css"

import { useMemo, useState } from "react"
import Link from "next/link"
import useSWR from "swr"
import { useTheme } from "next-themes"
import { Background, BackgroundVariant, Controls, ReactFlow } from "@xyflow/react"
import { ArrowLeftRight, ChevronsUpDown, FileCheck2, Monitor, Rocket, ShieldOff } from "lucide-react"

import { buildGraph, relevantRules, type Direction } from "@/components/control-center/build-graph"
import { nodeTypes } from "@/components/control-center/graph-nodes"
import { QueryState } from "@/components/query-state"
import { headCell, ListTable } from "@/components/settings/list-table"
import { radioGroupKeyDown } from "@/components/settings/radio-keys"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { fetcher } from "@/lib/api"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { Device, DevicesResponse, Overview, Rule, RulesResponse } from "@/lib/types"
import { cn } from "@/lib/utils"

export function ControlCenter() {
  const { t } = useI18n()
  const devices = useSWR<DevicesResponse>("/api/devices", fetcher)
  const rules = useSWR<RulesResponse>("/api/rules", fetcher)
  const overview = useSWR<Overview>("/api/overview", fetcher)
  const error = devices.error ?? rules.error
  const loading = devices.isLoading || rules.isLoading

  return (
    <QueryState
      error={error}
      isLoading={loading}
      onRetry={() => {
        devices.mutate()
        rules.mutate()
      }}
    >
      {devices.data && rules.data ? (
        devices.data.devices.length === 0 ? (
          <Empty className="border">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <Rocket />
              </EmptyMedia>
              <EmptyTitle>{t("Ağın henüz boş")}</EmptyTitle>
              <EmptyDescription>{t("Kurulum sihirbazı koordinatörü ve ilk iki cihazını adım adım ekletir.")}</EmptyDescription>
            </EmptyHeader>
            <EmptyContent>
              <Button nativeButton={false} render={<Link href="/setup" />}>
                {t("Kurulum sihirbazını aç")}
              </Button>
            </EmptyContent>
          </Empty>
        ) : (
          <Graph data={devices.data} rules={rules.data} version={overview.data?.version} />
        )
      ) : null}
    </QueryState>
  )
}

type View = "map" | "list"

/** A small segmented radio group with arrow key movement. */
function Segmented<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string
  value: T
  options: readonly (readonly [T, string])[]
  onChange: (value: T) => void
}) {
  const { t } = useI18n()
  return (
    <div role="radiogroup" aria-label={label} className="flex rounded-lg border bg-card p-0.5" onKeyDown={radioGroupKeyDown}>
      {options.map(([v, text]) => (
        <button
          key={v}
          type="button"
          role="radio"
          aria-checked={value === v}
          tabIndex={value === v ? 0 : -1}
          onClick={() => onChange(v)}
          className={cn(
            "rounded-md px-3 py-1 text-sm transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50",
            value === v ? "bg-secondary font-medium text-foreground" : "text-muted-foreground hover:text-foreground"
          )}
        >
          {t(text)}
        </button>
      ))}
    </div>
  )
}

const directions = [
  ["outgoing", msg("Giden")],
  ["incoming", msg("Gelen")],
] as const

const views = [
  ["map", msg("Harita")],
  ["list", msg("Liste")],
] as const

function Graph({ data, rules, version }: { data: DevicesResponse; rules: RulesResponse; version?: number }) {
  const { t } = useI18n()
  const [selectedName, setSelectedName] = useState(data.devices[0]?.name ?? "")
  const [direction, setDirection] = useState<Direction>("outgoing")
  const [view, setView] = useState<View>("map")
  const selected = data.devices.find((d) => d.name === selectedName) ?? data.devices[0]
  const relevant = useMemo(() => relevantRules(rules.rules, selected, direction), [rules.rules, selected, direction])

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger render={<Button variant="outline" className="min-w-48 justify-between bg-card" />}>
              <span className="flex items-center gap-2">
                <Monitor />
                {selected.name}
              </span>
              <ChevronsUpDown className="text-muted-foreground" />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="max-h-80 w-56 overflow-y-auto">
              {data.devices.map((d) => (
                <DropdownMenuItem key={d.id} onClick={() => setSelectedName(d.name)}>
                  <span className="flex flex-col">
                    <span>{d.name}</span>
                    <span className="font-mono text-[0.8125rem] text-muted-foreground">{d.ipv4}</span>
                  </span>
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
          <Segmented label={t("Yön")} value={direction} options={directions} onChange={setDirection} />
          <Segmented label={t("Görünüm")} value={view} options={views} onChange={setView} />
        </div>
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <FileCheck2 className="size-4 text-success" aria-hidden="true" />
          <span>{t("İmzalı belge")}</span>
          <span className="font-mono text-[0.8125rem]">v{version ?? "-"}</span>
        </div>
      </div>
      {view === "map" ? (
        <MapCanvas devices={data.devices} rules={rules.rules} selected={selected} direction={direction} ruleCount={relevant.length} />
      ) : (
        <AccessList rules={relevant} selected={selected} direction={direction} />
      )}
    </div>
  )
}

interface MapCanvasProps {
  devices: Device[]
  rules: Rule[]
  selected: Device
  direction: Direction
  ruleCount: number
}

function MapCanvas({ devices, rules, selected, direction, ruleCount }: MapCanvasProps) {
  const { t } = useI18n()
  const { resolvedTheme } = useTheme()
  const graph = useMemo(() => buildGraph(devices, rules, selected, direction), [devices, rules, selected, direction])
  return (
    <div className="relative flex min-h-[420px] flex-1 flex-col overflow-hidden rounded-lg border">
      <div className="flex-1">
        <ReactFlow
          nodes={graph.nodes}
          edges={graph.edges}
          nodeTypes={nodeTypes}
          colorMode={resolvedTheme === "light" ? "light" : "dark"}
          fitView
          fitViewOptions={{ padding: 0.35, maxZoom: 1.1 }}
          nodesConnectable={false}
          nodesDraggable
          elementsSelectable={false}
          proOptions={{ hideAttribution: true }}
          className="!bg-transparent"
        >
          <Background variant={BackgroundVariant.Dots} gap={18} size={1} className="opacity-60" />
          <Controls showInteractive={false} position="bottom-right" />
        </ReactFlow>
      </div>

      <p className="sr-only">
        {t("Harita yalnızca görseldir; aynı bilgi Liste görünümünde tablo olarak var.")}{" "}
        {direction === "outgoing"
          ? t("{name} için giden {count} kural.", { name: selected.name, count: ruleCount })
          : t("{name} için gelen {count} kural.", { name: selected.name, count: ruleCount })}
      </p>
      {ruleCount === 0 ? (
        <div className="pointer-events-none absolute inset-x-0 bottom-6 flex justify-center px-4">
          <NoRules selected={selected} direction={direction} className="pointer-events-auto rounded-lg border bg-card shadow-lg" />
        </div>
      ) : null}
    </div>
  )
}

function NoRules({ selected, direction, className }: { selected: Device; direction: Direction; className?: string }) {
  const { t } = useI18n()
  return (
    <div className={cn("flex flex-wrap items-center gap-3 px-4 py-3 text-sm", className)}>
      <ShieldOff className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
      <span className="text-pretty">
        {direction === "outgoing"
          ? t("{name} için giden kural yok; bu yöndeki tüm trafik reddedilir.", { name: selected.name })
          : t("{name} için gelen kural yok; bu yöndeki tüm trafik reddedilir.", { name: selected.name })}
      </span>
      <Button size="sm" variant="outline" nativeButton={false} render={<Link href="/rules" />}>
        <ArrowLeftRight data-icon="inline-start" />
        {t("Kural ekle")}
      </Button>
    </div>
  )
}

const protocolNames: Record<string, string> = { tcp: "TCP", udp: "UDP", icmp: "ICMP", any: msg("Tümü") }

/** The access map as a table: the text alternative of the graph, and easier on a phone. */
function AccessList({ rules, selected, direction }: { rules: Rule[]; selected: Device; direction: Direction }) {
  const { t } = useI18n()
  if (rules.length === 0) return <NoRules selected={selected} direction={direction} className="rounded-lg border" />
  const otherLabel = direction === "outgoing" ? t("Ulaşabildiği") : t("Ona ulaşabilen")
  return (
    <ListTable
      label={
        direction === "outgoing"
          ? t("{name} için giden erişim", { name: selected.name })
          : t("{name} için gelen erişim", { name: selected.name })
      }
    >
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className={cn(headCell, "w-16")}>{t("Kural")}</TableHead>
          <TableHead className={headCell}>{otherLabel}</TableHead>
          <TableHead className={headCell}>{t("Protokol ve port")}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rules.map((r) => {
          const side = (direction === "outgoing" ? r.to : r.from).filter((n) => n !== selected.name)
          return (
            <TableRow key={`${r.index}-${r.text}`}>
              <TableCell className="text-sm text-muted-foreground tabular-nums">
                {/* i18n-ignore: sayfa içi bağlantı kimliği */}
                <Link href={`/rules#kural-${r.index + 1}`} className="underline-offset-4 hover:text-foreground hover:underline">
                  {r.index + 1}
                </Link>
              </TableCell>
              <TableCell className="whitespace-normal">
                {side.length === 0 ? (
                  <span className="text-sm text-muted-foreground">{t("Yalnızca kendisi")}</span>
                ) : (
                  side.map((n, i) => (
                    <span key={n}>
                      {i > 0 ? ", " : null}
                      {n === "*" ? <span className="text-sm">{t("Tüm cihazlar")}</span> : <span className="font-mono text-[0.8125rem]">{n}</span>}
                    </span>
                  ))
                )}
              </TableCell>
              <TableCell className="whitespace-normal">
                <span className="text-sm">{r.service ? r.service.toLocaleUpperCase("en") : t(protocolNames[r.protocol] ?? r.protocol)}</span>
                {r.ports.length > 0 ? (
                  <span className="ml-2 font-mono text-[0.8125rem] text-muted-foreground">{r.ports.join(", ")}</span>
                ) : null}
              </TableCell>
            </TableRow>
          )
        })}
      </TableBody>
    </ListTable>
  )
}
