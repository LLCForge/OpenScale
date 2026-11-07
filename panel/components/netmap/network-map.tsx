"use client"

import { useMemo, useRef, useState } from "react"
import { Table2 } from "lucide-react"

import { DeviceIcon } from "@/components/netmap/device-icon"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { deviceKind, deviceKindLabels } from "@/lib/device-kind"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { MapEdge, MapNode, MapResponse } from "@/lib/p16-types"
import { cn } from "@/lib/utils"

// Network map (#229) drawn with plain SVG: the coordinator in the middle,
// devices on a ring, a line for every pair the tunnel connects. The SVG is
// a picture of the table next to it; keyboard and screen reader users get
// the same facts from the focusable nodes, the link list and the table.

const W = 880
const H = 560

interface Placed extends MapNode {
  x: number
  y: number
}

function layout(nodes: MapNode[]): { placed: Placed[]; nodeR: number } {
  const coordinator = nodes.find((n) => n.kind === "coordinator")
  const devices = nodes
    .filter((n) => n.kind === "device")
    .sort((a, b) => Number(b.thisComputer) - Number(a.thisComputer) || a.name.localeCompare(b.name, "tr"))
  const nodeR = devices.length > 24 ? 14 : devices.length > 12 ? 18 : 22
  const cx = W / 2
  const cy = H / 2
  const r = Math.min(W, H) / 2 - 64
  const placed: Placed[] = []
  if (coordinator) placed.push({ ...coordinator, x: cx, y: cy })
  devices.forEach((d, i) => {
    if (devices.length === 1 && !coordinator) {
      placed.push({ ...d, x: cx, y: cy })
      return
    }
    const angle = -Math.PI / 2 + (2 * Math.PI * i) / devices.length
    placed.push({ ...d, x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) })
  })
  return { placed, nodeR }
}

function short(name: string): string {
  return name.length > 16 ? `${name.slice(0, 15)}…` : name
}

export function edgeLabel(e: MapEdge): string {
  switch (e.path) {
    case "direct":
      return msg("Doğrudan")
    case "relay":
      return msg("Aktarıcı üzerinden")
    case "none":
      return msg("Şu an bağlantı yok")
  }
  if (e.rule) return msg("Kural (yol bilinmiyor)")
  return e.peer === "exit" ? msg("Çıkış düğümü tüneli (kural yok)") : msg("Yönetim tüneli (kural yok)")
}

const statusLabels: Record<MapNode["status"], string> = {
  this: msg("bu bilgisayar"),
  online: msg("çevrimiçi"),
  offline: msg("çevrimdışı"),
  unknown: msg("durum bilinmiyor"),
}

function edgeClass(e: MapEdge): { className: string; dash?: string; width: number } {
  switch (e.path) {
    case "direct":
      return { className: "stroke-success", width: 2.5 }
    case "relay":
      return { className: "stroke-warning", dash: "7 5", width: 2.5 }
    case "none":
      return { className: "stroke-muted-foreground", dash: "2 5", width: 1.5 }
  }
  if (e.rule) return { className: "stroke-foreground/60", width: 1.5 }
  return { className: "stroke-muted-foreground/70", dash: "1 5", width: 1.25 }
}

export function NetworkMap({ data }: { data: MapResponse }) {
  const { t } = useI18n()
  const { placed, nodeR } = useMemo(() => layout(data.nodes), [data.nodes])
  const byId = useMemo(() => new Map(placed.map((n) => [n.id, n])), [placed])
  const [selected, setSelected] = useState<string | null>(null)
  const [showTable, setShowTable] = useState(false)
  const refs = useRef<(SVGGElement | null)[]>([])

  const degree = (id: string) => data.edges.filter((e) => e.from === id || e.to === id).length
  const selectedNode = selected ? byId.get(selected) : undefined
  const selectedEdges = selected ? data.edges.filter((e) => e.from === selected || e.to === selected) : []
  const coordinator = placed.find((n) => n.kind === "coordinator")

  function nodeLabel(n: Placed): string {
    const kind = t(deviceKindLabels[deviceKind({ name: n.name, os: n.os, coordinator: n.kind === "coordinator" })])
    if (n.kind === "coordinator") return t("{name}, koordinatör, {status}", { name: t("Koordinatör"), status: t(statusLabels[n.status]) })
    return t("{name}, {kind}, {status}, {count} bağlantı", { name: n.name, kind, status: t(statusLabels[n.status]), count: degree(n.id) })
  }

  function onKey(e: React.KeyboardEvent<SVGGElement>, index: number, id: string) {
    const move = (to: number) => {
      e.preventDefault()
      refs.current[(to + placed.length) % placed.length]?.focus()
    }
    switch (e.key) {
      case "ArrowRight":
      case "ArrowDown":
        move(index + 1)
        break
      case "ArrowLeft":
      case "ArrowUp":
        move(index - 1)
        break
      case "Home":
        move(0)
        break
      case "End":
        move(placed.length - 1)
        break
      case "Enter":
      case " ":
        e.preventDefault()
        setSelected((s) => (s === id ? null : id))
        break
      case "Escape":
        setSelected(null)
        break
    }
  }

  const other = (e: MapEdge, id: string) => byId.get(e.from === id ? e.to : e.from)

  return (
    <div className="flex flex-col gap-4">
    <div className="flex flex-col gap-4 lg:flex-row">
      <div className="min-w-0 flex-1 overflow-x-auto rounded-xl border bg-card/40">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="h-auto w-full min-w-[560px] select-none"
          role="group"
          aria-labelledby="ag-haritasi-baslik ag-haritasi-aciklama"
        >
          <title id="ag-haritasi-baslik">{t("Ağ haritası")}</title>
          <desc id="ag-haritasi-aciklama">
            {t("{devices} cihaz ve {links} bağlantı. Cihazlar arasında ok tuşlarıyla gez, ayrıntı için Enter'a bas.", {
              devices: placed.filter((n) => n.kind === "device").length,
              links: data.edges.length,
            })}
          </desc>
          {coordinator
            ? placed
                .filter((n) => n.kind === "device")
                .map((n) => (
                  <line
                    key={`c-${n.id}`}
                    x1={coordinator.x}
                    y1={coordinator.y}
                    x2={n.x}
                    y2={n.y}
                    className="stroke-border"
                    strokeWidth={1}
                    aria-hidden="true"
                  />
                ))
            : null}
          {data.edges.map((e) => {
            const a = byId.get(e.from)
            const b = byId.get(e.to)
            if (!a || !b) return null
            const style = edgeClass(e)
            const dim = selected !== null && e.from !== selected && e.to !== selected
            return (
              <line
                key={`${e.from}-${e.to}`}
                x1={a.x}
                y1={a.y}
                x2={b.x}
                y2={b.y}
                className={cn(style.className, "transition-opacity", dim && "opacity-15")}
                strokeWidth={style.width}
                strokeDasharray={style.dash}
                strokeLinecap="round"
                aria-hidden="true"
              >
                <title>{`${a.name} – ${b.name}: ${t(edgeLabel(e))}`}</title>
              </line>
            )
          })}
          {placed.map((n, i) => {
            const isSel = selected === n.id
            const kind = deviceKind({ name: n.name, os: n.os, coordinator: n.kind === "coordinator" })
            const label = n.kind === "coordinator" ? t("Koordinatör") : short(n.name)
            return (
              <g
                key={n.id}
                ref={(el) => {
                  refs.current[i] = el
                }}
                transform={`translate(${n.x} ${n.y})`}
                role="button"
                tabIndex={0}
                aria-pressed={isSel}
                aria-label={nodeLabel(n)}
                className="group cursor-pointer outline-none"
                onClick={() => setSelected((s) => (s === n.id ? null : n.id))}
                onKeyDown={(e) => onKey(e, i, n.id)}
              >
                <circle r={nodeR + 6} className="fill-none stroke-ring opacity-0 group-focus-visible:opacity-100" strokeWidth={2} />
                <circle
                  r={nodeR}
                  className={cn("fill-card", isSel ? "stroke-foreground" : "stroke-border", n.thisComputer && "fill-secondary")}
                  strokeWidth={isSel ? 2.5 : 1.5}
                />
                <DeviceIcon
                  kind={kind}
                  x={-nodeR * 0.5}
                  y={-nodeR * 0.5}
                  width={nodeR}
                  height={nodeR}
                  className="text-foreground"
                />
                <circle
                  cx={nodeR * 0.72}
                  cy={-nodeR * 0.72}
                  r={4.5}
                  className={cn(
                    "stroke-card",
                    n.status === "online" || n.status === "this" ? "fill-success" : n.status === "offline" ? "fill-muted-foreground" : "fill-border"
                  )}
                  strokeWidth={1.5}
                />
                <text y={nodeR + 17} textAnchor="middle" className="fill-foreground text-[12px] font-medium">
                  {label}
                </text>
                {n.kind === "device" ? (
                  <text y={nodeR + 31} textAnchor="middle" className="fill-muted-foreground font-mono text-[10px]">
                    {n.ipv4}
                  </text>
                ) : null}
              </g>
            )
          })}
        </svg>
      </div>

      <aside className="flex w-full shrink-0 flex-col gap-4 lg:w-80" aria-live="polite">
        <Legend />
        <div className="flex flex-col gap-3 rounded-xl border p-4">
          {selectedNode ? (
            <>
              <div className="flex items-center gap-3">
                <DeviceIcon
                  kind={deviceKind({ name: selectedNode.name, os: selectedNode.os, coordinator: selectedNode.kind === "coordinator" })}
                  className="size-5"
                />
                <div className="flex min-w-0 flex-col">
                  <h3 className="truncate font-medium">{selectedNode.kind === "coordinator" ? t("Koordinatör") : selectedNode.name}</h3>
                  <span className="font-mono text-[0.8125rem] text-muted-foreground">{selectedNode.ipv4}</span>
                </div>
              </div>
              <div className="flex flex-wrap gap-1.5">
                <Badge variant="secondary">{t(statusLabels[selectedNode.status])}</Badge>
                {selectedNode.admin ? <Badge variant="outline">{t("Yönetici")}</Badge> : null}
                {selectedNode.exitNode ? <Badge variant="outline">{t("Çıkış düğümü")}</Badge> : null}
                {selectedNode.tags.map((tag) => (
                  <Badge key={tag} variant="outline">
                    tag:{tag}
                  </Badge>
                ))}
              </div>
              {selectedNode.kind === "coordinator" ? (
                <p className="text-sm leading-relaxed text-muted-foreground">
                  {t("Koordinatör cihazların birbirini bulmasını sağlar ve doğrudan yol yoksa trafiği şifreli olarak aktarır; trafiği okuyamaz.")}
                </p>
              ) : selectedEdges.length === 0 ? (
                <p className="text-sm text-muted-foreground">{t("Bu cihazın hiçbir cihazla bağlantısı yok: onu içeren bir kural yok.")}</p>
              ) : (
                <ul className="flex flex-col gap-2 text-sm" aria-label={t("Bağlantılar")}>
                  {selectedEdges.map((e) => {
                    const o = other(e, selectedNode.id)
                    return (
                      <li key={`${e.from}-${e.to}`} className="flex items-center justify-between gap-2">
                        <span className="truncate">{o?.name}</span>
                        <span className="shrink-0 text-sm text-muted-foreground">{t(edgeLabel(e))}</span>
                      </li>
                    )
                  })}
                </ul>
              )}
            </>
          ) : (
            <p className="text-sm leading-relaxed text-muted-foreground">
              {t("Bir cihaza tıkla veya Tab ile seçip Enter'a bas: bağlantıları burada listelenir.")}
            </p>
          )}
        </div>
        {!data.live ? (
          <p className="text-sm leading-relaxed text-muted-foreground">
            {t("Bu panel tünel çalıştırmıyor; yalnızca imzalı kurallardan çıkan bağlantılar gösterilir. Doğrudan veya aktarıcı yolu masaüstü uygulamasında görünür.")}
          </p>
        ) : null}
        <Button variant="outline" onClick={() => setShowTable((s) => !s)} aria-expanded={showTable} aria-controls="ag-haritasi-tablo">
          <Table2 data-icon="inline-start" />
          {showTable ? t("Tabloyu gizle") : t("Bağlantıları tablo olarak göster")}
        </Button>
      </aside>
    </div>
      {showTable ? <EdgeTable data={data} byId={byId} /> : null}
    </div>
  )
}

function EdgeTable({ data, byId }: { data: MapResponse; byId: Map<string, Placed> }) {
  const { t } = useI18n()
  return (
    <div id="ag-haritasi-tablo" className="w-full overflow-x-auto rounded-xl border">
      <Table>
        <caption className="sr-only">{t("Ağ haritasındaki bağlantılar")}</caption>
        <TableHeader>
          <TableRow>
            <TableHead>{t("Cihaz")}</TableHead>
            <TableHead>{t("Cihaz")}</TableHead>
            <TableHead>{t("Kural")}</TableHead>
            <TableHead>{t("Yol")}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.edges.map((e) => (
            <TableRow key={`${e.from}-${e.to}`}>
              <TableCell>{byId.get(e.from)?.name}</TableCell>
              <TableCell>{byId.get(e.to)?.name}</TableCell>
              <TableCell>{e.rule ? t("Var") : t("Yok")}</TableCell>
              <TableCell>{t(edgeLabel(e))}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

function Legend() {
  const { t } = useI18n()
  const items: { label: string; className: string; dash?: string }[] = [
    { label: msg("Doğrudan"), className: "stroke-success" },
    { label: msg("Aktarıcı üzerinden"), className: "stroke-warning", dash: "7 5" },
    { label: msg("Kural (yol bilinmiyor)"), className: "stroke-foreground/60" },
    { label: msg("Yönetim veya çıkış tüneli"), className: "stroke-muted-foreground/70", dash: "1 5" },
    { label: msg("Şu an bağlantı yok"), className: "stroke-muted-foreground", dash: "2 5" },
  ]
  return (
    <ul className="flex flex-col gap-2 rounded-xl border p-4 text-sm" aria-label={t("Gösterim")}>
      {items.map((i) => (
        <li key={i.label} className="flex items-center gap-3">
          <svg width="32" height="8" aria-hidden="true" className="shrink-0">
            <line x1="2" y1="4" x2="30" y2="4" className={i.className} strokeWidth={2.5} strokeDasharray={i.dash} strokeLinecap="round" />
          </svg>
          <span>{t(i.label)}</span>
        </li>
      ))}
    </ul>
  )
}
