import type { Edge, Node } from "@xyflow/react"

import { msg } from "@/lib/i18n/i18n"
import type { Device, Rule } from "@/lib/types"

export type Direction = "outgoing" | "incoming"

const COLUMN_X = { left: 0, middle: 380, right: 720 }
const ROW_GAP = 96

const protocolLabel: Record<Rule["protocol"], string> = {
  tcp: "TCP",
  udp: "UDP",
  icmp: "ICMP",
  any: msg("Tümü"),
}

function matches(entries: string[], name: string): boolean {
  return entries.includes("*") || entries.includes(name)
}

function ruleDetail(rule: Rule): string {
  return rule.ports.length > 0 ? rule.ports.join(", ") : msg("tüm portlar")
}

function centered(count: number, index: number): number {
  return (index - (count - 1) / 2) * ROW_GAP
}

const edgeStyle = { stroke: "var(--success)", strokeDasharray: "6 5", strokeWidth: 1.5 }

/**
 * Lays out the access graph for one device: the device on one side, the
 * rules that mention it in the middle, and the other side's devices (or the
 * "all devices" group) on the far side. Mirrors the signed rules exactly;
 * no connection state is implied.
 */
/** The enabled rules that mention the device on the chosen side. */
export function relevantRules(rules: Rule[], selected: Device, direction: Direction): Rule[] {
  return rules.filter((r) => !r.disabled && (direction === "outgoing" ? matches(r.from, selected.name) : matches(r.to, selected.name)))
}

export function buildGraph(devices: Device[], rules: Rule[], selected: Device, direction: Direction): { nodes: Node[]; edges: Edge[] } {
  const relevant = relevantRules(rules, selected, direction)
  const nodes: Node[] = []
  const edges: Edge[] = []
  const selfId = `device:${selected.name}`
  nodes.push({
    id: selfId,
    type: "device",
    position: { x: direction === "outgoing" ? COLUMN_X.left : COLUMN_X.right, y: 0 },
    data: { name: selected.name, ipv4: selected.ipv4, exitNode: selected.exitNode, selected: true },
  })

  const others = new Map<string, { label: string; isGroup: boolean }>()
  relevant.forEach((rule) => {
    const side = direction === "outgoing" ? rule.to : rule.from
    side.forEach((name) => {
      if (name === selected.name) return
      others.set(name, { label: name === "*" ? msg("Tüm cihazlar") : name, isGroup: name === "*" })
    })
  })
  const otherNames = [...others.keys()]
  const otherX = direction === "outgoing" ? COLUMN_X.right : COLUMN_X.left
  otherNames.forEach((name, i) => {
    const info = others.get(name)
    const device = devices.find((d) => d.name === name)
    const position = { x: otherX + (info?.isGroup ? 24 : 0), y: centered(otherNames.length, i) }
    if (info?.isGroup) {
      nodes.push({ id: `group:${name}`, type: "group", position, data: { label: info.label, count: devices.length } })
    } else {
      nodes.push({
        id: `device:${name}`,
        type: "device",
        position,
        data: { name, ipv4: device?.ipv4 ?? "", exitNode: device?.exitNode ?? false },
      })
    }
  })

  relevant.forEach((rule, i) => {
    const ruleId = `rule:${rule.index}`
    nodes.push({
      id: ruleId,
      type: "rule",
      position: { x: COLUMN_X.middle, y: centered(relevant.length, i) + 12 },
      data: { label: protocolLabel[rule.protocol], detail: ruleDetail(rule) },
    })
    const side = direction === "outgoing" ? rule.to : rule.from
    const targets = side.filter((n) => n !== selected.name).map((n) => (n === "*" ? `group:${n}` : `device:${n}`))
    if (direction === "outgoing") {
      edges.push({ id: `${selfId}->${ruleId}`, source: selfId, target: ruleId, animated: true, className: "text-success", style: edgeStyle })
      targets.forEach((t) =>
        edges.push({ id: `${ruleId}->${t}`, source: ruleId, target: t, animated: true, className: "text-success", style: edgeStyle })
      )
    } else {
      targets.forEach((s) =>
        edges.push({ id: `${s}->${ruleId}`, source: s, target: ruleId, animated: true, className: "text-success", style: edgeStyle })
      )
      edges.push({ id: `${ruleId}->${selfId}`, source: ruleId, target: selfId, animated: true, className: "text-success", style: edgeStyle })
    }
  })
  return { nodes, edges }
}
