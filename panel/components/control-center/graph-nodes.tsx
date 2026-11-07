"use client"

import { Handle, Position, type Node, type NodeProps } from "@xyflow/react"
import { Monitor, Network, Server } from "lucide-react"

import { useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

export type DeviceNodeData = {
  name: string
  ipv4: string
  exitNode: boolean
  selected?: boolean
}

export type RuleNodeData = {
  label: string
  detail: string
}

export type GroupNodeData = {
  label: string
  count: number
}

export type DeviceNode = Node<DeviceNodeData, "device">
export type RuleNode = Node<RuleNodeData, "rule">
export type GroupNode = Node<GroupNodeData, "group">

const handleClass = "!size-1.5 !min-w-0 !border-0 !bg-success/70"

export function DeviceNodeView({ data }: NodeProps<DeviceNode>) {
  const Icon = data.exitNode ? Server : Monitor
  return (
    <div
      className={cn(
        "flex w-56 items-center gap-3 rounded-lg border bg-card px-3 py-2.5 shadow-sm",
        data.selected && "border-primary/60 ring-2 ring-primary/20"
      )}
    >
      <Handle type="target" position={Position.Left} className={handleClass} />
      <span className="flex size-8 shrink-0 items-center justify-center rounded-md bg-secondary text-muted-foreground">
        <Icon className="size-4" />
      </span>
      <span className="flex min-w-0 flex-col">
        <span className="truncate text-sm font-medium">{data.name}</span>
        <span className="font-mono text-xs text-muted-foreground">{data.ipv4}</span>
      </span>
      <Handle type="source" position={Position.Right} className={handleClass} />
    </div>
  )
}

// Rule and group labels are Turkish msg() texts from build-graph (or a port
// list, which the dictionary leaves as it is).
export function RuleNodeView({ data }: NodeProps<RuleNode>) {
  const { t } = useI18n()
  return (
    <div className="flex items-center overflow-hidden rounded-full border bg-card text-xs shadow-sm">
      <Handle type="target" position={Position.Left} className={handleClass} />
      <span className="flex items-center gap-1.5 px-3 py-1.5 font-medium">
        <span className="size-1.5 rounded-full bg-success" aria-hidden="true" />
        {t(data.label)}
      </span>
      <span className="border-l px-2.5 py-1.5 font-mono text-muted-foreground">{t(data.detail)}</span>
      <Handle type="source" position={Position.Right} className={handleClass} />
    </div>
  )
}

export function GroupNodeView({ data }: NodeProps<GroupNode>) {
  const { t } = useI18n()
  return (
    <div className="flex w-44 items-center gap-3 rounded-lg border bg-card px-3 py-2.5 shadow-sm">
      <Handle type="target" position={Position.Left} className={handleClass} />
      <span className="flex size-8 shrink-0 items-center justify-center rounded-md bg-secondary text-muted-foreground">
        <Network className="size-4" />
      </span>
      <span className="flex flex-col">
        <span className="text-sm font-medium">{t(data.label)}</span>
        <span className="text-xs text-muted-foreground">{t("{count} cihaz", { count: data.count })}</span>
      </span>
      <Handle type="source" position={Position.Right} className={handleClass} />
    </div>
  )
}

export const nodeTypes = {
  device: DeviceNodeView,
  rule: RuleNodeView,
  group: GroupNodeView,
}
