// Shapes of the P16 endpoints (internal/panel/p16_api.go, netmap.go,
// history.go, score.go).

export type MapPath = "direct" | "relay" | "none" | "unknown"

export interface MapNode {
  id: string
  name: string
  kind: "device" | "coordinator"
  ipv4: string
  os: string
  exitNode: boolean
  admin: boolean
  thisComputer: boolean
  status: "this" | "online" | "offline" | "unknown"
  tags: string[]
}

export interface MapEdge {
  from: string
  to: string
  /** An enabled rule allows traffic in at least one direction. */
  rule: boolean
  /** Tunnel-only link without a rule. */
  peer: "" | "admin" | "exit"
  path: MapPath
}

export interface MapResponse {
  nodes: MapNode[]
  edges: MapEdge[]
  live: boolean
}

export type CheckStatus = "pass" | "warn" | "fail" | "skip"

export interface ScoreCheck {
  id: string
  status: CheckStatus
  weight: number
  count?: number
  days?: number
  names?: string[]
}

export interface ScoreReport {
  score: number
  grade: "excellent" | "good" | "fair" | "weak"
  checks: ScoreCheck[]
  local: boolean
  checkedAt: string
}

export interface HistorySample {
  at: string
  path: "direct" | "relay" | "none"
  rttMs?: number
}

export interface PathChange {
  at: string
  endpoint: string
  relayed: boolean
}

export interface HistoryPeer {
  name: string
  samples: HistorySample[]
  changes: PathChange[]
}

export interface HistoryReply {
  schema: number
  intervalSec: number
  since: string
  now: string
  peers: HistoryPeer[]
}

export interface ImportResult {
  version: number
  issuedAt: string
  expiresAt: string
  expired: boolean
  displayName: string
  currentVersion: number
  relation: "same" | "older" | "newer" | "different"
  devices: string[]
  revoked: string[]
  rules: number
  sha256: string
  changes: string[]
}

export interface HelpDoc {
  slug: string
  title: string
  group: string
  source: string
  body: string
}

export interface HelpBundle {
  schema: number
  docs: HelpDoc[]
}
