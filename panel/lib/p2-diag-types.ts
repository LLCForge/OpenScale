// Types of the phase 2 diagnostics API (internal/panel/p2_diag_api.go):
// the flight recorder (#836), the layered troubleshooter (#835) and the
// settings that restart the connection (#799).

export interface FlightRecStats {
  entries: number
  bytes: number
  max_bytes: number
  max_age_s: number
  oldest?: string
  newest?: string
  dropped: number
  total: number
}

export interface FlightRecInfo {
  id: string
  at: string
  reason: string
  size: number
}

export interface FlightRecStatus {
  schema: number
  enabled: boolean
  stats: FlightRecStats
  stored: FlightRecInfo[]
  auto_freeze: boolean
  auto_every_s: number
  error?: string
}

export interface FlightRecFreezeReply {
  schema: number
  saved: FlightRecInfo
}

export type StepStatus = "pass" | "fail" | "warn" | "skip"

export type StepLayer = "interface" | "gateway" | "dns" | "coordinator" | "relay" | "peer"

export interface TroubleshootStep {
  layer: StepLayer | string
  status: StepStatus
  key: string
  vars?: Record<string, string>
  title: string
  detail?: string
  fix?: string
  code?: string
  peer?: string
  duration_ms: number
}

export interface TroubleshootReport {
  schema: number
  at: string
  ok: boolean
  first_failure: number
  steps: TroubleshootStep[]
}

export interface PrefMeta {
  key: string
  description: string
  restarts_connection: boolean
}

export interface PrefMetaReply {
  schema: number
  prefs: PrefMeta[]
  remote_session: boolean
}
