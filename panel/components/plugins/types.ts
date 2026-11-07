// Response shapes of the G7 endpoints (internal/panel/g7_api.go, ADR-0220).

import { msg } from "@/lib/i18n/i18n"

export interface Subscription {
  category: string
  url: string
  sha256: string
}

export interface BlockingPolicy {
  default: string[]
  tags?: Record<string, string[]>
  devices?: Record<string, string[]>
  exceptions?: string[]
  device_exceptions?: Record<string, string[]>
}

export interface BlockingSettings {
  subscriptions?: Subscription[]
  policy?: BlockingPolicy
  keep?: string[]
  block_doh?: string[]
}

export interface PluginPin {
  name: string
  module_sha256: string
  manifest_sha256: string
}

export interface PluginEntry {
  name: string
  version?: string
  description?: string
  hooks: string[]
  data: string[]
  data_labels: string[]
  on_error?: string
  module_sha256?: string
  manifest_sha256?: string
  pinned: boolean
  status: string
  status_label: string
  reason?: string
  memory_limit_mib: number
  call_timeout_ms: number
}

export interface PluginEvent {
  time: string
  plugin: string
  hook?: string
  kind: string
  detail?: string
}

export interface ListArtifact {
  category: string
  sha256: string
  size: number
  names: number
}

export interface AdblockStats {
  queries: number
  blocked: Record<string, number>
  excepted: number
  kept: number
}

export interface ExtensionsRuntime {
  active: boolean
  version: number
  error?: string
  adblock?: AdblockStats
  lists: ListArtifact[]
  plugins: PluginEntry[]
  plugin_events: PluginEvent[]
  onion: number
  doh: number
  plugin_blocked: number
  plugin_allowed: number
  plugin_rewritten: number
}

export interface ExtensionsView {
  blocking: BlockingSettings | null
  pins: PluginPin[]
  runtime: ExtensionsRuntime
  categories: string[]
  exit_nodes: string[]
}

export interface AllowOnce {
  device?: string
  name: string
  until: string
}

export interface TopView {
  active: boolean
  until?: string
  names: { name: string; count: number }[]
  once: AllowOnce[]
}

export interface MonitorService {
  name: string
  state: string
  since: string
  downtime_sec: number
  last_error?: string
  last_latency_ms: number
}

export interface MonitorDevice {
  name: string
  watched: boolean
  online: boolean
  last_seen?: string
  warnings: string[]
}

export interface MonitorView {
  services: MonitorService[]
  devices: MonitorDevice[]
}

export interface NotifyChannel {
  kind: string
  label: string
  min_priority?: string
  max_per_hour?: number
  url?: string
  token?: string
  room?: string
  devices?: string[]
  smtp_addr?: string
  from?: string
}

export interface NotifyConfig {
  schema: number
  channels: NotifyChannel[]
  quiet_start?: string
  quiet_end?: string
  time_zone?: string
  dedupe_minutes?: number
  weekly_report?: boolean
  report_day?: number
  report_hour?: number
}

export interface QualityPoint {
  at: string
  samples: number
  lossPct: number
  /** Nanoseconds (Go time.Duration). */
  avgRtt: number
  minRtt: number
  maxRtt: number
}

export interface SpeedResult {
  target: string
  at: string
  downloadMbps: number
  uploadMbps: number
  error?: string
}

/** Turkish names of the blocking categories (internal/adblock). */
export const categoryLabels: Record<string, string> = {
  ads: msg("Reklamlar"),
  trackers: msg("İzleyiciler"),
  miners: msg("Kripto madencileri"),
  iot: msg("Akıllı TV ve IoT"),
  "os-telemetry": msg("İşletim sistemi telemetrisi"),
}
