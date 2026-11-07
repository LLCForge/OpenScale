// Types of the P07 endpoints (internal/panel/p07_api.go, p07_net_api.go,
// p07_file_api.go): sync guard, pause and backup probe; dynamic DNS; timed
// file links, antivirus scan of received files; subnet inventory and
// container serve suggestions. Every answer carries schema: 1. None of them
// changes the network document.

export interface SyncPauseView {
  /** owner, edge:game, edge:metered or another code-side reason. */
  reason: string
  label: string
  since?: string
  until?: string
}

export interface SyncAlarm {
  since: string
  /** "local" or "peer:<device>". */
  source: string
  reason: string
  files: number
  modified: number
  deleted: number
  added: number
  ext_changed: number
  sampled: number
  high_entropy: number
  bad_magic: number
  examples?: string[]
}

export interface SyncGuardFolder {
  id: string
  guard_off?: boolean
  alarm?: SyncAlarm
  error?: string
}

export interface BackupProbeFolder {
  folder: string
  ok: boolean
  error?: string
  snapshot?: string
  snapshot_time?: string
  snapshots: number
  files: number
  checked: number
  bytes: number
  missing: number
  problems?: { path: string; reason: string }[]
}

export interface BackupProbe {
  at: string
  target: string
  ok: boolean
  error?: string
  folders: BackupProbeFolder[]
}

export interface SyncGuardStatus {
  schema: number
  paused: boolean
  pauses: SyncPauseView[] | null
  folders: SyncGuardFolder[] | null
  probe?: BackupProbe
  probe_hours: number
}

export interface DDNSCheck {
  at: string
  host: string
  resolved?: string[]
  observed?: string
  status: "ok" | "stale" | "unresolved" | "unknown"
  message: string
}

export interface DDNSUpdater {
  enabled: boolean
  server?: string
  zone?: string
  name?: string
  ttl?: number
  key_name?: string
  algorithm?: string
  key_set: boolean
  published?: string
  published_at?: string
  last_try?: string
  last_error?: string
  current?: string
}

export interface DDNSStatus {
  schema: number
  check?: DDNSCheck
  updater: DDNSUpdater
}

export interface FileLink {
  id: string
  name: string
  path: string
  device: string
  size: number
  created: string
  expires: string
  max_downloads: number
  downloads: number
}

export interface FileLinksStatus {
  schema: number
  links: FileLink[] | null
  served: boolean
  note?: string
}

export interface FileLinkCreated {
  schema: number
  link: FileLink
  /** Holds the secret; shown only once. */
  url: string
}

export interface FileScanResult {
  name: string
  scanner: string
  verdict: "clean" | "infected" | "error" | "unavailable"
  detail?: string
  at: string
}

export interface FileScanStatus {
  schema: number
  available: boolean
  scanner?: string
  enabled: boolean
  cloud_note?: string
  results: FileScanResult[] | null
}

export interface SubnetDevice {
  addr: string
  mac: string
  vendor?: string
  random_mac?: boolean
  prefix: string
  /** A /32 or /128 for a rule that names only this device. */
  rule: string
}

export interface SubnetInventory {
  schema: number
  routed: string[] | null
  devices: SubnetDevice[] | null
  note?: string
}

export interface ServeSuggestion {
  container: string
  image?: string
  name: string
  type: string
  target?: string
  problem?: string
  published: boolean
}

export interface ServeSuggestions {
  schema: number
  available: boolean
  socket?: string
  error?: string
  suggestions: ServeSuggestion[] | null
}
