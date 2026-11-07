// Remote support toolbox (#852, ADR-0232): internal/support and
// internal/panel/f4a_api.go.

export type SupportKind = "processes" | "services" | "events" | "disks" | "startup"

export interface SupportProcess {
  pid: number
  name: string
  memory_kb: number
}

export interface SupportService {
  name: string
  display?: string
  state: string
  start?: string
}

export interface SupportEvent {
  time: string
  level: string
  source: string
  id?: number
  message: string
}

export interface SupportDisk {
  mount: string
  total_bytes: number
  free_bytes: number
}

export interface SupportStartupItem {
  name: string
  location: string
  command?: string
}

export interface SupportSnapshot {
  kind: SupportKind
  collected_at: string
  truncated: boolean
  processes?: SupportProcess[]
  services?: SupportService[]
  events?: SupportEvent[]
  disks?: SupportDisk[]
  startup?: SupportStartupItem[]
}

export interface SupportRuleState {
  read: boolean
  kill: boolean
}

export interface SupportRequest {
  id: string
  peer: string
  kill: boolean
  at: string
}

export interface SupportSession {
  id: string
  peer: string
  kill: boolean
  started: string
  lastUse: string
}

export interface SupportLogEvent {
  kind: string
  peer: string
  detail?: string
  at: string
}

export interface SupportLocalView {
  hosted: boolean
  pending: SupportRequest[]
  sessions: SupportSession[]
  log: SupportLogEvent[]
}
