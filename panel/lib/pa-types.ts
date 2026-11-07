// Types for the G1, G2 and G4 panel endpoints (panel-devir-G1/G2/G4.md).
// Field names follow the Go JSON tags exactly.

// i18n-ignore: sunucunun gönderdiği değerler, ekranda tabloyla gösterilir
export type RiskLevel = "düşük" | "orta" | "yüksek" | "kritik"

export interface RiskItem {
  text: string
  points: number
  widens: boolean
}

export interface RiskReport {
  score: number
  level: RiskLevel
  widens: boolean
  summary: string
  items: RiskItem[]
}

export interface GrantRecord {
  id: string
  name: string
  key: string
  issued_at: string
  not_after: string
  operations: string[] | null
  tags: string[] | null
  /** "piv:1234", "openpgp:5678", "token" or absent. */
  token?: string
}

export interface AdminList {
  schema: number
  grants: GrantRecord[]
  revoked: string[]
  expired: string[]
}

export interface PIIWarning {
  field: string
  value: string
  kind: string
}

export interface SensitiveState {
  devices: string[] | null
  approved: string[] | null
  needed: number
  complete: boolean
  fingerprint: string
}

export interface EmergencyRecord {
  kind: "lockdown" | "remove"
  device?: string
  base_version: number
  version: number
  prepared_at: string
  expires_at?: string
  needs_approvals?: boolean
  stale: boolean
  expired: boolean
}

export type CanaryState = "valid" | "expiring" | "expired" | "invalid" | "missing"

export interface CanaryReply {
  schema: number
  state: CanaryState
  label: string
  seq?: number
  issuedAt?: string
  notAfter?: string
  statement?: string
  /** The signed file, base64. */
  canary?: string
}

export interface SealedBlobReply {
  schema: number
  valid: boolean
  error?: string
  kind?: string
  seq?: number
  issuedAt?: string
  signer?: string
  size?: number
}

export interface IndependenceFinding {
  kind: string
  severity: "info" | "warning" | string
  coordinators: string[] | null
  message: string
}

export interface IndependenceReply {
  schema: number
  coordinators: { label: string; region: string }[] | null
  findings: IndependenceFinding[] | null
}

export interface AboutInfo {
  schema: number
  version: string
  label: string
  channel: "stable" | "beta" | "dev" | string
  build: string
  update_channel: "stable" | "beta" | string
}

export interface AutostartEntry {
  scope: "user" | "all"
  path?: string
  installed: boolean
  ours: boolean
}

export interface AutostartInfo {
  schema: number
  entries: AutostartEntry[]
}

export interface DiscreetInfo {
  schema: number
  supported: boolean
  enabled: boolean
  name: string
}

export interface AuthStatus {
  signed_in: boolean
  remote: boolean
  admin_mode: boolean
  admin_active: boolean
  admin_left_sec: number
  admin_token: boolean
}
