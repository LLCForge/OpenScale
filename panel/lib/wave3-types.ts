// Connection wave 3 types (internal/panel/wave3_types.go, wave3_api.go).

export interface ExitAutoSettings {
  mode: "" | "failover" | "fastest"
  candidates: string[]
  untrusted: boolean
  trustedWifi: string[]
  trustWired: boolean
  except: string[]
}

export interface ExitAutoState {
  settings: ExitAutoSettings
  exit: string
  reason: string
  since?: string
  networks: string[]
}

export interface CoordinatorState {
  name: string
  region: string
  fingerprint: string
  endpoint: string
  primary: boolean
  active: boolean
  relay: boolean
  until?: string
  rttMs: number
  lastReply?: string
  failures: number
}

export interface IntegrityNote {
  severity: string
  coordinator?: string
  peer?: string
  text: string
  verified: boolean
}

export interface Wave3Status {
  exitAuto?: ExitAutoState
  coordinators: CoordinatorState[]
  integrity: IntegrityNote[]
  profile: string
  profiles: { name: string; displayName: string; active: boolean; joined: boolean }[]
}

export interface CoordinatorEntry {
  name: string
  region: string
  endpoint: string
  fingerprint: string
  primary: boolean
  until?: string
  expired: boolean
}

export interface CoordinatorsResponse {
  coordinators: CoordinatorEntry[]
  device: Wave3Status | null
}

export interface ApprovalResponse {
  threshold: number
  approvers: { name: string; fingerprint: string }[]
  hardware: { tpm: string; tpmNote: string; piv: string[]; pivNote: string } | null
}
