// Types of the membership endpoints (ADR-0027, ADR-0028).

export interface InactiveDeviceInfo {
  name: string
  lastSeen: string | null
  addedAt: string
  expiresAt: string
  days: number
  ephemeral: boolean
  admin: boolean
}

export interface LeaveRequestInfo {
  deviceId: string
  name: string
  requestedAt: string
}

export interface CloneAlertInfo {
  name: string
  flips: number
  endpoints: string[]
  first: string
  last: string
}

export interface MembershipResponse {
  inactiveDays: number
  inactive: InactiveDeviceInfo[]
  ephemeral: string[]
  leaves: LeaveRequestInfo[]
  alerts: CloneAlertInfo[]
  liveError: string
  minClientVersion: string
  recoveryKeys: number
  rootEpoch: number
}

export interface SignResult {
  version: number
  changes: string[]
}

export interface PreauthResult {
  key: string
  name: string
  ipv4: string
  expiresAt: string
}
