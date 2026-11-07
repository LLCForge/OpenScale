// Types and helpers of connection wave 2 (ADR-0110): remote desktop
// service, folder sync and backup, traffic shaping, key hardening and
// threat detection. They mirror internal/panel/*_types.go.

import { ApiError, fetcher } from "@/lib/api"
import { msg, tx } from "@/lib/i18n/i18n"

export interface RDeskSession {
  id: string
  peer: string
  mode: "view" | "control" | string
  unattended: boolean
  code: string
  recording: boolean
  clipboard: boolean
  blank: boolean
  inputLock: boolean
  started: string
  ended?: string
  reason?: string
}

export interface RDeskSettings {
  recording: boolean
  recordingDays: number
  localLock: boolean
  power: boolean
  /** Folders a control session with a files rule may browse (ADR-0146). */
  fileRoots?: string[]
}

export interface RDeskStatus {
  supported: boolean
  hosted: boolean
  running: boolean
  error: string
  runner: string
  settings: RDeskSettings
  sessions: RDeskSession[]
  recent: RDeskSession[]
}

export interface SyncFolderView {
  id: string
  path: string
  mode: "sendreceive" | "sendonly" | "receiveonly" | string
  peers: string[]
  propagateDeletes: boolean
  versions: number
  servedTo: string[]
  readable: string[]
  lastPull?: string
  lastError?: string
  fetched: number
  deleted: number
  conflicts: number
  failed: number
}

export interface SyncBackupView {
  enabled: boolean
  target: string
  folders: string[]
  intervalHours: number
  keyFingerprint: string
  keyExported: boolean
  keyExportedAt?: string
  lastRun?: string
  lastError?: string
  lastSnapshot?: string
}

export interface OutboxView {
  id: string
  peer: string
  name: string
  size: number
  strip: string
  queued: string
  attempts: number
  nextTry: string
  lastError?: string
}

export interface SyncStatus {
  hosted: boolean
  running: boolean
  error: string
  intervalSec: number
  folders: SyncFolderView[]
  backup: SyncBackupView
  backupTargets: string[]
  outbox: OutboxView[]
}

export interface SyncVersion {
  path: string
  stored: string
  time: string
  size: number
}

export interface SyncSnapshot {
  folder: string
  name: string
  time: string
}

export interface TrafficSettings {
  portMap: boolean
  portMapDisable: string[]
  padding: "off" | "buckets" | "mtu" | string
  coverTraffic: number
  interactivePriority: boolean
  torSocks: string
}

export interface TrafficCost {
  padding: string
  paddingPercent: number
  coverTraffic: number
  packetsPerHour: number
  bytesPerDay: number
  bytesPer30Days: number
  mtu: number
  ack: string
}

export interface PortMapView {
  enabled: boolean
  active: boolean
  protocol?: string
  external?: string
  renewAt?: string
  lastError?: string
}

export interface ShapingView {
  padding: string
  paddedPackets: number
  paddingBytes: number
  coverRate: number
  coverPackets: number
  coverBytes: number
  interactivePriority: boolean
}

export interface TrafficStatus {
  settings: TrafficSettings
  cost: TrafficCost
  portMap: PortMapView | null
  shaping: ShapingView | null
  torActive: boolean
}

export interface GuardSettings {
  exitDnsUpstream: string
  exitDnsBlocklist: string
  dnssecTrustAnchors: string
  threatScan: boolean
  threatBlock: boolean
  blockForSec: number
  canaryPorts: number[]
}

export interface ThreatView {
  kind: string
  peer?: string
  count?: number
  port?: number
  canary?: string
  at: string
  blockedUntil?: string
}

export interface GuardStatus {
  settings: GuardSettings
  running: boolean
  dnssec: { secure: number; insecure: number; bogus: number }
  threats: ThreatView[]
  blocked: { peer: string; until: string }[]
}

export interface DoHFinding {
  browser: string
  profile: string
  mode: string
  resolver?: string
  bypass: boolean
}

export const threatKindText: Record<string, string> = {
  inbound_scan: msg("Gelen port taraması"),
  outbound_scan: msg("Bu cihazdan ağ taraması"),
  canary_address: msg("Tuzak adrese erişim"),
  canary_port: msg("Tuzak porta erişim"),
}

export function modeText(mode: string): string {
  return mode === "control" ? tx("izleme ve kontrol") : tx("yalnızca izleme")
}

/**
 * Queues a file for a device: it is sent when the device is reachable
 * (offline queue, #140), optionally without image metadata (#139).
 */
export async function queueFile(device: string, file: File, strip: "" | "location" | "all"): Promise<{ id: string }> {
  const session = await fetcher<{ csrfToken: string }>("/api/session")
  const params = new URLSearchParams({ device, name: file.name })
  if (strip) params.set("strip", strip)
  const res = await fetch(`/api/app/files/queue?${params.toString()}`, {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: { "Content-Type": "application/octet-stream", "X-CSRF-Token": session.csrfToken },
    body: file,
  })
  if (!res.ok) {
    let message: string = msg("Dosya kuyruğa alınamadı.")
    try {
      const data: unknown = await res.json()
      if (data && typeof data === "object" && "error" in data && typeof data.error === "string") message = data.error
    } catch {
      // Not JSON; keep the generic message.
    }
    throw new ApiError(message, res.status)
  }
  return (await res.json()) as { id: string }
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  const units = ["KiB", "MiB", "GiB", "TiB"]
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(1)} ${units[i]}`
}
