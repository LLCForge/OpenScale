// Remote access and diagnostics (ADR-0030, ADR-0031): SSH, file inbox,
// Wake-on-LAN and speed test. Every action runs from this computer; the
// other device decides from the signed rules.

import { ApiError, fetcher } from "@/lib/api"
import { msg } from "@/lib/i18n/i18n"

export type RuleService = "ssh" | "files" | "wake" | "speedtest" | "rdesk" | "sync"

export interface ServiceState {
  hosted: boolean
  running: boolean
  address: string
  error: string
}

export interface AppsStatus {
  ssh: ServiceState
  files: ServiceState
  wake: ServiceState
  speedtest: ServiceState
  sshFingerprint: string
  pendingOffers: number
  sshSessions: number
}

export interface RemoteDevice {
  name: string
  ipv4: string
  fqdn: string
  sshUsers: string[]
  sshRoot: boolean
  sshForward: boolean
  canSend: boolean
  canSpeedtest: boolean
  wakeRelays: string[]
  wakeMac: string
  sshFingerprint: string
  sshPort: number
}

export interface InboxFile {
  name: string
  size: number
  from: string
  receivedAt: string
  executable: boolean
}

export interface PendingOffer {
  id: string
  from: string
  name: string
  size: number
  at: string
  expiresAt: string
}

export interface InboxView {
  files: InboxFile[]
  pending: PendingOffer[]
  autoAccept: string[]
}

export interface TransferStatus {
  id: string
  device: string
  name: string
  size: number
  sent: number
  state: "sending" | "done" | "failed"
  error: string
  startedAt: string
}

export interface WakeResult {
  relay: string
  mac: string
}

export interface SpeedResult {
  device: string
  direction: string
  bytes: number
  seconds: number
  mbps: number
}

export const SSH_PORT = 4022

/** Fetcher that turns "not the desktop app" (404) into null. */
export async function optionalFetcher<T>(path: string): Promise<T | null> {
  try {
    return await fetcher<T>(path)
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null
    throw err
  }
}

export function inboxFileUrl(name: string): string {
  return `/api/app/inbox/file?name=${encodeURIComponent(name)}`
}

/** The ssh command for a device, as the owner would type it. */
export function sshCommand(device: RemoteDevice): string {
  const user = device.sshUsers[0] ?? (device.sshRoot ? "root" : "kullanici")
  return `openscale ssh ${user}@${device.name}`
}

/** The equivalent OpenSSH command (port 4022, fingerprint from the panel). */
export function openSSHCommand(device: RemoteDevice): string {
  const user = device.sshUsers[0] ?? (device.sshRoot ? "root" : "kullanici")
  return `ssh -p ${device.sshPort} ${user}@${device.fqdn}`
}

/**
 * Upload a file as the raw request body. The CSRF token is read from the
 * session like every other change; the Origin header comes from the
 * browser.
 */
export async function uploadFile(device: string, file: File): Promise<{ id: string }> {
  const session = await fetcher<{ csrfToken: string }>("/api/session")
  const url = `/api/app/files/send?device=${encodeURIComponent(device)}&name=${encodeURIComponent(file.name)}`
  const res = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: { "Content-Type": "application/octet-stream", "X-CSRF-Token": session.csrfToken },
    body: file,
  })
  if (!res.ok) {
    let message: string = msg("Dosya gönderilemedi.")
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

export const MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024
