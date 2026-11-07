// Types of the P02 endpoints (internal/panel/p02_api.go): "like this
// device", lost device, guests, two-part invites, invite launcher, nearby
// pairing, access requests and the connection card.

import { msg, tx } from "@/lib/i18n/i18n"
import type { Rule } from "@/lib/types"

/** GET /api/p02/devices/like: what the new device would copy from the source. */
export interface LikeSuggestion {
  source: string
  target: string
  tags: string[] | null
  groups: string[] | null
  /** rules[i].index is the suggestion's own order, not the document's. */
  rules: Rule[] | null
  exitUser: boolean
}

export interface ExposureRule {
  index: number
  description: string
  from: string[]
  to: string[]
  service?: string
  protocol?: string
  ports: string[] | null
  /** Removing the device leaves this rule empty. */
  onlyThisDevice: boolean
}

/** GET /api/p02/devices/lost */
export interface LostReport {
  name: string
  roles: string[] | null
  tags: string[] | null
  groups: string[] | null
  routes: string[] | null
  exitUser: boolean
  expiresAt: string
  outbound: ExposureRule[] | null
  inbound: ExposureRule[] | null
  lastSeen?: string | null
  ipv4: string
  checklist: string[] | null
}

export interface GuestView {
  tag: string
  inviteId?: string
  inviteExpiresAt?: string
  devices: string[]
  rules: Rule[]
  until?: string
  expired: boolean
}

export interface GuestsResponse {
  guests: GuestView[]
}

/** Prefix of the tags the guest wizard makes. */
export const GUEST_TAG_PREFIX = "konuk-"

export interface SplitInvite {
  partA: string
  partB: string
  expiresAt: string
}

export interface InviteLauncher {
  fileName: string
  /** File body, base64. */
  content: string
  expiresAt: string
}

export interface NearbyRequest {
  /** The enrollment request line (osreq1...). */
  request: string
  hostname: string
  deviceId: string
  from: string
  firstSeen: string
  lastSeen: string
}

export interface NearbyStatus {
  listening: boolean
  until?: string
  port: number
  requests: NearbyRequest[] | null
}

export interface AccessRequestBody {
  from: string
  to: string
  service?: string
  protocol?: string
  ports?: string[]
  users?: string[]
  hours: number
  reason?: string
  created_at: string
}

export interface AccessRequestEntry {
  id: string
  status: "pending" | "approved" | "rejected"
  receivedAt: string
  decidedAt?: string
  request?: AccessRequestBody
  /** Why the request no longer verifies (expired, unknown device). */
  error?: string
}

export interface AccessRequestsResponse {
  requests: AccessRequestEntry[]
}

export interface CardService {
  from: string[]
  label: string
  command?: string
  until?: string
  protocol?: string
  ports?: string[]
}

/** GET /api/p02/devices/card */
export interface ConnectionCard {
  name: string
  dnsName: string
  ipv4: string
  ipv6: string
  services: CardService[]
  /** Printable plain text. */
  text: string
  /** PNG data URL of the text. */
  qr?: string
}

/** "ssh, 8 saat" style summary of what a request or rule opens. */
export function accessSummary(r: { service?: string; protocol?: string; ports?: string[] | null; users?: string[] | null }): string {
  if (r.service) {
    const users = r.users && r.users.length > 0 ? ` (${r.users.join(", ")})` : ""
    const name = serviceNames[r.service]
    return `${name ? tx(name) : r.service}${users}`
  }
  const proto = (r.protocol || "tcp").toLocaleUpperCase("en")
  const ports = r.ports && r.ports.length > 0 ? r.ports.join(", ") : tx("tüm portlar")
  return `${proto} ${ports}`
}

const serviceNames: Record<string, string> = {
  ssh: "SSH",
  rdesk: msg("Uzak masaüstü"),
  files: msg("Dosya gönderme"),
  sync: msg("Eşitleme"),
  wake: msg("Uyandırma"),
  speedtest: msg("Hız testi"),
}
