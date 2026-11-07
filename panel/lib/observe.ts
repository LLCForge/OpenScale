// Types of the local observability API (/api/app/diag/{denied,audit,
// observe,stream}; ADR-0105). Everything stays on this computer.

import { msg } from "@/lib/i18n/i18n"

export type DenyReason =
  | "no_rule"
  | "deny_rule"
  | "disabled_rule"
  | "shields"
  | "unknown_peer"
  | "not_for_device"
  | "exit_not_allowed"
  | "untracked"
  | "flow_limit"
  | "no_document"

export interface DeniedEntry {
  direction: "in" | "out"
  peer?: string
  /** Masked address; only when the other side is not a device. */
  remote?: string
  proto: string
  port?: number
  reason: DenyReason | string
  rule?: number
  why: string
  count: number
  first: string
  last: string
}

export interface DeniedReply {
  schema: number
  entries: DeniedEntry[]
  totals: Record<string, number>
}

export interface AuditRecord {
  seq: number
  at: string
  kind: string
  severity: "info" | "warning" | "critical"
  message: string
  prev: string
  hash: string
}

export interface AuditReport {
  ok: boolean
  records: number
  first_seq: number
  last_seq: number
  last_hash: string
  problems: string[]
  notes: string[]
}

export interface AuditReply {
  schema: number
  records: AuditRecord[]
  verify: AuditReport
}

export interface ObservePrefs {
  schema: number
  metrics: boolean
  notifications: boolean
  profiling: boolean
  profiling_until?: string
}

export interface StreamEvent {
  seq: number
  at: string
  kind: string
  category: "connection" | "security" | "device" | "killswitch"
  severity: string
  peer?: string
  message: string
  notify?: boolean
}

export const denyReasonLabels: Record<string, string> = {
  no_rule: msg("Kural yok"),
  deny_rule: msg("Reddet kuralı"),
  disabled_rule: msg("Devre dışı kural"),
  shields: msg("Kalkan"),
  unknown_peer: msg("Bilinmeyen kaynak"),
  not_for_device: msg("Yanlış adres"),
  exit_not_allowed: msg("Çıkış izni yok"),
  untracked: msg("İzlenmeyen yanıt"),
  flow_limit: msg("Tablo dolu"),
  no_document: msg("Belge yok"),
}

/** SWR keys the event stream refreshes. */
export const diagStreamKeys = [
  "/api/app/diag/events",
  "/api/app/diag/denied",
  "/api/app/diag/audit",
  "/api/app/status",
] as const
