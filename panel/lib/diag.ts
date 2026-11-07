// Types of the diagnostics API (/api/app/diag/*). The server answers with
// a versioned document; `schema` is 1 for every type below.

export interface CaptiveStatus {
  checked: string
  detected: boolean
  gateway?: string
  http_status?: number
  location?: string
  reason?: string
}

export interface PeerObservation {
  peer: string
  seen_as: string
  at: string
}

export interface NetReport {
  schema: number
  at: string
  coordinator_reachable: boolean
  /** Nanoseconds (Go time.Duration). */
  coordinator_rtt: number
  coordinator_over_ipv6: boolean
  coordinator_features: string[] | null
  mapped_endpoint: string
  local_port: number
  port_preserved: boolean
  mapping_changes: number
  nat: string
  observations: PeerObservation[] | null
  have_ipv4: boolean
  have_ipv6: boolean
  local_candidates: string[] | null
  direct_peers: number
  relayed_peers: number
  ipv6_peers: number
  force_relay: boolean
  captive_portal: CaptiveStatus
  notes: string[] | null
  last_sync_error?: string
  document_version: number
  coordinator_error?: string
}

export interface EndpointChange {
  at: string
  endpoint: string
  relayed: boolean
}

export interface PeerPath {
  name: string
  id: string
  endpoint: string
  relayed: boolean
  class: string
  last_handshake: string
  observed?: string
  candidates?: string[]
  best_probed?: string
  /** Nanoseconds (Go time.Duration). */
  probe_rtt?: number
  probed_at?: string
  next_probe?: string
  history?: EndpointChange[]
  post_quantum: string
  psk_since?: string
  /** Why a relayed peer uses the relay (#394): forced, udp_blocked, no_candidates, direct_timeout. */
  relay_reason?: string
  /** What could give the peer a direct path (#394). */
  relay_hint?: string
}

export interface PathsReply {
  schema: number
  peers: PeerPath[]
}

export interface DiagEvent {
  at: string
  kind: string
  peer?: string
  message: string
}

export interface EventsReply {
  schema: number
  events: DiagEvent[]
}

export interface PingResult {
  schema: number
  peer: string
  ipv4: string
  path: "direct" | "relay" | "none"
  endpoint?: string
  rtt_ms?: number
  method?: "icmp" | "relay" | "probe"
  error?: string
}

export interface RelayReply {
  schema: number
  peer: string
  rtt_ms: number
}

/** Go's zero time ("0001-01-01T00:00:00Z") means "never". */
export function isZeroTime(iso: string | undefined): boolean {
  return !iso || iso.startsWith("0001-")
}

export function nsToMs(ns: number | undefined): string {
  if (!ns) return "-"
  return `${(ns / 1e6).toFixed(1)} ms`
}
