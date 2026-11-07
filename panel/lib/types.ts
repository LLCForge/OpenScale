// Shapes returned by the openscale panel API (internal/panel/api.go).

import type { Inventory, UpstreamInfo } from "@/lib/inventory-types"

export type AlertLevel = "danger" | "warning" | "info"

/** A coded, graded problem (F-193). Overview warnings use the same shape. */
export interface HealthAlert {
  code: string
  level: AlertLevel
  message: string
}

export type Warning = HealthAlert

export interface Overview {
  networkId: string
  version: number
  issuedAt: string
  expiresAt: string
  daysLeft: number
  dnsDomain: string
  ipv4Prefix: string
  ipv6Prefix: string
  rootFingerprint: string
  deviceCount: number
  exitNodeCount: number
  ruleCount: number
  revokedCount: number
  backupCount: number
  lastBackupAt: string | null
  warnings: Warning[]
  /** Network display name (F-160), "" when not set. */
  displayName: string
}

export type DeviceLiveStatus = "this" | "online" | "offline" | "unknown"

export interface Device {
  id: string
  name: string
  fqdn: string
  ipv4: string
  ipv6: string
  exitNode: boolean
  admin: boolean
  thisComputer: boolean
  status: DeviceLiveStatus
  lastSeen: string | null
  system: SystemInfo | null
  addedAt: string
  expiresAt: string
  daysLeft: number
  /** Tags (ADR-0021) without the "tag:" prefix. */
  tags: string[]
  /** Signed device type (#233, ADR-0232); "" or missing when none. */
  icon?: string
}

export interface Traffic {
  relayed: boolean
  endpoint: string
  lastHandshake: string | null
  rxBytes: number
  txBytes: number
}

export interface DeviceDetail extends Device {
  signingKey: string
  wireguardKey: string
  fingerprint: string
  dnsDomain: string
  outgoing: Rule[]
  incoming: Rule[]
  peers: { name: string; ipv4: string }[]
  direct: Traffic | null
  coordinator: Traffic | null
  liveAvailable: boolean
  /** False when exit users are restricted and this device is not one of them. */
  mayUseExitNode: boolean
}

export interface RevokedDevice {
  name: string
  revokedAt: string
}

export interface DevicesResponse {
  devices: Device[]
  revoked: RevokedDevice[]
  dnsDomain: string
  coordinator: CoordinatorLive | null
}

export interface SystemInfo {
  os: string
  osName: string
  version: string
  arch: string
  cpu: string
  cores: number
  memTotal: number
  memFree: number
  diskTotal: number
  diskFree: number
  uptime: number
  publicIp: string
  country: string
  reportedAt: string
  stale: boolean
  /** Older than this panel's OpenScale version (F-153). */
  outdated?: boolean
  /** The panel's version when outdated. */
  latest?: string
  /** Environment (F-172): container or VM kind, model, how OpenScale was installed. */
  virt?: string
  model?: string
  install?: string
  /** The device's own security posture statement (ADR-0109); display data, never proof. */
  posture?: PostureView
  /** OS from the detailed inventory ("Windows 11 Pro 26H2 (26300.9818)"); absent without one. */
  osLabel?: string
  /** Upstream exit of an exit node (ADR-0142). */
  upstream?: UpstreamInfo
  /** Detailed inventory (ADR-0143); only in the device detail answer. */
  detail?: Inventory
  /** The device announces an inventory this computer has not fetched yet. */
  detailPending?: boolean
}

export type PostureState = "on" | "off" | "unknown"

export interface PostureView {
  diskEncryption: PostureState
  firewall: PostureState
  /** Windows build number; absent elsewhere. */
  windowsBuild?: number
}

export interface CoordinatorLive {
  endpoint: string
  ipv4: string
  fingerprint: string
  publicIp: string
  country: string
  status: DeviceLiveStatus
  system: SystemInfo | null
}

export type Protocol = "tcp" | "udp" | "icmp" | "any"

/** A named protocol or a decimal IANA protocol number ("0"-"255"). */
export type RuleProtocol = Protocol | `${number}`

export type RuleAction = "allow" | "deny"

export interface Rule {
  index: number
  from: string[]
  to: string[]
  protocol: RuleProtocol
  ports: string[]
  description: string
  action: RuleAction
  disabled: boolean
  text: string
  /** Service rule (ADR-0030, ADR-0031): ssh, files, wake or speedtest; "" for traffic rules. */
  service?: string
  users?: string[] | null
  allowRoot?: boolean
  allowForward?: boolean
  via?: string[] | null
  /** rdesk (ADR-0055) and sync (ADR-0104, ADR-0110) rule fields. */
  allowControl?: boolean
  allowUnattended?: boolean
  folders?: string[] | null
  backup?: boolean
  quota?: number
  allowPrune?: boolean
  /** Also allows the reverse direction (ADR-0120). */
  bidirectional?: boolean
  /** End of a one-time access window (RFC 3339); absent when none. */
  notAfter?: string
  /** Limited to some hours or a start time; the edit form keeps these limits. */
  scheduled?: boolean
}

export interface Group {
  name: string
  /** Device names or "tag:x" references. */
  members: string[]
  /** Rules and exit user entries that refer to the group. */
  usedBy: number
}

export interface RulesResponse {
  rules: Rule[]
  devices: string[]
  groups: Group[]
  /** Tags carried by devices and pending invites. */
  tags: string[]
  /** Tags referenced by rules, groups or exit users but carried by nothing. */
  unusedTags: string[]
}

export interface Diff {
  from_version: number
  to_version: number
  added_devices: string[]
  removed_devices: string[]
  changed_devices: string[]
  added_rules: string[]
  removed_rules: string[]
  old_expires_at: string
  new_expires_at: string
  settings_changes: string[]
  /** Per-device details such as renames and key rotations; absent in old entries. */
  device_changes?: string[]
}

export interface ChangeResponse {
  dryRun: boolean
  diff: Diff
  lines: string[]
  version: number
}

export interface HistoryEntry {
  version: number
  issued_at: string
  expires_at: string
  devices: number
  rules: number
  diff?: Diff
}

export interface HistoryReport {
  entries: HistoryEntry[]
  problems: string[]
}

export interface CoordinatorInfo {
  endpoint: string
  wireguardKey: string
  fingerprint: string
  ipv4: string
  ipv6: string
}

export interface NetworkInfo {
  networkId: string
  version: number
  dnsDomain: string
  ipv4Prefix: string
  ipv6Prefix: string
  rootFingerprint: string
  dnsResolver: string
  coordinator: CoordinatorInfo | null
  bundle: string
  displayName: string
  dns: NetworkDns | null
  /** Resolvers that other devices cannot reach on port 53. */
  dnsWarnings: string[]
  /** Devices whose tunnel addresses may be chosen as resolvers. */
  resolvers: ResolverChoice[]
  exitUsers: ExitUsers
  /** Summary of the magic_dns section; absent from older servers. */
  magicDns?: MagicDnsSummary
}

export interface MagicDnsSummary {
  /** Domains appended to short names. */
  search: string[]
  /** Number of extra records under the network domain. */
  records: number
  deviceSubdomains: boolean
}

export interface SplitDns {
  domain: string
  nameservers: string[]
}

export interface NetworkDns {
  nameservers: string[]
  split: SplitDns[]
}

export interface ResolverChoice {
  name: string
  ipv4: string
  ipv6: string
}

export interface ExitUsers {
  /** False when every device may use exit nodes. */
  restricted: boolean
  users: string[]
}

export interface RotationInspectResponse {
  deviceName: string
  deviceId: string
  createdAt: string
}

export interface InspectResponse {
  suggestedName: string
  deviceId: string
  /** Short authentication string (ADR-0062), compared with the new device's screen. */
  sas?: string
}

export type AppMode = "setup" | "joining" | "member" | "admin"

export interface JoiningStatus {
  name: string
  shortCode: string
  waiting: boolean
  error: string
}

export interface PeerInfo {
  name: string
  ipv4: string
  fqdn: string
  online: boolean
  relayed: boolean
  pinned: boolean
  /** ISO country code of an exit node's public address, "" if unknown. */
  country: string
  /** Post-quantum PSK state (ADR-0033); "" while the tunnel is down. */
  postQuantum?: PostQuantumState
  /** Upstream exit of an exit node (ADR-0142), from its system report. */
  upstream?: UpstreamInfo
}

/** Post-quantum PSK state of a peer (ADR-0033). */
export type PostQuantumState = "" | "pq" | "negotiating" | "classical" | "unsupported" | "off"

/** Faz 4 tunnel options; durations in seconds, 0 = default. */
export interface TransportSettings {
  postQuantum: boolean
  pskRotationSec: number
  tcpFallback: string
  disableTcpFallback: boolean
  keepaliveSec: number
  adaptiveKeepalive: boolean
  lazyPeers: boolean
  lazyIdleSec: number
}

export interface DeviceStatus {
  name: string
  fqdn: string
  ipv4: string
  ipv6: string
  running: boolean
  connected: boolean
  documentVersion: number
  peers: PeerInfo[]
  exitNodes: PeerInfo[]
  exitNode: string
  exitNodeWanted: string
  killSwitch: boolean
  exitAllowLan: boolean
  killSwitchSupported: boolean
  killSwitchActive: boolean
  killSwitchError: string
  shields: boolean
  disconnectedUntil: string | null
  lastExitNode: string
  pinned: string[]
  membershipExpiresAt: string | null
  removed: boolean
  lastSync: string | null
  lastSyncError: string
  error: string
  /** This computer applies the network's DNS settings (F-065). */
  acceptNetworkDns: boolean
  networkDnsActive: boolean
  networkDnsError: string
  /** Tunnel MTU, 0 = default 1280. */
  mtu: number
  forceRelay: boolean
  /** Saved Faz 4 options (ADR-0032, ADR-0033). */
  transport?: TransportSettings
  /** UDP to the coordinator is blocked; control traffic uses TCP (ADR-0032). */
  coordinatorOverTcp?: boolean
}

export interface CoordinatorStatus {
  endpoint: string
  running: boolean
  error: string
  handoff: boolean
  /** Relay limit in bytes per second per device, 0 = default 20 MiB/s. */
  relayRate: number
  /** Relay burst in bytes, 0 = default 4 MiB. */
  relayBurst: number
  /** Saved TCP transport address, "" = off (ADR-0032). */
  tcpListen?: string
  /** Where the TCP transport listens now, "" when off. */
  tcpAddr?: string
  tcpMaxConns?: number
  tcpMaxConnsPerIp?: number
}

export interface AppStatus {
  mode: AppMode
  hostname: string
  suggestedEndpoint: string
  joining: JoiningStatus | null
  device: DeviceStatus | null
  coordinator: CoordinatorStatus | null
  error: string
  health: HealthAlert[]
  panelReadOnly: boolean
  /** Network display name (F-160), "" when not set. */
  networkName: string
}

/** Timed disconnect choices (F-121). */
export type DisconnectChoice = "5m" | "1h" | "morning"

export interface InviteInfo {
  id: string
  ipv4: string
  createdAt: string
  expiresAt: string
  used: boolean
  usedBy: string
  tags: string[]
  // Local note and uses of a multi-use invite (ADR-0028).
  note?: string
  maxUses?: number
  useCount?: number
}

export interface PendingEnrollment {
  // Tells the requests of a multi-use invite apart (ADR-0028).
  deviceId?: string
  inviteId: string
  hostname: string
  shortCode: string
  fingerprint: string
  requestedAt: string
  tags: string[]
}

export interface InvitesResponse {
  invites: InviteInfo[]
  pending: PendingEnrollment[]
  pendingError: string
}

export interface CreatedInvite {
  code: string
  expiresAt: string
}

export interface ServiceAccess {
  available: boolean
  port: number
  overlayOnly: boolean
}

export interface ListenerView {
  proto: string
  address: string
  port: number
  process: string
  exposure: "all" | "lan" | "openscale"
}

export interface LocalSecurity {
  supported: boolean
  rdp: ServiceAccess
  ssh: ServiceAccess
  listeners: ListenerView[]
  summary: { all: number; lan: number; openscale: number; local: number }
  checkedAt: string
  error: string
}
