// Types of the P12 endpoints (internal/panel/p12_api.go): the stable error
// code catalog (ADR-0165), the readable network report, per-device traffic
// history and OpenScale's own resource use. Every endpoint only reads.

import { msg } from "@/lib/i18n/i18n"

export interface ErrorCodeEntry {
  code: string
  /** belge, uyelik, baglanti, dns, kill-switch, sistem or panel. */
  area: string
  title: string
  cause: string
  steps: string[]
  commands?: string[]
  /** Anchor in docs/sorun-giderme.md, e.g. "sorun-giderme.md#os-3001". */
  doc: string
  since: number
  deprecated?: boolean
}

export interface ErrorCatalog {
  schema: number
  catalog: number
  codes: ErrorCodeEntry[]
}

/** Area names shown above the grouped code list. */
export const errorAreaLabels: Record<string, string> = { // i18n-ignore: anahtarlar sunucu alan kimlikleri, değerler msg()
  belge: msg("Ağ belgesi ve kök anahtar"),
  uyelik: msg("Üyelik ve davetler"),
  baglanti: msg("Bağlantı ve NAT"),
  dns: "DNS",
  "kill-switch": msg("Sızıntı kilidi (kill switch) ve güvenlik duvarı"),
  sistem: msg("Yetki, port ve dosyalar"),
  panel: msg("Panel ve yerel API"),
}

export interface ReportDevice {
  name: string
  ipv4: string
  roles: string
  tags: string
  expires: string
  routes?: string
  ephemeral?: boolean
}

export interface ReportRule {
  number: number
  sentence: string
  allow: boolean
  disabled?: boolean
}

export interface NetworkReport {
  schema: number
  network: string
  domain: string
  version: number
  issuedAt: string
  expiresAt: string
  createdAt: string
  ipv4Prefix: string
  ipv6Prefix: string
  devices: ReportDevice[]
  groups: { name: string; members: string }[]
  rules: ReportRule[]
  exitUsers: string
  dns: string[]
  coordinators: { name: string; endpoint: string; region?: string }[]
}

export interface TrafficPoint {
  hour: string
  rx: number
  tx: number
}

export interface TrafficHistory {
  schema: number
  hours: number
  device?: string
  devices: { name: string; rx: number; tx: number }[]
  points?: TrafficPoint[]
}

export interface ResourceSample {
  at: string
  cpuPercent: number
  cpuSeconds: number
  heapBytes: number
  sysBytes: number
  goroutines: number
  onBattery?: boolean
  percent?: number
}

export interface ResourceUsage {
  schema: number
  sampleEverySeconds: number
  summary: {
    samples: number
    avgCpuPercent: number
    maxCpuPercent: number
    maxHeapBytes: number
    lastSysBytes: number
    cpuSecondsOnBattery: number
    /** Share of samples taken on battery, 0-1; absent without a battery. */
    batteryShare?: number
    cpuTimeKnown: boolean
  }
  samples: ResourceSample[]
}
