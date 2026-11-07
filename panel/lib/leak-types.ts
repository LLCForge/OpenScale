/** Leak test (#77) and captive portal exception (#85) of the desktop app. */

export type LeakLevel = "ok" | "info" | "warn" | "leak"

export interface LeakCheck {
  id: string
  level: LeakLevel
  title: string
  detail?: string
}

export interface LeakReport {
  schema: number
  at: string
  exit_node: string
  seen_ipv4?: string
  seen_ipv6?: string
  leak: boolean
  checks: LeakCheck[]
}

export interface CaptiveGrant {
  addrs: string[]
  until: string
}
