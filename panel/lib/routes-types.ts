// Types of the Routes page API (ADR-0133).

export interface RouteDevice {
  name: string
  ipv4: string
  routes: string[]
  /** Devices a rule lets reach this router's routes. */
  clients: string[]
}

export interface RouteExternalExit {
  name: string
  endpoint: string
  dns: string
  description: string
}

export interface RouteConflict {
  kind: "overlay" | "route"
  prefix: string
  message: string
}

export interface RoutesStatus {
  devices: RouteDevice[]
  externalExits: RouteExternalExit[]
  strategy: "first" | "sequential" | "random"
  reserved: string[]
  conflicts: RouteConflict[]
  routerSupported: boolean
}

export interface RouteInspect {
  device: string
  routes: string[]
  current: string[]
  issuedAt: string
}

const cidr4 = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/
const cidr6 = /^[0-9a-fA-F:]+\/\d{1,3}$/

/** Splits "a/24, b/16" into trimmed CIDR strings; returns null on a bad entry. */
export function parseRouteList(text: string): string[] | null {
  const items = text
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
  if (items.length > 32) {
    return null
  }
  for (const item of items) {
    if (!cidr4.test(item) && !cidr6.test(item)) {
      return null
    }
  }
  return items
}
