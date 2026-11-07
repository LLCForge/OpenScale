// Types of the P10 platform endpoint (internal/panel/platform_api.go).

export interface PlatformCheck {
  area: string
  level: "ok" | "warn" | "error" | "repaired"
  /** Turkish, shown as is. */
  message: string
}

export interface PlatformStatus {
  schema: number
  os: {
    family: string
    version?: string
    build?: string
    patch?: string
    /** Windows: "Client", "Server" or "Server Core". */
    edition?: string
    arch: string
    server_core?: boolean
  }
  /** The build changed and a repair is pending. */
  os_update?: { from: string; to: string; detected_at: string }
  last_repair?: {
    at: string
    /** "os-update" or "manual". */
    reason: string
    from?: string
    to?: string
    checks: PlatformCheck[]
  }
  repairing?: boolean
  memory: {
    profile: "default" | "low" | string
    memory_limit?: number
    gc_percent?: number
    /** Live Go memory in bytes. */
    live: number
    budget?: number
    max_flows?: number
  }
  limits?: {
    /** "job" on Windows, "systemd" on Linux. */
    mechanism?: string
    memory_max?: number
    cpu_percent?: number
    applied?: boolean
    error?: string
  }
  wsl?: {
    installed?: boolean
    inside?: boolean
    version?: number
    mode?: string
    notes?: string[]
  }
  portable?: boolean
  notes?: string[]
}
