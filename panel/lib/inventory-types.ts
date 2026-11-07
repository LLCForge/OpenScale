// Detailed system inventory (ADR-0143) and upstream exit (ADR-0142) as the
// panel API returns them. The inventory keys follow sysinfo.Detail's JSON
// form; empty strings and zero numbers mean "could not be read".

export interface InventoryOS {
  name?: string
  ver?: string
  build?: string
  edition?: string
  install_type?: string
  channel?: string
  kernel?: string
  arch?: string
  /** Unix seconds; approximate on Linux. */
  installed?: number
  boot?: number
  tz?: string
  tz_offset: number
}

export interface InventoryCPU {
  model?: string
  sockets?: number
  cores?: number
  threads?: number
  base_mhz?: number
  max_mhz?: number
  /** "on", "off", "hv" (a hypervisor runs) or absent when unknown. */
  virt?: string
}

export interface InventoryMemModule {
  size?: number
  type?: string
  mhz?: number
  form?: string
}

export interface InventoryMem {
  total?: number
  slots?: number
  modules?: InventoryMemModule[]
}

export interface InventoryBoard {
  vendor?: string
  model?: string
  board_vendor?: string
  board_model?: string
  bios_vendor?: string
  bios_ver?: string
  /** "YYYY-MM-DD". */
  bios_date?: string
  /** "uefi" or "bios". */
  fw?: string
  /** "on", "off" or "unsupported". */
  secure_boot?: string
  /** "2.0", "1.2" or "none". */
  tpm?: string
  tpm_vendor?: string
}

export interface InventoryGPU {
  model?: string
  driver?: string
  vram?: number
}

export interface InventoryDisk {
  idx: number
  model?: string
  /** "nvme", "ssd" or "hdd". */
  type?: string
  bus?: string
  size?: number
  removable?: boolean
}

export interface InventoryVolume {
  mount: string
  fs?: string
  size?: number
  free?: number
  /** "on", "off" or absent when unknown. */
  enc?: string
  removable?: boolean
  /** InventoryDisk.idx holding the volume, -1 when unknown. */
  disk: number
}

export interface InventoryNIC {
  name?: string
  model?: string
  /** "wifi", "ethernet", "virtual", "cellular", "bluetooth" or "other". */
  type?: string
  up?: boolean
  /** Mbit/s. */
  speed?: number
  ipv4?: string[]
  ipv6?: string[]
  gw?: boolean
  /** Wi-Fi signal quality in percent. */
  signal?: number
  wifi_std?: string
}

export interface InventoryBattery {
  pct: number
  /** "charging", "discharging", "full" or "ac". */
  state?: string
  design_mwh?: number
  full_mwh?: number
  health?: number
  cycles?: number
}

export interface InventoryDisplay {
  name?: string
  w: number
  h: number
  hz?: number
}

export interface Inventory {
  v: number
  /** Unix seconds of the hardware collection. */
  at: number
  os: InventoryOS
  cpu: InventoryCPU
  mem: InventoryMem
  board: InventoryBoard
  gpus?: InventoryGPU[]
  disks?: InventoryDisk[]
  vols?: InventoryVolume[]
  nics?: InventoryNIC[]
  bat?: InventoryBattery
  displays?: InventoryDisplay[]
  /** Users with a logon session; -1 when unknown. */
  users: number
}

export type UpstreamMode = "tunnel" | "blocked" | "direct" | "off"

/** What members exit through; absent when the exit node runs an older version. */
export type UpstreamKind = "tor" | "warp" | "mullvad" | "wireguard"

/** An exit node's upstream exit through an external WireGuard provider (ADR-0142). */
export interface UpstreamInfo {
  /** Provider profile label ("Mullvad · İsveç") or profile name. */
  label: string
  mode: UpstreamMode
  lastHandshake?: string
  kind?: UpstreamKind
}
