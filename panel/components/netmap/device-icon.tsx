import { Laptop, Monitor, MonitorSmartphone, RadioTower, Server, Smartphone, type LucideIcon, type LucideProps } from "lucide-react"

import type { DeviceKind } from "@/lib/device-kind"

const icons: Record<DeviceKind, LucideIcon> = {
  coordinator: RadioTower,
  phone: Smartphone,
  server: Server,
  laptop: Laptop,
  desktop: Monitor,
  unknown: MonitorSmartphone,
}

/** Decorative icon for a device type; the label carries the meaning. */
export function DeviceIcon({ kind, ...props }: { kind: DeviceKind } & LucideProps) {
  const Icon = icons[kind]
  return <Icon aria-hidden="true" {...props} />
}
