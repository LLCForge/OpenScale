import { AppWindow, Cpu, Smartphone } from "lucide-react"

import { tx } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

// Operating system logos from simple-icons (CC0-1.0), copied to public/os by
// scripts/copy-os-icons.mjs. simple-icons has no Windows logo, so Windows
// uses a generic window icon. Keep the names in step with that script.

/** Distribution keywords checked in order against the detailed OS name. */
const linuxDistros: { match: RegExp; icon: string }[] = [
  { match: /linux\s*mint/i, icon: "linuxmint" },
  { match: /ubuntu/i, icon: "ubuntu" },
  { match: /raspbian|raspberry/i, icon: "raspberrypi" },
  { match: /debian/i, icon: "debian" },
  { match: /fedora/i, icon: "fedora" },
  { match: /centos/i, icon: "centos" },
  { match: /red\s*hat|rhel/i, icon: "redhat" },
  { match: /arch\s*linux|^arch\b/i, icon: "archlinux" },
  { match: /alpine/i, icon: "alpinelinux" },
  { match: /suse/i, icon: "opensuse" },
]

/** File name in public/os for an OS, "windows" for the generic Windows icon, or null when unknown. */
export function osIconName(os: string, osName?: string): string | null {
  const id = os.toLowerCase()
  const name = osName ?? ""
  switch (id) {
    case "windows":
      return "windows"
    case "darwin":
    case "macos":
    case "ios":
      return "apple"
    case "android":
      return "android"
    case "freebsd":
      return "freebsd"
    case "openbsd":
      return "openbsd"
    case "linux":
      return linuxDistros.find((d) => d.match.test(name))?.icon ?? "linux"
  }
  if (/windows/i.test(name)) return "windows"
  if (/mac\s*os|ios/i.test(name)) return "apple"
  return null
}

const genericNames: Record<string, string> = {
  windows: "Windows",
  darwin: "macOS",
  linux: "Linux",
  android: "Android",
  ios: "iOS",
  freebsd: "FreeBSD",
  openbsd: "OpenBSD",
}

/**
 * The detailed OS name the device reported ("Windows 11 Pro 25H2 (26300)",
 * "Debian GNU/Linux 13 (trixie)"), else a generic name from the OS id.
 * The reported text is shown as is, build number included.
 */
export function osDisplayName(os: string, osName?: string): string {
  const reported = (osName ?? "").trim()
  if (reported) return reported
  return genericNames[os.toLowerCase()] ?? (os || tx("Bilinmiyor"))
}

interface OsIconProps {
  os: string
  osName?: string
  className?: string
  /**
   * Accessible name. Leave empty when the OS name is written next to the
   * icon; the icon is then hidden from screen readers.
   */
  label?: string
}

/**
 * One-color OS logo that follows the text color: the SVG is used as a CSS
 * mask over currentColor, so it suits both themes. 16px by default.
 */
export function OsIcon({ os, osName, className, label }: OsIconProps) {
  const icon = osIconName(os, osName)
  const a11y = label ? { role: "img" as const, "aria-label": label } : { "aria-hidden": true as const }
  if (icon === null || icon === "windows") {
    const Fallback = icon === "windows" ? AppWindow : os === "android" || os === "ios" ? Smartphone : Cpu
    return <Fallback className={cn("size-4 shrink-0 text-muted-foreground", className)} {...a11y} />
  }
  return <MaskIcon name={icon} className={className} {...a11y} />
}

/**
 * A logo from public/os drawn in currentColor through a CSS mask. Also used
 * for the environment ("docker") on the device page.
 */
export function MaskIcon({ name, className, ...a11y }: { name: string; className?: string } & React.AriaAttributes & { role?: "img" }) {
  const url = `url("/os/${name}.svg")`
  return (
    <span
      {...a11y}
      className={cn("inline-block size-4 shrink-0 bg-current text-muted-foreground", className)}
      style={{
        maskImage: url,
        WebkitMaskImage: url,
        maskRepeat: "no-repeat",
        WebkitMaskRepeat: "no-repeat",
        maskPosition: "center",
        WebkitMaskPosition: "center",
        maskSize: "contain",
        WebkitMaskSize: "contain",
      }}
    />
  )
}
