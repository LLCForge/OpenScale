"use client"

import Link from "next/link"
import useSWR from "swr"
import { Info } from "lucide-react"

import { withNodes } from "@/components/devices/detail-card"
import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { DeviceDetail, DevicesResponse } from "@/lib/types"

/**
 * Explains why a device cannot use the network's exit nodes when exit
 * users are restricted (ADR-0021) and it is not one of them.
 */
export function ExitAccessNote({ device }: { device: DeviceDetail }) {
  const { t } = useI18n()
  const { data } = useSWR<DevicesResponse>("/api/devices", fetcher)
  const exitNodes = (data?.devices ?? []).filter((d) => d.exitNode && d.name !== device.name)
  if (device.mayUseExitNode || exitNodes.length === 0) return null
  return (
    <p className="flex gap-2 py-2.5 text-xs leading-relaxed text-muted-foreground text-pretty">
      <Info className="mt-0.5 size-3.5 shrink-0" />
      <span>
        {withNodes(
          t(
            "Bu cihaz ağdaki çıkış düğümlerini ({names}) kullanamaz: çıkış düğümü kullanıcıları sınırlı ve bu cihaz listede yok. Değiştirmek için {link} sayfasındaki \"Çıkış düğümü kullanıcıları\" ayarını kullan.",
            { names: exitNodes.map((d) => d.name).join(", ") },
          ),
          {
            link: (
              <Link href="/network" className="underline underline-offset-3 hover:text-foreground">
                {t("Ağ")}
              </Link>
            ),
          },
        )}
      </span>
    </p>
  )
}
