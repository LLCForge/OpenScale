"use client"

import useSWR from "swr"

import { CopyButton } from "@/components/copy-field"
import { headCell, ListTable } from "@/components/settings/list-table"
import { EmptyNote, SettingBadge } from "@/components/settings/settings-layout"
import { DetailSection } from "@/components/devices/detail-card"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { ApiError, fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { SubnetInventory } from "@/lib/p07-types"
import { cn } from "@/lib/utils"

// Devices behind a subnet this computer routes (#442): read from this
// computer's neighbor table. Nothing is sent to the network and nothing
// leaves this computer.

/** Only the vendor part of a MAC address is shown (PRODUCT.md, privacy). */
function maskMac(mac: string): string {
  const parts = mac.split(/[:-]/)
  return parts.length >= 3 ? `${parts.slice(0, 3).join(":")}:…` : "…"
}

export function SubnetInventorySection() {
  const { t, ts } = useI18n()
  const { data, error } = useSWR<SubnetInventory>("/api/app/routes/inventory", fetcher, {
    refreshInterval: 60_000,
    shouldRetryOnError: (err: unknown) => !(err instanceof ApiError && err.status === 404),
  })
  if (error instanceof ApiError && error.status === 404) return null
  // Only a computer that routes a subnet has anything to show.
  if (!data || ((data.routed ?? []).length === 0 && !data.note)) return null

  const devices = data.devices ?? []
  return (
    <DetailSection
      // i18n-ignore: bağlantı kimliği, görünmez
      id="alt-ag-cihazlari"
      title={t("Alt ağdaki cihazlar")}
      description={t(
        "Liste bu bilgisayarın komşu tablosundan okunur; ağa paket gönderilmez ve başka cihaza iletilmez. Yalnızca yakın zamanda konuşulan cihazlar görünür."
      )}
      framed={false}
    >
      {data.note ? (
        <EmptyNote>{ts(data.note)}</EmptyNote>
      ) : devices.length === 0 ? (
        <EmptyNote>{t("Yönlendirilen ağlarda ({networks}) henüz konuşulan cihaz yok.", { networks: (data.routed ?? []).join(", ") })}</EmptyNote>
      ) : (
        <ListTable label={t("Alt ağdaki cihazlar")}>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className={headCell}>{t("Adres")}</TableHead>
              <TableHead className={cn(headCell, "hidden sm:table-cell")}>{t("MAC (üretici)")}</TableHead>
              <TableHead className={cn(headCell, "hidden md:table-cell")}>{t("Üretici")}</TableHead>
              <TableHead className={cn(headCell, "hidden md:table-cell")}>{t("Ağ")}</TableHead>
              <TableHead className="w-40 text-right">
                <span className="sr-only">{t("Kural için")}</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {devices.map((d) => (
              <TableRow key={d.addr}>
                <TableCell>
                  <div className="flex flex-col gap-1">
                    <span className="font-mono text-[0.8125rem]">{d.addr}</span>
                    {d.random_mac ? (
                      <span title={t("Cihaz adresini değiştirebilir; kural yazarken dikkat et.")}>
                        <SettingBadge tone="warning">{t("Rastgele MAC")}</SettingBadge>
                      </span>
                    ) : null}
                  </div>
                </TableCell>
                <TableCell className="hidden font-mono text-[0.8125rem] sm:table-cell" title={t("Gizlilik için yalnızca üretici kısmı gösterilir")}>
                  {maskMac(d.mac)}
                </TableCell>
                <TableCell className="hidden text-sm md:table-cell">{d.vendor || "-"}</TableCell>
                <TableCell className="hidden font-mono text-[0.8125rem] md:table-cell">{d.prefix}</TableCell>
                <TableCell className="text-right">
                  <span className="inline-flex items-center gap-1 text-sm text-muted-foreground">
                    <span className="font-mono text-[0.8125rem]">{d.rule}</span>
                    <CopyButton value={d.rule} label={t("{address} adresini kural için kopyala", { address: d.rule })} />
                  </span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </ListTable>
      )}
    </DetailSection>
  )
}
