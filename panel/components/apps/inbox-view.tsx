"use client"

import { useState } from "react"
import useSWR from "swr"
import { Check, Download, FileWarning, ScanSearch, Trash2, X } from "lucide-react"
import { toast } from "sonner"

import { useAppStatus } from "@/components/app/use-app-status"
import { useReadOnly } from "@/components/app/read-only"
import { FileLinksSection } from "@/components/apps/file-links"
import { ScanBadge, ScanSection, rescan, scanResult, useFileScan } from "@/components/apps/file-scan"
import { DetailSection } from "@/components/devices/detail-card"
import { PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { headCell, ListTable, RowList, RowMenu } from "@/components/settings/list-table"
import { EmptyNote, SettingBadge, SettingRow, SettingsColumn, SettingsSection } from "@/components/settings/settings-layout"
import { useHash, useScrollToHash } from "@/components/settings/use-hash"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { DropdownMenuItem, DropdownMenuSeparator } from "@/components/ui/dropdown-menu"
import { Switch } from "@/components/ui/switch"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { errorMessage, post } from "@/lib/api"
import { inboxFileUrl, optionalFetcher, type InboxView as InboxData } from "@/lib/apps"
import { formatBytes, formatDateTime } from "@/lib/format"
import { useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

/** Received files of this computer (ADR-0031). */
export function InboxView() {
  const { t } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<InboxData | null>("/api/app/inbox", optionalFetcher, { refreshInterval: 3_000 })
  const app = useAppStatus(15_000)
  const readOnly = useReadOnly()
  const [deleting, setDeleting] = useState<string | null>(null)
  const { scan, mutate: mutateScan } = useFileScan()
  const hash = useHash()
  useScrollToHash(hash, data !== undefined && scan !== undefined)

  async function decide(id: string, accept: boolean) {
    try {
      const next = await post<InboxData>("/api/app/inbox/decide", { id, accept })
      await mutate(next, { revalidate: false })
      toast.success(accept ? t("Kabul edildi; aktarım başlıyor.") : t("Reddedildi."))
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }

  async function remove(name: string) {
    setDeleting(name)
    try {
      const next = await post<InboxData>("/api/app/inbox/delete", { name })
      await mutate(next, { revalidate: false })
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setDeleting(null)
    }
  }

  async function setAuto(device: string, on: boolean) {
    try {
      const next = await post<InboxData>("/api/app/inbox/auto-accept", { device, on })
      await mutate(next, { revalidate: false })
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }

  const peers = app.status?.device?.peers.map((p) => p.name) ?? []
  const autoDevices = Array.from(new Set([...(data?.autoAccept ?? []), ...peers])).sort()

  return (
    <SettingsColumn className="max-w-4xl">
      <PageHeader
        title={t("Gelen dosyalar")}
        description={t("Diğer cihazların bu bilgisayara gönderdiği dosyalar; OpenScale veri klasöründeki gelen kutusunda durur.")}
      />
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {data === null ? (
          <EmptyNote>{t("Gelen kutusu OpenScale servisinin çalıştığı bilgisayarda, masaüstü uygulamasında görünür.")}</EmptyNote>
        ) : data ? (
          <>
            {data.pending.length > 0 ? (
              <DetailSection
                id="onay-bekleyen"
                title={t("Onay bekleyen dosyalar")}
                description={t("Kabul etmezsen teklif iki dakika sonra kendiliğinden reddedilir.")}
                framed={false}
              >
                <RowList label={t("Onay bekleyen dosyalar")}>
                  {data.pending.map((p) => (
                    <li key={p.id} className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between sm:gap-6">
                      <div className="flex min-w-0 flex-col gap-0.5">
                        <span className="truncate text-sm font-medium">{p.name}</span>
                        <span className="text-sm text-muted-foreground">
                          {p.from} · {formatBytes(p.size)}
                        </span>
                      </div>
                      {readOnly ? (
                        <span className="text-sm text-muted-foreground">{t("Salt okunur panelde karar verilemez.")}</span>
                      ) : (
                        <div className="flex shrink-0 gap-2">
                          <Button size="sm" variant="outline" onClick={() => decide(p.id, false)}>
                            <X data-icon="inline-start" />
                            {t("Reddet")}
                          </Button>
                          <Button size="sm" onClick={() => decide(p.id, true)}>
                            <Check data-icon="inline-start" />
                            {t("Kabul et")}
                          </Button>
                        </div>
                      )}
                    </li>
                  ))}
                </RowList>
              </DetailSection>
            ) : null}

            <DetailSection
              id="dosyalar"
              title={t("Dosyalar")}
              description={t("Gelen kutusundaki dosyalar, en yenisi üstte.")}
              framed={false}
            >
              {data.files.some((f) => f.executable) ? (
                <Alert>
                  <FileWarning />
                  <AlertTitle>{t("Çalıştırılabilir dosyalar")}</AlertTitle>
                  <AlertDescription className="text-pretty">
                    {t(
                      "İşaretli dosyalar açıldığında program çalıştırabilir. Windows bunları internetten gelmiş gibi işaretler; yine de yalnızca beklediğin dosyaları aç."
                    )}
                  </AlertDescription>
                </Alert>
              ) : null}
              {data.files.length === 0 ? (
                <EmptyNote>
                  {t(
                    "Gelen kutusu boş. Bir cihazın buraya dosya gönderebilmesi için yönetici bir files kuralı eklemeli: kaynak o cihaz, hedef bu bilgisayar."
                  )}
                </EmptyNote>
              ) : (
                <ListTable label={t("Gelen dosyalar")}>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className={headCell}>{t("Dosya")}</TableHead>
                      <TableHead className={cn(headCell, "hidden sm:table-cell")}>{t("Gönderen")}</TableHead>
                      <TableHead className={cn(headCell, "hidden md:table-cell")}>{t("Boyut")}</TableHead>
                      <TableHead className={cn(headCell, "hidden md:table-cell")}>{t("Geldiği zaman")}</TableHead>
                      <TableHead className="w-12">
                        <span className="sr-only">{t("İşlemler")}</span>
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.files.map((f) => {
                      const verdict = scanResult(scan, f.name)
                      const infected = verdict?.verdict === "infected"
                      return (
                      <TableRow key={f.name}>
                        <TableCell className="max-w-72">
                          <div className="flex min-w-0 flex-col gap-1">
                            <span className="truncate font-medium" title={f.name}>
                              {f.name}
                            </span>
                            {f.executable || verdict ? (
                              <span className="flex flex-wrap gap-1">
                                {f.executable ? <SettingBadge tone="danger">{t("Çalıştırılabilir")}</SettingBadge> : null}
                                <ScanBadge result={verdict} />
                              </span>
                            ) : null}
                            {infected ? <span className="text-sm text-muted-foreground">{t("Dosya silinmedi; karar senin.")}</span> : null}
                            <span className="text-sm text-muted-foreground md:hidden">
                              {[f.from, formatBytes(f.size), formatDateTime(f.receivedAt)].filter(Boolean).join(" · ")}
                            </span>
                          </div>
                        </TableCell>
                        <TableCell className="hidden text-sm sm:table-cell">{f.from || "-"}</TableCell>
                        <TableCell className="hidden text-sm whitespace-nowrap md:table-cell">{formatBytes(f.size)}</TableCell>
                        <TableCell className="hidden text-sm whitespace-nowrap text-muted-foreground md:table-cell">{formatDateTime(f.receivedAt)}</TableCell>
                        <TableCell className="text-right">
                          <RowMenu label={t("{name} için işlemler", { name: f.name })} className="w-44">
                            <DropdownMenuItem
                              disabled={infected}
                              render={<a href={inboxFileUrl(f.name)} download={f.name} />}
                              onClick={() => {
                                if (f.executable) toast.warning(t("Bu dosya açıldığında kod çalıştırabilir; kaynağından eminsen aç."))
                              }}
                            >
                              <Download />
                              {t("İndir")}
                            </DropdownMenuItem>
                            {scan?.available && !readOnly ? (
                              <DropdownMenuItem onClick={() => rescan(f.name, (next) => void mutateScan(next, { revalidate: false }))}>
                                <ScanSearch />
                                {t("Yeniden tara")}
                              </DropdownMenuItem>
                            ) : null}
                            {readOnly ? null : (
                              <>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem variant="destructive" disabled={deleting === f.name} onClick={() => remove(f.name)}>
                                  <Trash2 />
                                  {t("Sil")}
                                </DropdownMenuItem>
                              </>
                            )}
                          </RowMenu>
                        </TableCell>
                      </TableRow>
                      )
                    })}
                  </TableBody>
                </ListTable>
              )}
            </DetailSection>

            {scan ? <ScanSection scan={scan} readOnly={readOnly} onChange={(next) => void mutateScan(next, { revalidate: false })} /> : null}

            <FileLinksSection peers={peers} readOnly={readOnly} />

            <SettingsSection
              id="otomatik-kabul"
              title={t("Bu cihazdan otomatik kabul")}
              description={t("Açık olan cihazların dosyaları sorulmadan kabul edilir. Kural yine gerekir: files kuralı olmayan cihaz hiçbir zaman gönderemez.")}
            >
              {autoDevices.length === 0 ? (
                <EmptyNote framed={false}>{t("Ulaşılabilir cihaz yok.")}</EmptyNote>
              ) : (
                autoDevices.map((d) => (
                  <SettingRow
                    key={d}
                    title={d}
                    htmlFor={`auto-${d}`}
                    className="py-3"
                    action={<Switch id={`auto-${d}`} checked={data.autoAccept.includes(d)} disabled={readOnly} onCheckedChange={(on) => setAuto(d, on)} />}
                  />
                ))
              )}
            </SettingsSection>
          </>
        ) : null}
      </QueryState>
    </SettingsColumn>
  )
}
