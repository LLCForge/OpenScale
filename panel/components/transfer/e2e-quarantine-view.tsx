"use client"

import { useState } from "react"
import useSWR from "swr"
import { ShieldAlert, TriangleAlert } from "lucide-react"
import { toast } from "sonner"

import { useReadOnly } from "@/components/app/read-only"
import { optionalGet, postCoded } from "@/components/auth/strict-api"
import { PageHeader } from "@/components/page-header"
import { EmptyNote } from "@/components/settings/settings-layout"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { errorMessage } from "@/lib/api"
import { formatBytes, formatDateTime } from "@/lib/format"
import { useI18n } from "@/lib/i18n/i18n"

// Quarantine for files received end to end (#659, ADR-0205). Each file
// carries the operating system's "came from the internet" mark; moving it
// to the inbox happens only after the warning is read.

interface QuarantinedFile {
  name: string
  size: number
  received: string
  executable: boolean
  marked: boolean
  warning: string
}

interface QuarantineView {
  files: QuarantinedFile[] | null
}

export function E2EQuarantineView() {
  const { t, ts } = useI18n()
  const readOnly = useReadOnly()
  const { data, error, isLoading, mutate } = useSWR<QuarantineView | null>("/api/app/e2e/quarantine", optionalGet, { refreshInterval: 10_000 })
  const [release, setRelease] = useState<QuarantinedFile | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  async function remove(name: string) {
    setBusy(name)
    try {
      await postCoded("/api/app/e2e/quarantine/delete", { name })
      toast.success(t("Dosya silindi."))
      await mutate()
    } catch (err) {
      toast.error(err instanceof Error ? errorMessage(err) : t("Dosya silinemedi."))
    } finally {
      setBusy(null)
    }
  }

  async function moveToInbox(file: QuarantinedFile) {
    setBusy(file.name)
    try {
      const res = await postCoded<{ path: string; warning: string }>("/api/app/e2e/quarantine/release", { name: file.name })
      toast.success(t("Gelen kutusuna taşındı: {path}", { path: res.path }))
      await mutate()
    } catch (err) {
      toast.error(err instanceof Error ? errorMessage(err) : t("Dosya taşınamadı."))
    } finally {
      setBusy(null)
      setRelease(null)
    }
  }

  const files = data?.files ?? []

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title={t("Karantinadaki dosyalar")}
        description={t("Başka cihazlardan gelen dosyalar burada bekler ve işletim sisteminin 'internetten geldi' işaretini taşır.")}
      />
      {isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : error ? (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertDescription>{error instanceof Error ? errorMessage(error) : t("Karantina okunamadı.")}</AlertDescription>
        </Alert>
      ) : data === null ? (
        <EmptyNote>{t("Bu sürümde karantina yok.")}</EmptyNote>
      ) : files.length === 0 ? (
        <EmptyNote>{t("Karantinada dosya yok. Kabul ettiğiniz dosyalar açılmadan önce burada bekler.")}</EmptyNote>
      ) : (
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">{t("Dosya")}</TableHead>
                <TableHead scope="col">{t("Boyut")}</TableHead>
                <TableHead scope="col">{t("Geliş")}</TableHead>
                <TableHead scope="col">{t("Durum")}</TableHead>
                <TableHead scope="col">
                  <span className="sr-only">{t("İşlemler")}</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {files.map((f) => (
                <TableRow key={f.name}>
                  <TableCell className="max-w-64 truncate font-medium" title={f.name}>
                    {f.name}
                  </TableCell>
                  <TableCell className="tabular-nums">{formatBytes(f.size)}</TableCell>
                  <TableCell className="tabular-nums">{formatDateTime(f.received)}</TableCell>
                  <TableCell className="text-sm">
                    <div className="flex flex-col gap-0.5">
                      {f.executable ? (
                        <span className="text-destructive">{t("Kod çalıştırabilir")}</span>
                      ) : (
                        <span className="text-muted-foreground">{t("Belge")}</span>
                      )}
                      {f.marked ? null : (
                        <span className="text-xs text-warning-foreground dark:text-warning">
                          {t("Bu dosya sisteminde işaret konamadı; açarken dikkatli olun.")}
                        </span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex justify-end gap-2">
                      <Button size="sm" variant="outline" disabled={readOnly || busy !== null} onClick={() => setRelease(f)}>
                        {t("Gelen kutusuna taşı")}
                      </Button>
                      <Button size="sm" variant="ghost" disabled={readOnly || busy !== null} onClick={() => remove(f.name)}>
                        {t("Sil")}
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <AlertDialog open={release !== null} onOpenChange={(open) => (open ? undefined : setRelease(null))}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <ShieldAlert className="size-4" aria-hidden="true" />
              {release?.name}
            </AlertDialogTitle>
            <AlertDialogDescription className="text-pretty">{release ? ts(release.warning) : null}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("Vazgeç")}</AlertDialogCancel>
            <AlertDialogAction onClick={() => (release ? moveToInbox(release) : undefined)}>{t("Anladım, gelen kutusuna taşı")}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
