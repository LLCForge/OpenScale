"use client"

import { useState } from "react"
import useSWR from "swr"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"
import { Download, Save } from "lucide-react"

import { DetailSection } from "@/components/devices/detail-card"
import { DiagSectionState } from "@/components/diag/diag-errors"
import { headCell, ListTable } from "@/components/settings/list-table"
import { EmptyNote, SettingBadge } from "@/components/settings/settings-layout"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { errorMessage, fetcher, post, postForBlob } from "@/lib/api"
import { formatAgo, formatBytes, formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { FlightRecFreezeReply, FlightRecStatus } from "@/lib/p2-diag-types"
import { useLiveInterval } from "@/lib/use-event-stream"
import { cn } from "@/lib/utils"

const statusKey = "/api/app/diag/flightrec"

const reasonLabels: Record<string, { label: string; tone: "muted" | "warning" | "danger" }> = {
  manual: { label: msg("Elle"), tone: "muted" },
  tunnel_down: { label: msg("Tünel düştü"), tone: "danger" },
  coordinator_lost: { label: msg("Koordinatör koptu"), tone: "warning" },
}

const exportSchema = z.object({
  to: z
    .string()
    .trim()
    .max(256, msg("Anahtar çok uzun."))
    .regex(/^osbk1:[A-Za-z0-9_-]{43}$/, msg("'osbk1:' ile başlayan anahtarı eksiksiz yapıştırın.")),
})

type ExportForm = z.infer<typeof exportSchema>

function ExportDialog({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { t } = useI18n()
  const form = useForm<ExportForm>({ resolver: zodResolver(exportSchema), defaultValues: { to: "" } })
  const { errors, isSubmitting } = form.formState

  function close() {
    form.reset()
    onClose()
  }

  async function onSubmit(values: ExportForm) {
    if (id === null) return
    try {
      const { blob, filename } = await postForBlob("/api/app/diag/flightrec/export", { id, to: values.to })
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
      toast.success(t("Şifreli kayıt indirildi; yalnızca anahtarın sahibi açabilir."))
      close()
    } catch (err) {
      form.setError("to", { message: errorMessage(err) })
    }
  }

  return (
    <Dialog open={id !== null} onOpenChange={(open) => (open ? undefined : close())}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("Kaydı yardımcıya şifrele")}</DialogTitle>
          <DialogDescription>
            {t("Yardım edecek kişi anahtarını şu komutla üretir:")} <code className="font-mono">openscale debug bundle-key --out yardim.key</code>
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
          <FieldGroup>
            <Field data-invalid={errors.to ? true : undefined}>
              <FieldLabel htmlFor="flightrec-to">{t("Yardımcının açık anahtarı")}</FieldLabel>
              <Input id="flightrec-to" autoComplete="off" spellCheck={false} placeholder="osbk1:…" className="font-mono" {...form.register("to")} />
              <FieldDescription>{t("Kayıt bu anahtara şifrelenir. Parmak izini yardımcıyla sesli karşılaştırın.")}</FieldDescription>
              <FieldError errors={[errors.to ? { message: t(errors.to.message ?? "") } : undefined]} />
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={close}>
              {t("Vazgeç")}
            </Button>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting ? <Spinner data-icon="inline-start" /> : <Download data-icon="inline-start" />}
              {t("Şifreli indir")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/**
 * The connection flight recorder (#836): the last half hour of detailed,
 * masked service log kept in memory. "Son kopmayı kaydet" freezes it into
 * a recording sealed to this computer's own key; a dropout does the same
 * by itself, at most every quarter hour. A recording leaves the computer
 * only sealed to a helper's key.
 */
export function FlightRecorderCard() {
  const { t, ts } = useI18n()
  const refreshInterval = useLiveInterval(30_000)
  const { data, error, isLoading, mutate } = useSWR<FlightRecStatus>(statusKey, fetcher, { refreshInterval })
  const [saving, setSaving] = useState(false)
  const [exportId, setExportId] = useState<string | null>(null)

  async function freeze() {
    setSaving(true)
    try {
      await post<FlightRecFreezeReply>("/api/app/diag/flightrec/freeze", {})
      toast.success(t("Son {min} dakikanın kaydı saklandı.", { min: Math.round((data?.stats.max_age_s ?? 1800) / 60) }))
      await mutate()
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  const stored = data?.stored ?? []
  return (
    <DetailSection
      id="ucus-kaydedici"
      title={t("Uçuş kaydedici")}
      description={t(
        "Son 30 dakikanın ayrıntılı günlüğü bellekte tutulur; anahtarlar, IP adresleri ve cihaz adları maskelenir. Kopma olunca kendiliğinden saklanır; bu bilgisayarın dışına yalnızca yardımcının anahtarına şifrelenerek çıkar.",
      )}
      framed={false}
      action={
        <Button type="button" variant="outline" onClick={() => void freeze()} disabled={saving || !data?.enabled}>
          {saving ? <Spinner data-icon="inline-start" /> : <Save data-icon="inline-start" />}
          {t("Son kopmayı kaydet")}
        </Button>
      }
    >
      <DiagSectionState section={t("Uçuş kaydedici")} error={error} isLoading={isLoading}>
        {data ? (
          <div className="flex flex-col gap-3">
            {data.enabled ? (
              <p className="text-sm text-muted-foreground">
                {t("Bellekte {count} kayıt, {size} / {max}.", {
                  count: data.stats.entries,
                  size: formatBytes(data.stats.bytes),
                  max: formatBytes(data.stats.max_bytes),
                })}{" "}
                {data.auto_freeze ? t("Kopmada kendiliğinden saklanır (en çok {min} dakikada bir).", { min: Math.round(data.auto_every_s / 60) }) : null}
              </p>
            ) : null}
            {data.error ? <EmptyNote>{ts(data.error)}</EmptyNote> : null}
            {stored.length === 0 ? (
              <EmptyNote>{t("Saklanan kayıt yok. Bağlantı koptuğunda veya düğmeye bastığınızda burada görünür.")}</EmptyNote>
            ) : (
              <ListTable label={t("Saklanan uçuş kayıtları")}>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className={cn(headCell, "w-32")}>{t("Zaman")}</TableHead>
                    <TableHead className={headCell}>{t("Neden")}</TableHead>
                    <TableHead className={cn(headCell, "hidden w-24 sm:table-cell")}>{t("Boyut")}</TableHead>
                    <TableHead className={cn(headCell, "w-28 text-right")}>
                      <span className="sr-only">{t("İşlem")}</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {stored.map((s) => {
                    const r = reasonLabels[s.reason]
                    return (
                      <TableRow key={s.id}>
                        <TableCell className="text-sm text-muted-foreground">
                          <time dateTime={s.at} title={formatDateTime(s.at)}>
                            {formatAgo(s.at)}
                          </time>
                        </TableCell>
                        <TableCell>
                          <SettingBadge tone={r?.tone ?? "muted"}>{r ? t(r.label) : s.reason}</SettingBadge>
                        </TableCell>
                        <TableCell className="hidden text-sm text-muted-foreground sm:table-cell">{formatBytes(s.size)}</TableCell>
                        <TableCell className="text-right">
                          <Button type="button" variant="ghost" size="sm" onClick={() => setExportId(s.id)}>
                            <Download data-icon="inline-start" />
                            {t("Dışa ver")}
                          </Button>
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </ListTable>
            )}
          </div>
        ) : null}
      </DiagSectionState>
      <ExportDialog id={exportId} onClose={() => setExportId(null)} />
    </DetailSection>
  )
}
