"use client"

import { useState } from "react"
import Link from "next/link"
import useSWR from "swr"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { Link2, Plus } from "lucide-react"
import { toast } from "sonner"

import { CodeLine } from "@/components/copy-field"
import { NativeSelect } from "@/components/native-select"
import { EmptyNote, SettingsSection } from "@/components/settings/settings-layout"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { ApiError, errorMessage, fetcher, post } from "@/lib/api"
import { formatBytes, formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { FileLink, FileLinkCreated, FileLinksStatus } from "@/lib/p07-types"

// Timed single-file links (#460, ADR-0161): one file, one device, a number
// of downloads and an end time. The address carries a secret and is shown
// only once; the service keeps only its hash.

const KEY = "/api/app/files/links"

const schema = z.object({
  path: z.string().trim().min(1, msg("Dosyanın tam yolunu yaz")).max(4096, msg("Yol çok uzun")),
  device: z.string().min(1, msg("Cihazı seç")),
  hours: z.number({ message: msg("Sayı gir") }).int().min(1, msg("En az 1 saat")).max(720, msg("En fazla 720 saat")),
  downloads: z.number({ message: msg("Sayı gir") }).int().min(1, msg("En az 1")).max(100, msg("En fazla 100")),
})
type Values = z.infer<typeof schema>

export function FileLinksSection({ peers, readOnly }: { peers: string[]; readOnly: boolean }) {
  const { t, ts } = useI18n()
  const { data, error, mutate } = useSWR<FileLinksStatus>(KEY, fetcher, {
    refreshInterval: 30_000,
    shouldRetryOnError: (err: unknown) => !(err instanceof ApiError && err.status === 404),
  })
  const [creating, setCreating] = useState(false)
  const [revoking, setRevoking] = useState<string | null>(null)

  if (error instanceof ApiError && error.status === 404) return null
  if (!data) return null

  async function revoke(l: FileLink) {
    setRevoking(l.id)
    try {
      await mutate(await post<FileLinksStatus>(`${KEY}/revoke`, { id: l.id }), { revalidate: false })
      toast.success(t("Bağlantı iptal edildi."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setRevoking(null)
    }
  }

  const links = data.links ?? []
  return (
    <SettingsSection
      id="sureli-baglanti"
      title={t("Süreli bağlantılar")}
      description={t("Tek bir dosyayı tek bir cihaza, belirli sayıda indirme ve belirli süre için açar. Dosya bağlantıdan sonra değişirse sunulmaz.")}
      action={
        readOnly ? null : (
          <Button variant="outline" onClick={() => setCreating(true)}>
            <Plus data-icon="inline-start" />
            {t("Bağlantı oluştur")}
          </Button>
        )
      }
    >
      {!data.served && data.note ? (
        <Alert className="my-4">
          <AlertTitle>{t("Bağlantılar şu an indirilemez")}</AlertTitle>
          <AlertDescription className="text-pretty">
            {ts(data.note)}{" "}
            <Link href="/rules" className="underline underline-offset-4">
              {t("Kurallar sayfasına git")}
            </Link>
          </AlertDescription>
        </Alert>
      ) : null}
      {links.length === 0 ? (
        <EmptyNote framed={false}>{t("Etkin bağlantı yok.")}</EmptyNote>
      ) : (
        links.map((l) => (
          <div key={l.id} data-slot="setting-row" className="flex flex-col gap-2 py-4 sm:flex-row sm:items-center sm:justify-between sm:gap-6">
            <div className="flex min-w-0 flex-col gap-0.5">
              <span className="truncate text-sm font-medium" title={l.path}>
                {l.name}
              </span>
              <span className="text-sm text-muted-foreground">
                {t("{device} · {downloads}/{max} indirme · {size} · {until} tarihine kadar", {
                  device: l.device,
                  downloads: l.downloads,
                  max: l.max_downloads,
                  size: formatBytes(l.size),
                  until: formatDateTime(l.expires),
                })}
              </span>
            </div>
            {readOnly ? null : (
              <Button variant="ghost" size="sm" disabled={revoking === l.id} onClick={() => revoke(l)}>
                {revoking === l.id ? <Spinner data-icon="inline-start" /> : null}
                {t("İptal et")}
              </Button>
            )}
          </div>
        ))
      )}
      <CreateLinkDialog open={creating} onOpenChange={setCreating} peers={peers} onCreated={() => mutate()} />
    </SettingsSection>
  )
}

interface CreateLinkDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  peers: string[]
  onCreated: () => void
}

function CreateLinkDialog({ open, onOpenChange, peers, onCreated }: CreateLinkDialogProps) {
  const { t } = useI18n()
  const [created, setCreated] = useState<FileLinkCreated | null>(null)
  const form = useForm<Values>({ resolver: zodResolver(schema), defaultValues: { path: "", device: "", hours: 24, downloads: 1 } })
  const { errors, isSubmitting } = form.formState

  function close(v: boolean) {
    if (!v) {
      setCreated(null)
      form.reset()
    }
    onOpenChange(v)
  }

  async function submit(v: Values) {
    try {
      setCreated(await post<FileLinkCreated>(KEY, v))
      onCreated()
    } catch (err) {
      form.setError("path", { message: errorMessage(err) })
    }
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{created ? t("Bağlantı hazır") : t("Süreli bağlantı oluştur")}</DialogTitle>
          <DialogDescription className="text-pretty">
            {created
              ? t("Bu adres bir daha gösterilmeyecek. Yalnızca {device} cihazı açabilir.", { device: created.link.device })
              : t("Dosya tünel içinden, yalnızca seçtiğin cihaza sunulur. Veri klasöründeki dosyalar (anahtarlar) paylaşılamaz.")}
          </DialogDescription>
        </DialogHeader>
        {created ? (
          <div className="flex flex-col gap-3">
            <CodeLine value={created.url} label={t("Adresi kopyala")} secret />
            <p className="text-sm text-muted-foreground">
              {t("{count} indirme, {until} tarihine kadar.", { count: created.link.max_downloads, until: formatDateTime(created.link.expires) })}
            </p>
            <DialogFooter>
              <Button onClick={() => close(false)}>{t("Tamam")}</Button>
            </DialogFooter>
          </div>
        ) : (
          <form onSubmit={form.handleSubmit(submit)} noValidate className="flex flex-col gap-6">
            <FieldGroup>
              <Field data-invalid={errors.path ? true : undefined}>
                <FieldLabel htmlFor="link-path">{t("Dosyanın tam yolu")}</FieldLabel>
                <Input
                  id="link-path"
                  autoComplete="off"
                  spellCheck={false}
                  className="font-mono"
                  placeholder={t("C:\\Users\\ad\\Belgeler\\rapor.pdf")}
                  aria-invalid={errors.path ? true : undefined}
                  {...form.register("path")}
                />
                <FieldError errors={[errors.path]} />
              </Field>
              <Field data-invalid={errors.device ? true : undefined}>
                <FieldLabel htmlFor="link-device">{t("Açabilecek cihaz")}</FieldLabel>
                <NativeSelect id="link-device" aria-invalid={errors.device ? true : undefined} {...form.register("device")}>
                  <option value="">{t("Seç")}</option>
                  {peers.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </NativeSelect>
                <FieldError errors={[errors.device]} />
              </Field>
              <div className="flex flex-wrap gap-4">
                <Field data-invalid={errors.hours ? true : undefined} className="w-36">
                  <FieldLabel htmlFor="link-hours">{t("Geçerlilik (saat)")}</FieldLabel>
                  <Input id="link-hours" type="number" min={1} max={720} {...form.register("hours", { valueAsNumber: true })} />
                  <FieldError errors={[errors.hours]} />
                </Field>
                <Field data-invalid={errors.downloads ? true : undefined} className="w-36">
                  <FieldLabel htmlFor="link-downloads">{t("İndirme sayısı")}</FieldLabel>
                  <Input id="link-downloads" type="number" min={1} max={100} {...form.register("downloads", { valueAsNumber: true })} />
                  <FieldError errors={[errors.downloads]} />
                </Field>
              </div>
              <FieldDescription>{t("Bağlantı tünel içinde düz HTTP'dir; adresi yalnızca o cihazın sahibine ver.")}</FieldDescription>
            </FieldGroup>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => close(false)}>
                {t("Vazgeç")}
              </Button>
              <Button type="submit" disabled={isSubmitting}>
                {isSubmitting ? <Spinner data-icon="inline-start" /> : <Link2 data-icon="inline-start" />}
                {t("Bağlantı oluştur")}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}
