"use client"

import useSWR from "swr"
import { Copy, Printer } from "lucide-react"
import { toast } from "sonner"

import { CodeLine, CopyButton } from "@/components/copy-field"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Skeleton } from "@/components/ui/skeleton"
import { errorMessage, fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { ConnectionCard } from "@/lib/p02-types"

// Connection card (#557): how to reach a device, ready to share or print.
// It names the device, its addresses and the services the rules open to
// it, with the ready commands. It carries no password or key.

export function ConnectionCardDialog({ name, onClose }: { name: string | null; onClose: () => void }) {
  const { t } = useI18n()
  return (
    <Dialog open={name !== null} onOpenChange={(v) => (!v ? onClose() : undefined)}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader data-print-hide="">
          <DialogTitle>{t("Bağlantı kartı")}</DialogTitle>
          <DialogDescription className="text-pretty">
            {t("Bu kartı cihaza bağlanacak kişiyle paylaş. Kart parola içermez; bağlanmak için kişinin cihazında OpenScale açık olmalı.")}
          </DialogDescription>
        </DialogHeader>
        {name ? <CardBody name={name} onClose={onClose} /> : null}
      </DialogContent>
    </Dialog>
  )
}

function CardBody({ name, onClose }: { name: string; onClose: () => void }) {
  const { t } = useI18n()
  const { data, error } = useSWR<ConnectionCard>(`/api/p02/devices/card?name=${encodeURIComponent(name)}`, fetcher, { revalidateOnFocus: false })

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertDescription>{errorMessage(error)}</AlertDescription>
      </Alert>
    )
  }
  if (!data) {
    return (
      <div className="flex flex-col gap-2" aria-busy="true" aria-label={t("Kart hazırlanıyor")}>
        <Skeleton className="h-5 w-1/2" />
        <Skeleton className="h-40 w-full" />
      </div>
    )
  }

  return (
    <>
      <article data-print-area="" aria-label={t("{name} bağlantı kartı", { name: data.name })} className="flex flex-col gap-4 rounded-lg border p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex min-w-0 flex-col gap-1">
            <h3 className="text-base font-semibold">{data.name}</h3>
            <dl className="grid grid-cols-[auto_1fr] items-center gap-x-3 gap-y-1 text-sm">
              <dt className="text-muted-foreground">{t("Ad")}</dt>
              <dd className="flex min-w-0 items-center gap-1">
                <span className="font-mono text-[0.8125rem] break-all">{data.dnsName}</span>
                <CopyButton value={data.dnsName} label={t("Adı kopyala")} className="size-6" />
              </dd>
              <dt className="text-muted-foreground">IPv4</dt>
              <dd className="flex min-w-0 items-center gap-1">
                <span className="font-mono text-[0.8125rem]">{data.ipv4}</span>
                <CopyButton value={data.ipv4} label={t("IPv4 adresini kopyala")} className="size-6" />
              </dd>
              <dt className="text-muted-foreground">IPv6</dt>
              <dd className="font-mono text-[0.8125rem] break-all">{data.ipv6}</dd>
            </dl>
          </div>
          {data.qr ? (
            // A data URL made by the server; img-src allows data: (static.go).
            // eslint-disable-next-line @next/next/no-img-element
            <img src={data.qr} alt={t("Kartın metnini taşıyan QR kodu")} width={112} height={112} className="size-28 shrink-0 rounded-md border bg-background p-1 [image-rendering:pixelated]" />
          ) : null}
        </div>
        <section className="flex flex-col gap-2">
          <h4 className="text-sm font-medium">{t("İzin verilen bağlantılar")}</h4>
          {data.services.length === 0 ? (
            <p className="text-sm text-muted-foreground text-pretty">{t("Kurallar şu an hiçbir cihaza bu cihaza bağlanma izni vermiyor.")}</p>
          ) : (
            <ul className="flex flex-col gap-3">
              {data.services.map((s, i) => (
                <li key={`${s.label}-${i}`} className="flex flex-col gap-1.5">
                  <span className="flex flex-wrap items-baseline gap-x-2 text-sm">
                    <span className="font-medium">{s.label}</span>
                    <span className="text-muted-foreground">
                      {s.from.join(", ")}
                      {s.until ? ` · ${t("{until} tarihine kadar", { until: s.until })}` : ""}
                    </span>
                  </span>
                  {s.command ? <CodeLine value={s.command} label={t("Komutu kopyala")} /> : null}
                </li>
              ))}
            </ul>
          )}
        </section>
      </article>
      <DialogFooter data-print-hide="">
        <CopyTextButton text={data.text} />
        <Button type="button" variant="outline" onClick={() => window.print()}>
          <Printer data-icon="inline-start" />
          {t("Yazdır")}
        </Button>
        <Button type="button" onClick={onClose}>
          {t("Kapat")}
        </Button>
      </DialogFooter>
    </>
  )
}

function CopyTextButton({ text }: { text: string }) {
  const { t } = useI18n()
  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      toast.success(t("Kartın metni kopyalandı."))
    } catch {
      toast.error(t("Pano kullanılamadı; metni elle seç."))
    }
  }
  return (
    <Button type="button" variant="outline" onClick={copy}>
      <Copy data-icon="inline-start" />
      {t("Metni kopyala")}
    </Button>
  )
}
