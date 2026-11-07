"use client"

import useSWR from "swr"
import { CircleCheck, Info } from "lucide-react"

import { QueryState } from "@/components/query-state"
import { SignChangeDialog } from "@/components/sign-change"
import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"

/** One reference to the retiring device (admin.RetireItem). */
export interface RetireItem {
  title: string
  effect: string
  /** True when the signed retirement changes or removes it. */
  cleaned: boolean
}

export interface RetireSection {
  id: string
  title: string
  items: RetireItem[]
}

/** GET /api/f2/retire?name= (admin.RetirePreview). */
export interface RetirePreview {
  device: string
  ipv4: string
  ipv6: string
  exitNode: boolean
  sections: RetireSection[]
  cleaned: number
  notes: string[]
}

interface RetireDeviceDialogProps {
  /** Device to retire; null closes the dialog. */
  name: string | null
  onClose: () => void
}

/**
 * Retirement wizard (#825): before the revocation the owner sees every rule,
 * group, DNS record, exit chain, sync or backup partner, SSH access and
 * Wake-on-LAN relay that names the device. The revocation and every clean-up
 * are signed together in one version.
 */
export function RetireDeviceDialog({ name, onClose }: RetireDeviceDialogProps) {
  const { t } = useI18n()
  return (
    <SignChangeDialog
      open={name !== null}
      onOpenChange={(open) => {
        if (!open) onClose()
      }}
      title={t("{name} cihazını emekliye ayır", { name: name ?? "" })}
      description={t(
        "Cihazın anahtarları kalıcı olarak iptal edilir ve aşağıdaki bütün başvurular aynı imzada temizlenir. Bu işlem geri alınamaz; cihaz geri gelmek isterse yeni davetle katılmalı."
      )}
      extra={name !== null ? <RetirePreviewList name={name} /> : null}
      endpoint="/api/f2/retire"
      payload={{ name: name ?? "" }}
      confirmLabel={t("İmzala ve emekliye ayır")}
      destructive
      confirmText={name ?? undefined}
    />
  )
}

function RetirePreviewList({ name }: { name: string }) {
  const { data, error, isLoading, mutate } = useSWR<RetirePreview>(`/api/f2/retire?name=${encodeURIComponent(name)}`, fetcher)
  return (
    <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
      {data ? <PreviewBody preview={data} /> : null}
    </QueryState>
  )
}

function PreviewBody({ preview }: { preview: RetirePreview }) {
  const { t, ts } = useI18n()
  return (
    <section aria-label={t("Emekliye ayırma önizlemesi")} className="flex max-h-72 flex-col gap-4 overflow-y-auto rounded-lg border p-3">
      {preview.sections.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("Belgede bu cihaza başka başvuru yok.")}</p>
      ) : (
        preview.sections.map((s) => (
          <div key={s.id} className="flex flex-col gap-2">
            <h3 className="text-sm font-semibold">
              {ts(s.title)} <span className="font-normal text-muted-foreground">({s.items.length})</span>
            </h3>
            <ul className="flex flex-col gap-2">
              {s.items.map((it, i) => (
                <li key={`${s.id}-${i}`} className="flex gap-2 text-sm">
                  {it.cleaned ? (
                    <CircleCheck className="mt-0.5 size-4 shrink-0 text-destructive" aria-label={t("İmzayla temizlenir")} />
                  ) : (
                    <Info className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-label={t("Bilgi")} />
                  )}
                  <span className="flex min-w-0 flex-col">
                    <span className="font-mono text-xs break-all">{it.title}</span>
                    <span className="leading-relaxed text-muted-foreground text-pretty">{ts(it.effect)}</span>
                  </span>
                </li>
              ))}
            </ul>
          </div>
        ))
      )}
      <p className="text-sm">
        {t("İmzayla birlikte temizlenecek girdi:")} <span className="font-medium">{preview.cleaned}</span>
      </p>
      {preview.notes.length > 0 ? (
        <ul className="flex flex-col gap-1 border-t pt-3 text-sm leading-relaxed text-muted-foreground">
          {preview.notes.map((n) => (
            <li key={n} className="text-pretty">
              {ts(n)}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  )
}
