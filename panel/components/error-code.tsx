"use client"

import { useState } from "react"
import useSWR from "swr"
import { CircleHelp } from "lucide-react"

import { CodeLine, CopyButton } from "@/components/copy-field"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Skeleton } from "@/components/ui/skeleton"
import { ApiError, errorMessage, fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { ErrorCodeEntry } from "@/lib/p12-types"
import { cn } from "@/lib/utils"

// Stable error codes (#550, ADR-0165). A server error that carries a code
// shows it as a small copyable badge with a "Nasıl çözülür?" link; the link
// opens the catalog entry (cause, steps, commands). The catalog is static,
// so an entry is fetched once per code and kept.

/** The code of an error, when the server gave one. */
export function errorCode(err: unknown): string | undefined {
  return err instanceof ApiError ? err.code : undefined
}

/** Badge and help link for a coded error; renders nothing without a code. */
export function ErrorCodeHelp({ error, className }: { error: unknown; className?: string }) {
  const code = errorCode(error)
  if (!code) return null
  return <ErrorCodeLink code={code} className={className} />
}

export function ErrorCodeLink({ code, className }: { code: string; className?: string }) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  return (
    <span className={cn("flex flex-wrap items-center gap-2", className)}>
      <span
        title={t("Bu kod kalıcıdır; yardım isterken bu kodu söyle.")}
        className="inline-flex h-6 items-center gap-0.5 rounded-md border bg-background pr-0.5 pl-2 font-mono text-[0.8125rem] text-foreground"
      >
        {code}
        <CopyButton value={code} label={t("{code} kodunu kopyala", { code })} className="size-5" />
      </span>
      <Button type="button" variant="link" size="sm" className="h-6 px-0" onClick={() => setOpen(true)}>
        <CircleHelp data-icon="inline-start" />
        {t("Nasıl çözülür?")}
      </Button>
      <ErrorCodeDialog code={open ? code : null} onClose={() => setOpen(false)} />
    </span>
  )
}

/** The catalog entry of one code in a dialog. */
export function ErrorCodeDialog({ code, onClose }: { code: string | null; onClose: () => void }) {
  return (
    <Dialog open={code !== null} onOpenChange={(v) => (!v ? onClose() : undefined)}>
      <DialogContent className="sm:max-w-lg">{code ? <EntryBody code={code} onClose={onClose} /> : null}</DialogContent>
    </Dialog>
  )
}

function EntryBody({ code, onClose }: { code: string; onClose: () => void }) {
  const { t, ts } = useI18n()
  const { data, error } = useSWR<ErrorCodeEntry>(`/api/errors/${encodeURIComponent(code)}`, fetcher, {
    revalidateOnFocus: false,
    revalidateIfStale: false,
    shouldRetryOnError: false,
  })
  return (
    <>
      <DialogHeader>
        <DialogTitle className="flex flex-wrap items-center gap-2">
          <span className="font-mono">{code}</span>
          {data ? <span>{ts(data.title)}</span> : null}
        </DialogTitle>
        <DialogDescription className="text-pretty">
          {error
            ? errorMessage(error)
            : data?.deprecated
              ? t("Bu kod artık oluşmuyor; eski iletiler için tutuluyor.")
              : t("Bu kodun açıklaması panelle birlikte gelir; internet gerekmez.")}
        </DialogDescription>
      </DialogHeader>
      {data ? <EntryDetails entry={data} /> : error ? null : <EntrySkeleton />}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose}>
          {t("Kapat")}
        </Button>
      </DialogFooter>
    </>
  )
}

export function EntryDetails({ entry }: { entry: ErrorCodeEntry }) {
  const { t, ts } = useI18n()
  return (
    <div className="flex flex-col gap-5 text-sm leading-relaxed">
      <section className="flex flex-col gap-1">
        <h3 className="font-medium">{t("Neden")}</h3>
        <p className="text-muted-foreground text-pretty">{ts(entry.cause)}</p>
      </section>
      {entry.steps.length > 0 ? (
        <section className="flex flex-col gap-1">
          <h3 className="font-medium">{t("Ne yapmalı")}</h3>
          <ol className="flex list-decimal flex-col gap-1 pl-5 text-muted-foreground marker:text-foreground">
            {entry.steps.map((s) => (
              <li key={s} className="text-pretty">
                {ts(s)}
              </li>
            ))}
          </ol>
        </section>
      ) : null}
      {entry.commands && entry.commands.length > 0 ? (
        <section className="flex flex-col gap-2">
          <h3 className="font-medium">{t("Bakılacak komutlar")}</h3>
          {entry.commands.map((c) => (
            <CodeLine key={c} value={c} label={t("Komutu kopyala")} />
          ))}
        </section>
      ) : null}
    </div>
  )
}

function EntrySkeleton() {
  const { t } = useI18n()
  return (
    <div className="flex flex-col gap-2" aria-busy="true" aria-label={t("Açıklama yükleniyor")}>
      <Skeleton className="h-4 w-1/3" />
      <Skeleton className="h-16 w-full" />
    </div>
  )
}
