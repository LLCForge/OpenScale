"use client"

import { Fragment, useState, type ReactNode } from "react"
import useSWR, { useSWRConfig } from "swr"
import { Check, Inbox, X } from "lucide-react"
import { toast } from "sonner"

import { Writable, useReadOnly } from "@/components/app/read-only"
import { CodeLine } from "@/components/copy-field"
import { NativeSelect } from "@/components/native-select"
import { CountBadge, PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { SettingBadge } from "@/components/settings/settings-layout"
import { SignChangeDialog } from "@/components/sign-change"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Spinner } from "@/components/ui/spinner"
import { Textarea } from "@/components/ui/textarea"
import { errorMessage, fetcher, post } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import { accessSummary, type AccessRequestEntry, type AccessRequestsResponse } from "@/lib/p02-types"

// Cihazlar > Erişim istekleri (#383, ADR-0158): a device asks for access
// with "openscale access request"; the line is signed with the device's
// own key and reaches the owner by hand. Nothing is approved by itself:
// approving signs a rule that ends by itself, never longer than asked.

const KEY = "/api/p02/access-requests"
const REQUEST_COMMAND = msg("openscale access request --to <cihaz> --service ssh --users <hesap> --hours 8")

const statusText: Record<AccessRequestEntry["status"], string> = {
  pending: msg("Bekliyor"),
  approved: msg("Onaylandı"),
  rejected: msg("Reddedildi"),
}

/** Fills {name} placeholders of an already translated text with React nodes (keeps the bold parts). */
function richText(text: string, nodes: Record<string, ReactNode>): ReactNode {
  return text.split(/\{(\w+)\}/g).map((part, i) => (i % 2 === 1 ? <Fragment key={i}>{part in nodes ? nodes[part] : `{${part}}`}</Fragment> : part))
}

export function AccessRequestsView() {
  const { t } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<AccessRequestsResponse>(KEY, fetcher, { refreshInterval: 15_000 })
  const [approving, setApproving] = useState<AccessRequestEntry | null>(null)
  const requests = data?.requests ?? []
  const pending = requests.filter((r) => r.status === "pending")
  const decided = requests.filter((r) => r.status !== "pending")

  return (
    <>
      <PageHeader
        title={msg("Erişim istekleri")}
        badge={data && pending.length > 0 ? <CountBadge>{t("{count} bekliyor", { count: pending.length })}</CountBadge> : null}
        description={msg("Cihazların kendi anahtarıyla imzaladığı süreli erişim istekleri. Onaylarsan süreli bir kural imzalanır; süre dolunca kendiliğinden geçersiz olur.")}
      />
      <div className="flex flex-col gap-8">
        <Writable>
          <AddRequest onAdded={() => mutate()} />
        </Writable>
        <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
          {requests.length === 0 ? (
            <Empty className="border">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <Inbox />
                </EmptyMedia>
                <EmptyTitle>{t("İstek yok")}</EmptyTitle>
                <EmptyDescription className="text-pretty">{t("Erişim istemek için kişi kendi cihazında şu komutu çalıştırır ve çıkan satırı sana iletir:")}</EmptyDescription>
              </EmptyHeader>
              <CodeLine value={t(REQUEST_COMMAND)} label={t("Komutu kopyala")} className="w-full max-w-xl" />
            </Empty>
          ) : (
            <div className="flex flex-col gap-8">
              {pending.length > 0 ? (
                <RequestList title={t("Bekleyenler")} entries={pending} onApprove={setApproving} onChanged={() => mutate()} />
              ) : null}
              {decided.length > 0 ? <RequestList title={t("Yanıtlananlar")} entries={decided} onApprove={setApproving} onChanged={() => mutate()} /> : null}
            </div>
          )}
        </QueryState>
      </div>
      <ApproveDialog entry={approving} onClose={() => setApproving(null)} />
    </>
  )
}

function AddRequest({ onAdded }: { onAdded: () => void }) {
  const { t } = useI18n()
  const [line, setLine] = useState("")
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  async function add() {
    const value = line.trim()
    if (!value.startsWith("osreq1.")) {
      setErr(tx("Bu bir OpenScale erişim isteği değil; 'osreq1.' ile başlamalı."))
      return
    }
    setBusy(true)
    setErr(null)
    try {
      const res = await post<{ id: string; duplicate?: boolean }>(KEY, { request: value })
      toast.success(res.duplicate ? tx("Bu istek zaten listede.") : tx("İstek doğrulandı ve listeye eklendi."))
      setLine("")
      onAdded()
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section aria-labelledby="add-request-title" className="flex flex-col gap-3">
      <h2 id="add-request-title" className="text-base font-semibold">
        {t("İstek ekle")}
      </h2>
      <Field data-invalid={err ? true : undefined}>
        <FieldLabel htmlFor="access-request-line" className="sr-only">
          {t("Erişim isteği satırı")}
        </FieldLabel>
        <Textarea
          id="access-request-line"
          rows={3}
          spellCheck={false}
          autoComplete="off"
          maxLength={2048}
          className="font-mono text-[0.8125rem] break-all"
          placeholder="osreq1...."
          value={line}
          onChange={(e) => setLine(e.target.value)}
          aria-invalid={err ? true : undefined}
        />
        <FieldDescription className="text-pretty">
          {richText(t("Kişinin cihazındaki {command} komutunun çıktısını yapıştır. İstek cihazın anahtarıyla doğrulanır; eklemek hiçbir şeyi onaylamaz."), {
            command: <code className="font-mono text-[0.8125rem] text-foreground">openscale access request</code>,
          })}
        </FieldDescription>
      </Field>
      {err ? (
        <Alert variant="destructive">
          <AlertDescription>{err}</AlertDescription>
        </Alert>
      ) : null}
      <Button className="w-fit" variant="outline" onClick={add} disabled={busy || line.trim() === ""}>
        {busy ? <Spinner data-icon="inline-start" /> : null}
        {t("İsteği doğrula ve ekle")}
      </Button>
    </section>
  )
}

interface RequestListProps {
  title: string
  entries: AccessRequestEntry[]
  onApprove: (e: AccessRequestEntry) => void
  onChanged: () => void
}

function RequestList({ title, entries, onApprove, onChanged }: RequestListProps) {
  return (
    <section aria-label={title} className="flex flex-col gap-2">
      <h2 className="text-base font-semibold">{title}</h2>
      <ul className="flex flex-col divide-y rounded-lg border">
        {entries.map((e) => (
          <RequestRow key={e.id} entry={e} onApprove={() => onApprove(e)} onChanged={onChanged} />
        ))}
      </ul>
    </section>
  )
}

function RequestRow({ entry, onApprove, onChanged }: { entry: AccessRequestEntry; onApprove: () => void; onChanged: () => void }) {
  const { t, ts } = useI18n()
  const readOnly = useReadOnly()
  const [busy, setBusy] = useState(false)
  const r = entry.request

  async function reject() {
    setBusy(true)
    try {
      await post(`${KEY}/reject`, { id: entry.id })
      toast.success(tx("İstek reddedildi."))
      onChanged()
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <li className="flex flex-col gap-3 px-4 py-4 md:flex-row md:items-center md:justify-between md:gap-8">
      <div className="flex min-w-0 flex-col gap-1">
        {r ? (
          <>
            <span className="text-sm text-pretty">
              {richText(t("{from}, {to} cihazına {count} saat {access} erişimi istiyor.", { count: r.hours }), {
                from: <span className="font-medium">{r.from}</span>,
                to: <span className="font-medium">{r.to}</span>,
                access: accessSummary(r),
              })}
            </span>
            {r.reason ? <span className="text-sm text-muted-foreground text-pretty">{t("Gerekçe: {reason}", { reason: r.reason })}</span> : null}
          </>
        ) : (
          <span className="text-sm text-pretty">
            {entry.error ? t("Bu istek artık doğrulanamıyor: {error}", { error: ts(entry.error) }) : t("Bu istek artık doğrulanamıyor.")}
          </span>
        )}
        <span className="text-sm text-muted-foreground">
          {t("Geldi: {date}", { date: formatDateTime(entry.receivedAt) })}
          {entry.decidedAt ? ` · ${t("Yanıt: {date}", { date: formatDateTime(entry.decidedAt) })}` : ""}
        </span>
      </div>
      <div className="flex shrink-0 flex-wrap items-center gap-2">
        {entry.status === "pending" ? (
          readOnly ? (
            <SettingBadge tone="warning">{t("Bekliyor")}</SettingBadge>
          ) : (
            <>
              <Button variant="outline" onClick={reject} disabled={busy}>
                {busy ? <Spinner data-icon="inline-start" /> : <X data-icon="inline-start" />}
                {t("Reddet")}
              </Button>
              <Button onClick={onApprove} disabled={!r}>
                <Check data-icon="inline-start" />
                {t("Onayla…")}
              </Button>
            </>
          )
        ) : (
          <SettingBadge tone={entry.status === "approved" ? "success" : "muted"}>{t(statusText[entry.status])}</SettingBadge>
        )}
      </div>
    </li>
  )
}

/** Approval signs a rule; the owner may shorten the asked duration. */
function ApproveDialog({ entry, onClose }: { entry: AccessRequestEntry | null; onClose: () => void }) {
  const { t } = useI18n()
  const { mutate } = useSWRConfig()
  const [hours, setHours] = useState(0)
  const asked = entry?.request?.hours ?? 0
  const choices = [asked, 24, 8, 4, 1].filter((h, i, all) => h > 0 && h <= asked && all.indexOf(h) === i)

  function close(open: boolean) {
    if (open) return
    setHours(0)
    void mutate(KEY)
    onClose()
  }

  return (
    <>
      {entry?.request ? (
        <SignChangeDialog
          open
          onOpenChange={close}
          title={t("{name} için erişimi onayla", { name: entry.request.from })}
          description={t("{to} cihazına {access} erişimi için süreli bir kural imzalanır. Süre yalnızca kısaltılabilir.", {
            to: entry.request.to,
            access: accessSummary(entry.request),
          })}
          endpoint={`${KEY}/approve`}
          payload={{ id: entry.id, hours }}
          confirmLabel={t("İmzala ve onayla")}
          extra={
            <Field>
              <FieldLabel htmlFor="access-hours">{t("Süre")}</FieldLabel>
              <NativeSelect id="access-hours" value={String(hours)} onChange={(e) => setHours(Number(e.target.value))}>
                {choices.map((h) => (
                  <option key={h} value={h === asked ? "0" : String(h)}>
                    {h === asked ? t("İstenen süre ({count} saat)", { count: h }) : t("{count} saat", { count: h })}
                  </option>
                ))}
              </NativeSelect>
            </Field>
          }
        />
      ) : null}
    </>
  )
}
