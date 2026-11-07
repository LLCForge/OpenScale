"use client"

import { useState } from "react"
import useSWR, { useSWRConfig } from "swr"
import { useForm, Controller } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { BellRing, Check, Clock, Download, Ticket, TicketX } from "lucide-react"
import { toast } from "sonner"

import { CodeLine } from "@/components/copy-field"
import { NativeSelect } from "@/components/native-select"
import { radioGroupKeyDown } from "@/components/settings/radio-keys"
import { TagList } from "@/components/tag-list"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { errorMessage, fetcher, post } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import { GUEST_TAG_PREFIX, type GuestsResponse, type InviteLauncher, type SplitInvite } from "@/lib/p02-types"
import { MAX_TAGS, parseTagText, sameTags, tagTextSchema } from "@/lib/references"
import type { CreatedInvite, InviteInfo, InvitesResponse, PendingEnrollment } from "@/lib/types"
import { cn } from "@/lib/utils"

const passphrase = z.string().min(1, msg("Kök anahtar parolası gerekli")).max(1024, msg("Parola çok uzun"))
const refreshKeys = ["/api/invites", "/api/devices", "/api/overview", "/api/history", "/api/network"]

interface InvitesPanelProps {
  /** The "Cihaz davet et" dialog, opened from the page's add menu. */
  inviting: boolean
  onInvitingChange: (open: boolean) => void
}

/**
 * The approval queue and the open invites, polled while the page is open.
 * Renders nothing but its dialogs while there is nothing waiting.
 */
export function InvitesPanel({ inviting, onInvitingChange }: InvitesPanelProps) {
  const { t, ts } = useI18n()
  const { data } = useSWR<InvitesResponse>("/api/invites", fetcher, { refreshInterval: 3_000 })
  const [approving, setApproving] = useState<PendingEnrollment | null>(null)
  const [revoking, setRevoking] = useState<InviteInfo | null>(null)
  const pending = data?.pending ?? []
  const open = (data?.invites ?? []).filter((i) => !i.used)

  return (
    <>
      {pending.length > 0 ? (
        <section aria-labelledby="pending-title" className="flex flex-col gap-2">
          <div className="flex flex-col gap-1">
            <h2 id="pending-title" className="flex items-center gap-2 text-base font-semibold">
              <BellRing className="size-4" />
              {t("Onay bekleyen cihazlar ({count})", { count: pending.length })}
            </h2>
            <p className="text-sm text-muted-foreground">{t("Kod yeni bilgisayarın ekranındakiyle aynıysa onayla.")}</p>
          </div>
          <ul className="flex flex-col divide-y rounded-lg border">
            {pending.map((p) => (
              <li
                key={`${p.inviteId}-${p.deviceId ?? ""}`}
                className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="flex flex-col gap-1">
                  <span className="font-medium">{p.hostname || t("Adsız cihaz")}</span>
                  <span className="text-sm text-muted-foreground">{t("İstek: {time}", { time: formatDateTime(p.requestedAt) })}</span>
                  <TagList tags={p.tags ?? []} />
                </div>
                <div className="flex items-center gap-3">
                  <ShortCode code={p.shortCode} />
                  {p.deviceId ? <RejectButton pending={p} /> : null}
                  <Button onClick={() => setApproving(p)}>
                    <Check data-icon="inline-start" />
                    {t("Onayla")}
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {open.length > 0 || data?.pendingError ? (
        <section aria-labelledby="open-invites-title" className="flex flex-col gap-2">
          <h2 id="open-invites-title" className="text-base font-semibold">
            {t("Açık davetler ({count})", { count: open.length })}
          </h2>
          {open.length > 0 ? (
            <ul className="flex flex-col divide-y rounded-lg border text-sm">
              {open.map((inv) => (
                <li key={inv.id} className="flex items-center justify-between gap-4 px-4 py-2.5">
                  <span className="flex flex-col gap-1">
                    <span className="flex items-center gap-2 text-muted-foreground">
                      <Clock className="size-4 shrink-0" />
                      {t("{time} tarihine kadar geçerli", { time: formatDateTime(inv.expiresAt) })}
                      {(inv.maxUses ?? 1) > 1 ? ` · ${t("{used}/{max} kullanıldı", { used: inv.useCount ?? 0, max: inv.maxUses ?? 1 })}` : ""}
                    </span>
                    {inv.note ? <span className="text-foreground">{inv.note}</span> : null}
                    <TagList tags={inv.tags ?? []} />
                  </span>
                  <Button variant="ghost" size="sm" onClick={() => setRevoking(inv)}>
                    <TicketX data-icon="inline-start" />
                    {t("İptal et")}
                  </Button>
                </li>
              ))}
            </ul>
          ) : null}
          {data?.pendingError ? <p className="text-sm text-muted-foreground">{ts(data.pendingError)}</p> : null}
        </section>
      ) : null}

      <InviteDialog open={inviting} onOpenChange={onInvitingChange} />
      <ApproveDialog pending={approving} onClose={() => setApproving(null)} />
      <RevokeInviteDialog invite={revoking} onClose={() => setRevoking(null)} />
    </>
  )
}

/** Rejects one pending request without revoking its invite (F-107). */
function RejectButton({ pending }: { pending: PendingEnrollment }) {
  const { t } = useI18n()
  const { mutate } = useSWRConfig()
  const [busy, setBusy] = useState(false)
  async function reject() {
    setBusy(true)
    try {
      await post("/api/invites/reject", { inviteId: pending.inviteId, deviceId: pending.deviceId })
      toast.success(t("İstek reddedildi; davet geçerli kalıyor."))
      await mutate("/api/invites")
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Button variant="outline" onClick={reject} disabled={busy}>
      {busy ? <Spinner data-icon="inline-start" /> : <TicketX data-icon="inline-start" />}
      {t("Reddet")}
    </Button>
  )
}

function ShortCode({ code }: { code: string }) {
  const { t } = useI18n()
  return (
    <span aria-label={t("Doğrulama kodu {code}", { code: code.split("").join(" ") })} className="flex gap-1">
      {code.split("").map((d, i) => (
        <span key={`${i}-${d}`} className="flex h-10 w-8 items-center justify-center rounded-md border bg-background font-mono text-xl font-semibold">
          {d}
        </span>
      ))}
    </span>
  )
}

const lifetimes = [
  { hours: 1, label: msg("1 saat") },
  { hours: 24, label: msg("1 gün") },
  { hours: 168, label: msg("7 gün") },
]

/**
 * How the invite is handed over: one code, a code split in two parts for
 * two channels (#359, ADR-0157), or a small setup file that carries the
 * code (#360).
 */
type InviteMode = "code" | "split" | "launcher"

const inviteModes: { value: InviteMode; label: string }[] = [
  { value: "code", label: msg("Tek kod") },
  { value: "split", label: msg("İki parçalı kod") },
  { value: "launcher", label: msg("Kurulum dosyası") },
]

/** A launcher invite lives at most a day (internal/panel/p02_api.go). */
const LAUNCHER_MAX_HOURS = 24

type Created =
  | { kind: "code"; invite: CreatedInvite }
  | { kind: "split"; split: SplitInvite }
  | { kind: "launcher"; launcher: InviteLauncher }

/** Saves a base64 file body the server returned under its own name. */
function saveBase64(fileName: string, content: string) {
  const bytes = Uint8Array.from(atob(content), (c) => c.charCodeAt(0))
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }))
  const a = document.createElement("a")
  a.href = url
  a.download = fileName
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1_000)
}

const inviteSchema = z.object({
  passphrase,
  lifetimeHours: z.number().int().min(1).max(168),
  tags: tagTextSchema,
  // Multi-use invites and local notes (ADR-0028, F-184, F-132).
  maxUses: z.number({ message: msg("Sayı girin") }).int().min(1, msg("En az 1")).max(64, msg("En fazla 64")),
  note: z.string().trim().max(120, msg("En fazla 120 karakter")),
})
type InviteValues = z.infer<typeof inviteSchema>

function InviteDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const { t } = useI18n()
  const { mutate } = useSWRConfig()
  const [created, setCreated] = useState<Created | null>(null)
  const [mode, setMode] = useState<InviteMode>("code")
  const [platform, setPlatform] = useState<"windows" | "linux">("windows")
  const form = useForm<InviteValues>({
    resolver: zodResolver(inviteSchema),
    defaultValues: { passphrase: "", lifetimeHours: 1, tags: "", maxUses: 1, note: "" },
  })
  const { errors, isSubmitting } = form.formState

  function close(v: boolean) {
    if (!v) {
      setCreated(null)
      setMode("code")
      form.reset()
    }
    onOpenChange(v)
  }

  async function onSubmit(values: InviteValues) {
    try {
      const tags = parseTagText(values.tags)
      const common = {
        passphrase: values.passphrase,
        ...(tags.length > 0 ? { tags } : {}),
        ...(values.note ? { note: values.note } : {}),
      }
      if (mode === "split") {
        const split = await post<SplitInvite>("/api/p02/invites/split", { ...common, lifetimeHours: values.lifetimeHours })
        setCreated({ kind: "split", split })
      } else if (mode === "launcher") {
        const launcher = await post<InviteLauncher>("/api/p02/invites/launcher", {
          ...common,
          platform,
          lifetimeHours: Math.min(values.lifetimeHours, LAUNCHER_MAX_HOURS),
        })
        saveBase64(launcher.fileName, launcher.content)
        setCreated({ kind: "launcher", launcher })
      } else {
        const invite = await post<CreatedInvite>("/api/invites", {
          ...common,
          lifetimeHours: values.lifetimeHours,
          ...(values.maxUses > 1 ? { maxUses: values.maxUses } : {}),
        })
        setCreated({ kind: "code", invite })
      }
      form.reset()
      await Promise.all(refreshKeys.map((k) => mutate(k)))
    } catch (err) {
      form.setValue("passphrase", "")
      form.setError("passphrase", { message: errorMessage(err) })
    }
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{created ? t(createdTitle[created.kind]) : t("Cihaz davet et")}</DialogTitle>
          <DialogDescription className="text-pretty">
            {created
              ? t(createdText[created.kind])
              : t("Davet, kök anahtarınla imzalanıp ağ belgesine eklenir. Süresi dolunca kendiliğinden geçersiz olur.")}
          </DialogDescription>
        </DialogHeader>
        {created ? (
          <div className="flex flex-col gap-3">
            <CreatedView created={created} />
            <DialogFooter>
              <Button onClick={() => close(false)}>{t("Tamam")}</Button>
            </DialogFooter>
          </div>
        ) : (
          <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-6">
            <FieldGroup>
              <Field>
                <FieldLabel id="invite-mode-label">{t("Nasıl verilecek")}</FieldLabel>
                <div
                  role="radiogroup"
                  aria-labelledby="invite-mode-label"
                  onKeyDown={radioGroupKeyDown}
                  className="flex w-fit max-w-full flex-wrap rounded-lg border bg-card p-0.5"
                >
                  {inviteModes.map((m) => (
                    <button
                      key={m.value}
                      type="button"
                      role="radio"
                      aria-checked={mode === m.value}
                      tabIndex={mode === m.value ? 0 : -1}
                      onClick={() => setMode(m.value)}
                      className={cn(
                        "rounded-md px-3 py-1.5 text-sm transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50",
                        mode === m.value ? "bg-secondary font-medium text-foreground" : "text-muted-foreground hover:text-foreground"
                      )}
                    >
                      {t(m.label)}
                    </button>
                  ))}
                </div>
                <FieldDescription className="text-pretty">{t(modeText[mode])}</FieldDescription>
              </Field>
              {mode === "launcher" ? (
                <Field>
                  <FieldLabel htmlFor="invite-platform">{t("Yeni cihazın sistemi")}</FieldLabel>
                  <NativeSelect id="invite-platform" value={platform} onChange={(e) => setPlatform(e.target.value === "linux" ? "linux" : "windows")}>
                    <option value="windows">Windows (.cmd)</option>
                    <option value="linux">Linux (.sh)</option>
                  </NativeSelect>
                </Field>
              ) : null}
              <Field>
                <FieldLabel id="invite-life-label">{t("Geçerlilik süresi")}</FieldLabel>
                <Controller
                  control={form.control}
                  name="lifetimeHours"
                  render={({ field }) => (
                    <div
                      role="radiogroup"
                      aria-labelledby="invite-life-label"
                      onKeyDown={radioGroupKeyDown}
                      className="flex w-fit rounded-lg border bg-card p-0.5"
                    >
                      {lifetimes.map((l) => (
                        <button
                          key={l.hours}
                          type="button"
                          role="radio"
                          aria-checked={field.value === l.hours}
                          tabIndex={field.value === l.hours ? 0 : -1}
                          disabled={mode === "launcher" && l.hours > LAUNCHER_MAX_HOURS}
                          onClick={() => field.onChange(l.hours)}
                          className={cn(
                            "rounded-md px-3 py-1.5 text-sm transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50 disabled:opacity-50",
                            field.value === l.hours ? "bg-secondary font-medium text-foreground" : "text-muted-foreground hover:text-foreground"
                          )}
                        >
                          {t(l.label)}
                        </button>
                      ))}
                    </div>
                  )}
                />
                <FieldDescription>
                  {mode === "launcher"
                    ? t("Kurulum dosyasındaki davet en çok 1 gün geçerli olur.")
                    : t("Kısa süre daha güvenli; kodu hemen kullanacaksan 1 saat yeterli.")}
                </FieldDescription>
              </Field>
              <Field data-invalid={errors.tags ? true : undefined}>
                <FieldLabel htmlFor="invite-tags">{t("Etiketler (isteğe bağlı)")}</FieldLabel>
                <Input
                  id="invite-tags"
                  autoComplete="off"
                  spellCheck={false}
                  className="font-mono"
                  placeholder={t("sunucu, ofis")}
                  aria-invalid={errors.tags ? true : undefined}
                  {...form.register("tags")}
                />
                <FieldDescription>
                  {t(
                    "Katılan cihaz bu etiketlerle eklenir; kurallar ona hemen tag:ad ile başvurabilir. Virgül veya boşlukla ayır, en fazla {max}.",
                    { max: MAX_TAGS },
                  )}
                </FieldDescription>
                <FieldError errors={[errors.tags]} />
              </Field>
              <Field data-invalid={errors.maxUses ? true : undefined} hidden={mode !== "code"}>
                <FieldLabel htmlFor="invite-uses">{t("Kaç cihaz katılabilir")}</FieldLabel>
                <Input
                  id="invite-uses"
                  type="number"
                  min={1}
                  max={64}
                  className="w-24"
                  aria-invalid={errors.maxUses ? true : undefined}
                  {...form.register("maxUses", { valueAsNumber: true })}
                />
                <FieldDescription>
                  {t("1'den fazlaysa kod birden çok cihazda kullanılabilir; her cihazı yine 4 haneli kodla ayrı ayrı onaylarsın.")}
                </FieldDescription>
                <FieldError errors={[errors.maxUses]} />
              </Field>
              <Field data-invalid={errors.note ? true : undefined}>
                <FieldLabel htmlFor="invite-note">{t("Açıklama (isteğe bağlı)")}</FieldLabel>
                <Input
                  id="invite-note"
                  autoComplete="off"
                  placeholder={t("Ayşe'nin telefonu")}
                  aria-invalid={errors.note ? true : undefined}
                  {...form.register("note")}
                />
                <FieldDescription>{t("Yalnızca bu bilgisayarda tutulur; imzalı ağ belgesine girmez.")}</FieldDescription>
                <FieldError errors={[errors.note]} />
              </Field>
              <Field data-invalid={errors.passphrase ? true : undefined}>
                <FieldLabel htmlFor="invite-pass">{t("Kök anahtar parolası")}</FieldLabel>
                <Input id="invite-pass" type="password" autoComplete="current-password" autoFocus {...form.register("passphrase")} />
                <FieldError errors={[errors.passphrase]} />
              </Field>
            </FieldGroup>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => close(false)}>
                {t("Vazgeç")}
              </Button>
              <Button type="submit" disabled={isSubmitting}>
                {isSubmitting ? (
                  <Spinner data-icon="inline-start" />
                ) : mode === "launcher" ? (
                  <Download data-icon="inline-start" />
                ) : (
                  <Ticket data-icon="inline-start" />
                )}
                {mode === "launcher" ? t("Kurulum dosyasını indir") : t("Davet oluştur")}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

const modeText: Record<InviteMode, string> = {
  code: msg("Yeni cihaz kodu 'Ağa katıl' ekranına yapıştırır."),
  split:
    msg("Kod iki parçaya bölünür: birini mesajla, diğerini telefonda okuyarak ver. Tek parçayı ele geçiren katılım başlatamaz. Eski sürümdeki cihazlar bölünmüş kodu tanımaz."),
  launcher:
    msg("Kodu taşıyan küçük bir dosya iner; internetten bir şey indirmez. Windows'ta kodu panoya koyup uygulamayı açar, Linux'ta katılımı doğrudan başlatır. Katılım yine senin onayını ister."),
}

const createdTitle: Record<Created["kind"], string> = {
  code: msg("Davet kodu hazır"),
  split: msg("İki parçalı davet hazır"),
  launcher: msg("Kurulum dosyası indirildi"),
}

const createdText: Record<Created["kind"], string> = {
  code: msg("Yeni bilgisayarda OpenScale'i aç, Davet koduyla katıl'ı seç ve bu kodu yapıştır. Kod seçtiğin sayıda cihaz için geçerlidir."),
  split: msg("Yeni cihaz iki parçayı 'Ağa katıl' ekranına aynı alana, aralarında boşlukla yazar. İki parçayı aynı kanaldan gönderme."),
  launcher: msg("Dosyayı yeni cihaza kendin taşı. Windows'ta OpenScale kurulu değilse resmi kurulum dosyasını yanına koy."),
}

/** "ABCD EFGH IJKL" groups for reading a part aloud. */
function readable(code: string): string {
  return code.replace(/\s+/g, "").replace(/(.{4})(?=.)/g, "$1 ")
}

function CreatedView({ created }: { created: Created }) {
  const { t } = useI18n()
  if (created.kind === "code") {
    return (
      <>
        <CodeLine value={created.invite.code} label={t("Davet kodunu kopyala")} secret />
        <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
          {t(
            "Geçerlilik: {time}. Kodu kendin taşı; içinde ağına bağlanma anahtarı var. Kodu ele geçiren biri de istek gönderebilir, bu yüzden onaylarken 4 haneli kodu mutlaka karşılaştır.",
            { time: formatDateTime(created.invite.expiresAt) },
          )}
        </p>
      </>
    )
  }
  if (created.kind === "split") {
    return (
      <>
        <div className="flex flex-col gap-1.5">
          <span className="text-sm font-medium">{t("A parçası: mesajla gönder")}</span>
          <CodeLine value={created.split.partA} label={t("A parçasını kopyala")} secret />
        </div>
        <div className="flex flex-col gap-1.5">
          <span className="text-sm font-medium">{t("B parçası: telefonda oku")}</span>
          <p
            aria-label={t("B parçası {code}", { code: created.split.partB.split("").join(" ") })}
            className="rounded-lg border bg-muted/40 px-4 py-3 text-center font-mono text-xl font-semibold tracking-widest break-all"
          >
            {readable(created.split.partB)}
          </p>
        </div>
        <p className="text-sm leading-relaxed text-muted-foreground">{t("Geçerlilik: {time}.", { time: formatDateTime(created.split.expiresAt) })}</p>
      </>
    )
  }
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-3 rounded-lg border px-4 py-3">
        <span className="min-w-0 truncate font-mono text-[0.8125rem]">{created.launcher.fileName}</span>
        <Button variant="outline" size="sm" onClick={() => saveBase64(created.launcher.fileName, created.launcher.content)}>
          <Download data-icon="inline-start" />
          {t("Yeniden indir")}
        </Button>
      </div>
      <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
        {t("Davet {time} tarihinde geçersiz olur. Dosya davet kodunu açık taşır; kimseyle paylaşma ve işin bitince sil.", {
          time: formatDateTime(created.launcher.expiresAt),
        })}
      </p>
    </div>
  )
}

const approveSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, msg("Ad gerekli"))
    .max(63, msg("En fazla 63 karakter"))
    .regex(/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/, msg("Küçük harf, rakam ve tire; tireyle başlayıp bitemez")),
  exitNode: z.boolean(),
  // A temporary device leaves by itself after 24 hours (ADR-0028, #22).
  ephemeral: z.boolean(),
  tags: tagTextSchema,
  passphrase,
})
type ApproveValues = z.infer<typeof approveSchema>

function ApproveDialog({ pending, onClose }: { pending: PendingEnrollment | null; onClose: () => void }) {
  return (
    <Dialog open={pending !== null} onOpenChange={(v) => (!v ? onClose() : undefined)}>
      <DialogContent className="sm:max-w-md">
        {pending ? <ApproveForm key={`${pending.inviteId}-${pending.deviceId ?? ""}`} pending={pending} onClose={onClose} /> : null}
      </DialogContent>
    </Dialog>
  )
}

/** Hours left of a guest's access, for a guest invite's device (#368). */
function useGuestHours(pending: PendingEnrollment): number | null {
  const guestTag = (pending.tags ?? []).find((t) => t.startsWith(GUEST_TAG_PREFIX))
  const { data } = useSWR<GuestsResponse>(guestTag ? "/api/p02/guests" : null, fetcher)
  if (!guestTag) return null
  const until = data?.guests.find((g) => g.tag === guestTag)?.until
  if (!until) return null
  const hours = Math.ceil((new Date(until).getTime() - Date.now()) / 3_600_000)
  // A temporary device lives at most 30 days (trust.MaxEphemeralLife).
  return Math.min(Math.max(hours, 1), 720)
}

function ApproveForm({ pending, onClose }: { pending: PendingEnrollment; onClose: () => void }) {
  const { t } = useI18n()
  const { mutate } = useSWRConfig()
  const isGuest = (pending.tags ?? []).some((t) => t.startsWith(GUEST_TAG_PREFIX))
  const guestHours = useGuestHours(pending)
  const form = useForm<ApproveValues>({
    resolver: zodResolver(approveSchema),
    // A guest's device leaves when the guest's rule ends: temporary by default.
    defaultValues: { name: pending.hostname || "", exitNode: false, ephemeral: isGuest, tags: (pending.tags ?? []).join(", "), passphrase: "" },
  })
  const { errors, isSubmitting } = form.formState

  async function onSubmit(values: ApproveValues) {
    try {
      // Tags are sent only when changed; when present they replace the
      // invite's tags (an empty list removes them).
      const tags = parseTagText(values.tags)
      const res = await post<{ name: string; ipv4: string }>("/api/invites/approve", {
        name: values.name,
        exitNode: values.exitNode,
        passphrase: values.passphrase,
        inviteId: pending.inviteId,
        shortCode: pending.shortCode,
        ...(pending.deviceId ? { deviceId: pending.deviceId } : {}),
        ...(values.ephemeral ? { ephemeral: true, ...(guestHours !== null ? { lifetimeHours: guestHours } : {}) } : {}),
        ...(sameTags(tags, pending.tags ?? []) ? {} : { tags }),
      })
      toast.success(t("{name} ağa eklendi ({ip}).", { name: res.name, ip: res.ipv4 }))
      await Promise.all(refreshKeys.map((k) => mutate(k)))
      onClose()
    } catch (err) {
      form.setValue("passphrase", "")
      form.setError("passphrase", { message: errorMessage(err) })
    }
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("Cihazı onayla")}</DialogTitle>
        <DialogDescription className="text-pretty">
          {t("Yeni bilgisayarın ekranındaki kod aşağıdakiyle aynı olmalı. Farklıysa onaylama ve daveti iptal et.")}
        </DialogDescription>
      </DialogHeader>
      <div className="flex flex-col items-center gap-2 rounded-xl border bg-muted/40 p-4">
        <ShortCode code={pending.shortCode} />
        <span className="font-mono text-[0.8125rem] text-muted-foreground">{t("Parmak izi {fingerprint}", { fingerprint: pending.fingerprint })}</span>
      </div>
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-6">
        <FieldGroup>
          <Field data-invalid={errors.name ? true : undefined}>
            <FieldLabel htmlFor="approve-name">{t("Cihaz adı")}</FieldLabel>
            <Input id="approve-name" autoComplete="off" {...form.register("name")} />
            <FieldError errors={[errors.name]} />
          </Field>
          <Field orientation="horizontal">
            <Controller
              control={form.control}
              name="exitNode"
              render={({ field }) => <Switch id="approve-exit" checked={field.value} onCheckedChange={field.onChange} />}
            />
            <FieldLabel htmlFor="approve-exit">{t("Çıkış düğümü olabilsin")}</FieldLabel>
          </Field>
          <Field orientation="horizontal">
            <Controller
              control={form.control}
              name="ephemeral"
              render={({ field }) => <Switch id="approve-ephemeral" checked={field.value} onCheckedChange={field.onChange} />}
            />
            <FieldLabel htmlFor="approve-ephemeral">
              {guestHours !== null
                ? t("Geçici (konuk) cihaz: {count} saat sonra, konuk erişimiyle birlikte düşer", { count: guestHours })
                : t("Geçici (misafir) cihaz: 24 saat sonra kendiliğinden düşer")}
            </FieldLabel>
          </Field>
          <Field data-invalid={errors.tags ? true : undefined}>
            <FieldLabel htmlFor="approve-tags">{t("Etiketler")}</FieldLabel>
            <Input
              id="approve-tags"
              autoComplete="off"
              spellCheck={false}
              className="font-mono"
              placeholder={t("sunucu, ofis")}
              aria-invalid={errors.tags ? true : undefined}
              {...form.register("tags")}
            />
            <FieldDescription>
              {t("Davetteki etiketler hazır gelir. Değiştirirsen davetin etiketlerinin yerine geçer; boş bırakmak hepsini kaldırır.")}
            </FieldDescription>
            <FieldError errors={[errors.tags]} />
          </Field>
          <Field data-invalid={errors.passphrase ? true : undefined}>
            <FieldLabel htmlFor="approve-pass">{t("Kök anahtar parolası")}</FieldLabel>
            <Input id="approve-pass" type="password" autoComplete="current-password" {...form.register("passphrase")} />
            <FieldError errors={[errors.passphrase]} />
          </Field>
        </FieldGroup>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose}>
            {t("Vazgeç")}
          </Button>
          <Button type="submit" disabled={isSubmitting}>
            {isSubmitting ? <Spinner data-icon="inline-start" /> : <Check data-icon="inline-start" />}
            {t("Kodlar aynı, onayla")}
          </Button>
        </DialogFooter>
      </form>
    </>
  )
}

const revokeSchema = z.object({ passphrase })
type RevokeValues = z.infer<typeof revokeSchema>

function RevokeInviteDialog({ invite, onClose }: { invite: InviteInfo | null; onClose: () => void }) {
  const { t } = useI18n()
  const { mutate } = useSWRConfig()
  const form = useForm<RevokeValues>({ resolver: zodResolver(revokeSchema), defaultValues: { passphrase: "" } })
  const { errors, isSubmitting } = form.formState

  async function onSubmit(values: RevokeValues) {
    if (!invite) return
    try {
      await post("/api/invites/revoke", { ...values, inviteId: invite.id })
      toast.success(t("Davet iptal edildi."))
      form.reset()
      await Promise.all(refreshKeys.map((k) => mutate(k)))
      onClose()
    } catch (err) {
      form.setValue("passphrase", "")
      form.setError("passphrase", { message: errorMessage(err) })
    }
  }

  return (
    <Dialog
      open={invite !== null}
      onOpenChange={(v) => {
        if (!v) {
          form.reset()
          onClose()
        }
      }}
    >
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("Daveti iptal et")}</DialogTitle>
          <DialogDescription>{t("Kod artık kullanılamaz. Bekleyen istek varsa düşer.")}</DialogDescription>
        </DialogHeader>
        <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-6">
          <Field data-invalid={errors.passphrase ? true : undefined}>
            <FieldLabel htmlFor="revoke-invite-pass">{t("Kök anahtar parolası")}</FieldLabel>
            <Input id="revoke-invite-pass" type="password" autoComplete="current-password" autoFocus {...form.register("passphrase")} />
            <FieldError errors={[errors.passphrase]} />
          </Field>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t("Vazgeç")}
            </Button>
            <Button type="submit" variant="destructive" disabled={isSubmitting}>
              {isSubmitting ? <Spinner data-icon="inline-start" /> : <TicketX data-icon="inline-start" />}
              {t("İptal et")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
