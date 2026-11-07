"use client"

import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import useSWR, { useSWRConfig } from "swr"
import { toast } from "sonner"
import { ShieldCheck, TriangleAlert } from "lucide-react"

import { DiffList, removedRuleCount } from "@/components/diff-list"
import { PersonalDataWarnings, RiskSummary, splitPersonalData } from "@/components/security/risk-summary"
import { ErrorCodeHelp, ErrorCodeLink, errorCode } from "@/components/error-code"
import { TokenSignOption } from "@/components/shell/token-sign"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { errorMessage, post } from "@/lib/api"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { RiskReport } from "@/lib/pa-types"
import type { ChangeResponse } from "@/lib/types"
import { cn } from "@/lib/utils"

const passphraseSchema = z.object({
  passphrase: z.string().min(1, msg("Kök anahtar parolası gerekli")).max(1024, msg("Parola çok uzun")),
})

type PassphraseForm = z.infer<typeof passphraseSchema>

/** Every SWR key whose data changes when a new document version is signed. */
const documentKeys = ["/api/overview", "/api/devices", "/api/rules", "/api/history", "/api/network", "/api/invites", "/api/policy/report", "/api/policy/text"]

/** Keys with a query string, such as a device's detail page. */
function isDocumentKey(key: unknown): boolean {
  return typeof key === "string" && (documentKeys.includes(key) || key.startsWith("/api/devices/detail"))
}

/**
 * Red text on the 20% red fill of a destructive button falls under 4.5:1
 * in the dark theme; the text is lifted toward the foreground there.
 */
export const destructiveText = "dark:text-[color-mix(in_oklch,var(--destructive),var(--foreground)_45%)]"

/**
 * The server-computed dry run of a change. The dialog header and the form
 * share it through the SWR key, so it is fetched once.
 */
function usePreview(endpoint: string, payload: Record<string, unknown>, enabled = true) {
  return useSWR(
    enabled ? [endpoint, JSON.stringify(payload)] : null,
    () => post<PreviewResponse>(endpoint, { ...payload, dryRun: true }),
    { revalidateOnFocus: false, revalidateIfStale: false, shouldRetryOnError: false }
  )
}

/** The dry run with the G1 risk summary (ADR-0177); older servers leave it out. */
type PreviewResponse = ChangeResponse & { risk?: RiskReport | null }

/** A signed change's answer; some endpoints add their own fields. */
export type SignedResponse = ChangeResponse & Record<string, unknown>

interface SignChangeProps {
  endpoint: string
  payload: Record<string, unknown>
  confirmLabel: string
  destructive?: boolean
  /**
   * Text the owner types before an irreversible change can be signed,
   * usually the device name. Only used together with `destructive`.
   */
  confirmText?: string
  onBack?: () => void
  /** Shown as "Vazgeç" when there is no step to go back to. */
  onCancel?: () => void
  onDone: () => void
  /**
   * Receives the signed answer before onDone, for endpoints that return
   * more than the new version (the guest wizard's invite code).
   */
  onSigned?: (res: SignedResponse) => void
  /** Renders a plain footer instead of the dialog footer band (wizard pages). */
  inline?: boolean
}

function InlineFooter({ children }: { children: React.ReactNode }) {
  return <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">{children}</div>
}

/**
 * Shows the server-computed diff for a change (dry run) and signs it with
 * the root key passphrase. The passphrase is sent once and never stored.
 */
export function SignChange({ endpoint, payload, confirmLabel, destructive, confirmText, onBack, onCancel, onDone, onSigned, inline }: SignChangeProps) {
  const Footer = inline ? InlineFooter : DialogFooter
  const { t } = useI18n()
  const { mutate } = useSWRConfig()
  const preview = usePreview(endpoint, payload)
  const form = useForm<PassphraseForm>({
    resolver: zodResolver(passphraseSchema),
    defaultValues: { passphrase: "" },
  })
  const [typed, setTyped] = useState("")
  const [signCode, setSignCode] = useState<string | undefined>(undefined)
  const mustType = destructive && confirmText ? confirmText : null
  const typedOk = mustType === null || typed.trim() === mustType

  async function onSubmit(values: PassphraseForm) {
    if (!typedOk) return
    setSignCode(undefined)
    try {
      const res = await post<SignedResponse>(endpoint, { ...payload, dryRun: false, passphrase: values.passphrase })
      form.reset()
      setTyped("")
      await mutate(isDocumentKey)
      toast.success(t("Ağ belgesi sürüm {version} olarak imzalandı.", { version: res.version }))
      onSigned?.(res)
      onDone()
    } catch (err) {
      form.setValue("passphrase", "")
      form.setError("passphrase", { message: errorMessage(err) })
      setSignCode(errorCode(err))
    }
  }

  // "YubiKey ile imzala" (ADR-0223): the tray's token session signs.
  const [tokenSigning, setTokenSigning] = useState(false)
  async function onTokenSign() {
    if (!typedOk) return
    setSignCode(undefined)
    setTokenSigning(true)
    try {
      const res = await post<SignedResponse>(endpoint, { ...payload, dryRun: false, token: true })
      form.reset()
      setTyped("")
      await mutate(isDocumentKey)
      toast.success(t("Ağ belgesi sürüm {version} olarak YubiKey ile imzalandı.", { version: res.version }))
      onSigned?.(res)
      onDone()
    } catch (err) {
      form.setError("passphrase", { message: errorMessage(err) })
      setSignCode(errorCode(err))
    } finally {
      setTokenSigning(false)
    }
  }

  const { errors, isSubmitting } = form.formState

  // A wizard step shows both: "Vazgeç" leaves the whole flow, "Geri" one step.
  const leave =
    onBack || onCancel ? (
      <>
        {onCancel ? (
          <Button type="button" variant={onBack ? "ghost" : "outline"} onClick={onCancel} disabled={isSubmitting}>
            {t("Vazgeç")}
          </Button>
        ) : null}
        {onBack ? (
          <Button type="button" variant="outline" onClick={onBack} disabled={isSubmitting}>
            {t("Geri")}
          </Button>
        ) : null}
      </>
    ) : null

  if (preview.error) {
    return (
      <div className="flex flex-col gap-4">
        <Alert variant="destructive">
          <AlertDescription className="flex flex-col gap-2">
            <span>{errorMessage(preview.error)}</span>
            <ErrorCodeHelp error={preview.error} />
          </AlertDescription>
        </Alert>
        {leave ? <Footer>{leave}</Footer> : null}
      </div>
    )
  }

  if (!preview.data) {
    return (
      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-2" aria-busy="true" aria-label={t("Değişiklik hesaplanıyor")}>
          <Skeleton className="h-4 w-1/3" />
          <Skeleton className="h-20 w-full" />
        </div>
        {leave ? <Footer>{leave}</Footer> : null}
      </div>
    )
  }

  const { pii, rest } = splitPersonalData(preview.data.lines)
  const risk = preview.data.risk ?? null

  return (
    <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
      <FieldGroup>
        {risk ? <RiskSummary risk={risk} /> : null}
        <PersonalDataWarnings lines={pii} />
        <Field>
          <FieldLabel>{t("İmzalanacak değişiklikler")}</FieldLabel>
          <DiffList lines={rest} />
        </Field>
        {mustType ? (
          <Field data-invalid={typed !== "" && !typedOk ? true : undefined}>
            <FieldLabel htmlFor="sign-confirm-text">
              {withNode(t("Onaylamak için {name} yaz"), "name", <span className="font-mono font-semibold">{mustType}</span>)}
            </FieldLabel>
            <Input
              id="sign-confirm-text"
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              autoFocus
              className="font-mono"
              maxLength={256}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              aria-invalid={typed !== "" && !typedOk ? true : undefined}
              aria-describedby="sign-confirm-hint"
            />
            <FieldDescription id="sign-confirm-hint">{t("Bu işlem geri alınamaz; yanlış cihazı seçmediğinden emin olmak için adını yaz.")}</FieldDescription>
          </Field>
        ) : null}
        <Field data-invalid={errors.passphrase ? true : undefined}>
          <FieldLabel htmlFor="sign-passphrase">{t("Kök anahtar parolası")}</FieldLabel>
          <Input
            id="sign-passphrase"
            type="password"
            autoComplete="current-password"
            autoFocus={!mustType}
            aria-invalid={errors.passphrase ? true : undefined}
            {...form.register("passphrase")}
          />
          <FieldDescription>{t("Parola yalnızca bu imza için kullanılır, saklanmaz.")}</FieldDescription>
          <FieldError errors={[errors.passphrase]} />
          {signCode ? <ErrorCodeLink code={signCode} /> : null}
        </Field>
        <TokenSignOption disabled={isSubmitting || !typedOk} signing={tokenSigning} onSign={onTokenSign} />
      </FieldGroup>
      <Footer>
        {leave}
        <Button
          type="submit"
          variant={destructive ? "destructive" : "default"}
          className={cn(destructive && destructiveText)}
          disabled={isSubmitting || !typedOk}
        >
          {isSubmitting ? <Spinner data-icon="inline-start" /> : <ShieldCheck data-icon="inline-start" />}
          {confirmLabel}
        </Button>
      </Footer>
    </form>
  )
}

interface SignChangeDialogProps extends Omit<SignChangeProps, "onDone" | "onBack" | "onCancel" | "inline"> {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description: string
  /** Choices shown above the diff that change the payload (a shorter duration). */
  extra?: React.ReactNode
}

/**
 * A dialog that only previews and signs a prepared change. A destructive
 * change that also deletes rules says so above the description, before
 * the owner reads anything else.
 */
export function SignChangeDialog({ open, onOpenChange, title, description, extra, ...rest }: SignChangeDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {open && rest.destructive ? <CascadeWarning endpoint={rest.endpoint} payload={rest.payload} /> : null}
          <DialogDescription className="text-pretty">{description}</DialogDescription>
        </DialogHeader>
        {open && extra ? extra : null}
        {open ? <SignChange {...rest} onCancel={() => onOpenChange(false)} onDone={() => onOpenChange(false)} /> : null}
      </DialogContent>
    </Dialog>
  )
}

/** "Bununla birlikte silinecek: N kural" when the dry run removes rules too. */
function CascadeWarning({ endpoint, payload }: { endpoint: string; payload: Record<string, unknown> }) {
  const { t } = useI18n()
  const { data } = usePreview(endpoint, payload)
  const rules = data ? removedRuleCount(data.lines) : 0
  if (rules === 0) return null
  return (
    <Alert variant="destructive" className="mt-1">
      <TriangleAlert />
      <AlertTitle>{t("Bununla birlikte silinecek: {count} kural", { count: rules })}</AlertTitle>
      <AlertDescription className="text-pretty">
        {t("Bu cihaza bağlı erişim kuralları da belgeden kalkar. Hangileri olduğu aşağıdaki farkta kırmızı satırlarda.")}
      </AlertDescription>
    </Alert>
  )
}

/** Puts a node where the translated text has its {name} placeholder. */
function withNode(text: string, name: string, node: React.ReactNode): React.ReactNode {
  const mark = `{${name}}`
  const at = text.indexOf(mark)
  if (at < 0) return text
  return (
    <>
      {text.slice(0, at)}
      {node}
      {text.slice(at + mark.length)}
    </>
  )
}
