"use client"

import { useState } from "react"
import { useForm, Controller } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"

import { NearbyRequests } from "@/components/devices/nearby-requests"
import { radioGroupKeyDown } from "@/components/settings/radio-keys"
import { SignChange } from "@/components/sign-change"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { errorMessage, post } from "@/lib/api"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { NearbyRequest } from "@/lib/p02-types"
import type { InspectResponse } from "@/lib/types"
import { cn } from "@/lib/utils"

const requestSchema = z.object({
  request: z
    .string()
    .trim()
    .min(1, msg("Kayıt isteği gerekli"))
    .max(8192, msg("Kayıt isteği çok uzun"))
    .startsWith("osreq1.", msg("Bu bir OpenScale kayıt isteği değil; 'osreq1.' ile başlamalı")),
})

const detailsSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, msg("Cihaz adı gerekli"))
    .max(63, msg("En fazla 63 karakter"))
    .regex(/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/, msg("Küçük harf, rakam ve tire kullan; tire ile başlayıp bitemez")),
  fingerprint: z.string().trim(),
  sasMatches: z.boolean(),
  exitNode: z.boolean(),
  lifetimeDays: z.number().int().min(1, msg("En az 1 gün")).max(3650, msg("En fazla 3650 gün")),
  typedSas: z.string().trim().max(64, msg("Kod çok uzun")),
})

const fingerprintPattern = /^[A-Za-z2-7]{4}-?[A-Za-z2-7]{4}-?[A-Za-z2-7]{4}-?[A-Za-z2-7]{4}$/

type RequestForm = z.infer<typeof requestSchema>
type DetailsForm = z.infer<typeof detailsSchema>

type Step =
  | { kind: "request" }
  /** nearby: the request came over the local network; the owner types the short code. */
  | { kind: "details"; request: string; inspected: InspectResponse; nearby: boolean }
  | { kind: "sign"; payload: Record<string, unknown> }

interface AddDeviceDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function AddDeviceDialog({ open, onOpenChange }: AddDeviceDialogProps) {
  const { t } = useI18n()
  const [step, setStep] = useState<Step>({ kind: "request" })

  function handleOpenChange(next: boolean) {
    if (!next) setStep({ kind: "request" })
    onOpenChange(next)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("Cihaz ekle")}</DialogTitle>
          <DialogDescription>
            {step.kind === "request" && t("1/3: Yeni cihazın kayıt isteğini yapıştır ya da yerel ağdaki istekler arasından seç.")}
            {step.kind === "details" &&
              (step.nearby
                ? t("2/3: Yeni cihazın ekranındaki kısa kodu kendin yaz. Panel bu kodu sana göstermez.")
                : t("2/3: Yeni cihazın ekranındaki parmak izini kendin yaz. Panel bu değeri sana göstermez."))}
            {step.kind === "sign" && t("3/3: Değişikliği kontrol et ve kök anahtarınla imzala.")}
          </DialogDescription>
        </DialogHeader>
        {open && step.kind === "request" ? (
          <RequestStep
            onNext={(request, inspected, nearby) => setStep({ kind: "details", request, inspected, nearby })}
            onCancel={() => handleOpenChange(false)}
          />
        ) : null}
        {open && step.kind === "details" ? (
          <DetailsStep
            inspected={step.inspected}
            nearby={step.nearby}
            onBack={() => setStep({ kind: "request" })}
            onNext={(values) => {
              // Either the typed fingerprint or the compared short code (ADR-0062).
              const { sasMatches, fingerprint, typedSas, ...rest } = values
              const proof = step.nearby
                ? { sas: typedSas }
                : sasMatches && !fingerprint
                  ? { sas: step.inspected.sas ?? "" }
                  : { fingerprint }
              setStep({ kind: "sign", payload: { request: step.request, ...rest, ...proof } })
            }}
          />
        ) : null}
        {open && step.kind === "sign" ? (
          <SignChange
            endpoint="/api/devices"
            payload={step.payload}
            confirmLabel={t("İmzala ve ekle")}
            onBack={() => setStep({ kind: "request" })}
            onCancel={() => handleOpenChange(false)}
            onDone={() => handleOpenChange(false)}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

type RequestSource = "paste" | "nearby"

const sources: { value: RequestSource; label: string }[] = [
  { value: "paste", label: msg("İsteği yapıştır") },
  { value: "nearby", label: msg("Yakındaki istekler") },
]

interface RequestStepProps {
  onNext: (request: string, inspected: InspectResponse, nearby: boolean) => void
  onCancel: () => void
}

function RequestStep({ onNext, onCancel }: RequestStepProps) {
  const { t } = useI18n()
  const [source, setSource] = useState<RequestSource>("paste")
  const [picking, setPicking] = useState<string | null>(null)
  const [nearbyError, setNearbyError] = useState<string | null>(null)

  async function pick(r: NearbyRequest) {
    setPicking(r.deviceId)
    setNearbyError(null)
    try {
      const inspected = await post<InspectResponse>("/api/devices/inspect", { request: r.request })
      onNext(r.request, { ...inspected, suggestedName: inspected.suggestedName || r.hostname }, true)
    } catch (err) {
      setNearbyError(errorMessage(err))
    } finally {
      setPicking(null)
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div role="radiogroup" aria-label={t("İsteğin geldiği yer")} onKeyDown={radioGroupKeyDown} className="flex w-fit rounded-lg border bg-card p-0.5">
        {sources.map((s) => (
          <button
            key={s.value}
            type="button"
            role="radio"
            aria-checked={source === s.value}
            tabIndex={source === s.value ? 0 : -1}
            onClick={() => setSource(s.value)}
            className={cn(
              "rounded-md px-3 py-1.5 text-sm transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50",
              source === s.value ? "bg-secondary font-medium text-foreground" : "text-muted-foreground hover:text-foreground"
            )}
          >
            {t(s.label)}
          </button>
        ))}
      </div>
      {source === "paste" ? (
        <PasteRequest onNext={(request, inspected) => onNext(request, inspected, false)} onCancel={onCancel} />
      ) : (
        <>
          <NearbyRequests onPick={pick} picking={picking} />
          {nearbyError ? (
            <Alert variant="destructive">
              <AlertDescription>{nearbyError}</AlertDescription>
            </Alert>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onCancel}>
              {t("Vazgeç")}
            </Button>
          </DialogFooter>
        </>
      )}
    </div>
  )
}

function PasteRequest({ onNext, onCancel }: { onNext: (request: string, inspected: InspectResponse) => void; onCancel: () => void }) {
  const { t } = useI18n()
  const form = useForm<RequestForm>({ resolver: zodResolver(requestSchema), defaultValues: { request: "" } })
  const [serverError, setServerError] = useState<string | null>(null)

  async function onSubmit(values: RequestForm) {
    setServerError(null)
    try {
      const inspected = await post<InspectResponse>("/api/devices/inspect", { request: values.request })
      onNext(values.request, inspected)
    } catch (err) {
      setServerError(errorMessage(err))
    }
  }

  const { errors, isSubmitting } = form.formState
  return (
    <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
      <FieldGroup>
        <Field data-invalid={errors.request ? true : undefined}>
          <FieldLabel htmlFor="device-request">{t("Kayıt isteği")}</FieldLabel>
          <Textarea
            id="device-request"
            rows={5}
            spellCheck={false}
            autoComplete="off"
            className="font-mono text-[0.8125rem] break-all"
            placeholder="osreq1...."
            aria-invalid={errors.request ? true : undefined}
            {...form.register("request")}
          />
          <FieldDescription>{t("Yeni cihazda 'openscale keygen' çalıştır. İstek yalnızca açık anahtarları içerir ve 24 saat geçerlidir.")}</FieldDescription>
          <FieldError errors={[errors.request]} />
        </Field>
      </FieldGroup>
      {serverError ? (
        <Alert variant="destructive">
          <AlertDescription>{serverError}</AlertDescription>
        </Alert>
      ) : null}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          {t("Vazgeç")}
        </Button>
        <Button type="submit" disabled={isSubmitting}>
          {isSubmitting ? <Spinner data-icon="inline-start" /> : null}
          {t("İsteği doğrula")}
        </Button>
      </DialogFooter>
    </form>
  )
}

interface DetailsStepProps {
  inspected: InspectResponse
  nearby: boolean
  onBack: () => void
  onNext: (values: DetailsForm) => void
}

function DetailsStep({ inspected, nearby, onBack, onNext }: DetailsStepProps) {
  const { t } = useI18n()
  const form = useForm<DetailsForm>({
    resolver: zodResolver(detailsSchema),
    defaultValues: { name: inspected.suggestedName, fingerprint: "", sasMatches: false, exitNode: false, lifetimeDays: 365, typedSas: "" },
  })
  const { errors } = form.formState
  const [useSAS, setUseSAS] = useState(false)

  function submit(values: DetailsForm) {
    if (nearby) {
      // Digits only; the server compares it with the request's own code.
      if (values.typedSas.replace(/[^0-9]/g, "").length !== 20) {
        form.setError("typedSas", { message: msg("Kod 20 rakamdan oluşur; yeni cihazın ekranındakinin tamamını yaz") })
        return
      }
      onNext({ ...values, fingerprint: "", sasMatches: false })
      return
    }
    if (useSAS) {
      if (!values.sasMatches) {
        form.setError("sasMatches", { message: msg("Kodlar aynıysa onaylayın; farklıysa cihazı eklemeyin") })
        return
      }
      onNext({ ...values, fingerprint: "" })
      return
    }
    if (!fingerprintPattern.test(values.fingerprint)) {
      form.setError("fingerprint", { message: msg("Parmak izi XXXX-XXXX-XXXX-XXXX biçiminde olmalı") })
      return
    }
    onNext({ ...values, sasMatches: false })
  }

  return (
    <form onSubmit={form.handleSubmit(submit)} noValidate className="flex flex-col gap-4">
      <p className="text-sm text-muted-foreground">
        {t("İstek doğrulandı. Cihaz kimliği")} <span className="font-mono">{inspected.deviceId}…</span>
      </p>
      <FieldGroup>
        <Field data-invalid={errors.name ? true : undefined}>
          <FieldLabel htmlFor="device-name">{t("Cihaz adı")}</FieldLabel>
          <Input id="device-name" autoComplete="off" aria-invalid={errors.name ? true : undefined} {...form.register("name")} />
          <FieldDescription>{t("Ağda bu adla görünür, ör. laptop.openscale.internal")}</FieldDescription>
          <FieldError errors={[errors.name]} />
        </Field>
        {nearby ? (
          <Field data-invalid={errors.typedSas ? true : undefined}>
            <FieldLabel htmlFor="device-typed-sas">{t("Yeni cihazın ekranındaki kod")}</FieldLabel>
            <Input
              id="device-typed-sas"
              autoComplete="off"
              spellCheck={false}
              inputMode="numeric"
              className="font-mono tracking-widest"
              aria-invalid={errors.typedSas ? true : undefined}
              {...form.register("typedSas")}
            />
            <FieldDescription>
              {t("Yeni cihazda \"openscale key sas\" komutunun gösterdiği kodu yaz. Kod tutmazsa istek yolda değiştirilmiştir ve cihaz eklenmez.")}
            </FieldDescription>
            <FieldError errors={[errors.typedSas]} />
          </Field>
        ) : null}
        {inspected.sas && !nearby ? (
          <Field orientation="horizontal">
            <FieldContent>
              <FieldLabel htmlFor="device-use-sas">{t("Parmak izi yerine kısa kodu karşılaştır")}</FieldLabel>
              <FieldDescription>{t("Yeni cihazda \"openscale key sas\" komutunun gösterdiği 20 haneli kodla karşılaştırılır.")}</FieldDescription>
            </FieldContent>
            <Switch id="device-use-sas" checked={useSAS} onCheckedChange={(on) => setUseSAS(on)} />
          </Field>
        ) : null}
        {useSAS && inspected.sas ? (
          <Controller
            control={form.control}
            name="sasMatches"
            render={({ field }) => (
              <Field data-invalid={errors.sasMatches ? true : undefined}>
                <FieldLabel>{t("Kısa doğrulama kodu")}</FieldLabel>
                <p className="rounded-md bg-muted px-3 py-2 text-center font-mono text-lg tracking-widest">{inspected.sas}</p>
                <label className="flex items-center gap-2 text-sm">
                  <Checkbox checked={field.value} onCheckedChange={(v) => field.onChange(v === true)} />
                  {t("Yeni cihazın ekranındaki kod bununla birebir aynı")}
                </label>
                <FieldDescription>{t("Bir hane bile farklıysa istek yolda değiştirilmiştir; cihazı eklemeyin.")}</FieldDescription>
                <FieldError errors={[errors.sasMatches]} />
              </Field>
            )}
          />
        ) : null}
        <Field data-invalid={errors.fingerprint ? true : undefined} hidden={useSAS || nearby}>
          <FieldLabel htmlFor="device-fingerprint">{t("Parmak izi")}</FieldLabel>
          <Input
            id="device-fingerprint"
            autoComplete="off"
            spellCheck={false}
            className="font-mono uppercase"
            placeholder="XXXX-XXXX-XXXX-XXXX"
            aria-invalid={errors.fingerprint ? true : undefined}
            {...form.register("fingerprint")}
          />
          <FieldDescription>{t("Yeni cihazın ekranında yazanı gir. Eşleşmezse istek yolda değiştirilmiş olabilir ve cihaz eklenmez.")}</FieldDescription>
          <FieldError errors={[errors.fingerprint]} />
        </Field>
        <Field data-invalid={errors.lifetimeDays ? true : undefined}>
          <FieldLabel htmlFor="device-lifetime">{t("Üyelik süresi (gün)")}</FieldLabel>
          <Input
            id="device-lifetime"
            type="number"
            inputMode="numeric"
            min={1}
            max={3650}
            aria-invalid={errors.lifetimeDays ? true : undefined}
            {...form.register("lifetimeDays", { valueAsNumber: true })}
          />
          <FieldError errors={[errors.lifetimeDays]} />
        </Field>
        <Controller
          control={form.control}
          name="exitNode"
          render={({ field }) => (
            <Field orientation="horizontal">
              <FieldContent>
                <FieldLabel htmlFor="device-exit">{t("Çıkış düğümü olabilir")}</FieldLabel>
                <FieldDescription>{t("Diğer cihazlar internet trafiğini bu cihaz üzerinden çıkarabilir.")}</FieldDescription>
              </FieldContent>
              <Switch id="device-exit" checked={field.value} onCheckedChange={(checked) => field.onChange(checked)} />
            </Field>
          )}
        />
      </FieldGroup>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onBack}>
          {t("Geri")}
        </Button>
        <Button type="submit">{t("Değişikliği göster")}</Button>
      </DialogFooter>
    </form>
  )
}
