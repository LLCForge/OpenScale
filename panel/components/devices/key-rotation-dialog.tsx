"use client"

import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { ShieldAlert } from "lucide-react"

import { SignChange } from "@/components/sign-change"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { Textarea } from "@/components/ui/textarea"
import { errorMessage, post } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import type { RotationInspectResponse } from "@/lib/types"

const requestSchema = z.object({
  request: z
    .string()
    .trim()
    .min(1, msg("Anahtar yenileme isteği gerekli"))
    .max(4096, msg("İstek çok uzun"))
    .startsWith("osrot1.", msg("Bu bir OpenScale anahtar yenileme isteği değil; 'osrot1.' ile başlamalı")),
})

const fingerprintSchema = z.object({
  fingerprint: z
    .string()
    .trim()
    .regex(/^[A-Za-z2-7]{4}-?[A-Za-z2-7]{4}-?[A-Za-z2-7]{4}-?[A-Za-z2-7]{4}$/, msg("Parmak izi XXXX-XXXX-XXXX-XXXX biçiminde olmalı")),
})

type RequestForm = z.infer<typeof requestSchema>
type FingerprintForm = z.infer<typeof fingerprintSchema>

type Step =
  | { kind: "request" }
  | { kind: "fingerprint"; request: string; inspected: RotationInspectResponse }
  | { kind: "sign"; request: string; fingerprint: string; deviceName: string }

interface KeyRotationDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** When opened from a device's page, a request for another device is refused. */
  expectedName?: string
}

/**
 * Installs a device's new keys from its rotation request (ADR-0020). Like
 * adding a device, the owner types the fingerprint shown on the device; the
 * panel never displays it.
 */
export function KeyRotationDialog({ open, onOpenChange, expectedName }: KeyRotationDialogProps) {
  const { t } = useI18n()
  const [step, setStep] = useState<Step>({ kind: "request" })

  function handleOpenChange(next: boolean) {
    if (!next) setStep({ kind: "request" })
    onOpenChange(next)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("Anahtar yenileme isteği")}</DialogTitle>
          <DialogDescription className="text-pretty">
            {step.kind === "request" && t("1/3: Cihazın ürettiği anahtar yenileme isteğini yapıştır.")}
            {step.kind === "fingerprint" && t("2/3: Cihazın ekranındaki yeni parmak izini kendin yaz. Panel bu değeri sana göstermez.")}
            {step.kind === "sign" && t("3/3: Değişikliği kontrol et ve kök anahtarınla imzala.")}
          </DialogDescription>
        </DialogHeader>
        {open && step.kind === "request" ? (
          <RequestStep expectedName={expectedName} onNext={(request, inspected) => setStep({ kind: "fingerprint", request, inspected })} />
        ) : null}
        {open && step.kind === "fingerprint" ? (
          <FingerprintStep
            inspected={step.inspected}
            onBack={() => setStep({ kind: "request" })}
            onNext={(fingerprint) =>
              setStep({ kind: "sign", request: step.request, fingerprint, deviceName: step.inspected.deviceName })
            }
          />
        ) : null}
        {open && step.kind === "sign" ? (
          <SignChange
            endpoint="/api/devices/rotation"
            payload={{ request: step.request, fingerprint: step.fingerprint }}
            confirmLabel={t("İmzala ve {name} anahtarlarını yenile", { name: step.deviceName })}
            onBack={() => setStep({ kind: "request" })}
            onDone={() => handleOpenChange(false)}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

function StolenKeyNote() {
  const { t } = useI18n()
  return (
    <Alert>
      <ShieldAlert />
      <AlertTitle>{t("Anahtar çalınmış olabilir mi?")}</AlertTitle>
      <AlertDescription className="text-pretty">
        {t(
          "Yenileme, cihazın kendi isteğiyle anahtarlarını değiştirir. Cihazın veya anahtarının ele geçirilmiş olabileceğinden şüpheleniyorsan yenileme yapma: cihazı ağdan kalıcı olarak çıkar ve sıfırlayıp yeni bir davetle yeniden ekle."
        )}
      </AlertDescription>
    </Alert>
  )
}

function RequestStep({
  expectedName,
  onNext,
}: {
  expectedName?: string
  onNext: (request: string, inspected: RotationInspectResponse) => void
}) {
  const { t } = useI18n()
  const form = useForm<RequestForm>({ resolver: zodResolver(requestSchema), defaultValues: { request: "" } })
  const [serverError, setServerError] = useState<string | null>(null)

  async function onSubmit(values: RequestForm) {
    setServerError(null)
    try {
      const inspected = await post<RotationInspectResponse>("/api/devices/rotation/inspect", { request: values.request })
      if (expectedName && inspected.deviceName !== expectedName) {
        setServerError(tx("Bu istek {name} cihazına ait, {expected} cihazına değil. Doğru isteği yapıştır.", { name: inspected.deviceName, expected: expectedName }))
        return
      }
      onNext(values.request, inspected)
    } catch (err) {
      setServerError(errorMessage(err))
    }
  }

  const { errors, isSubmitting } = form.formState
  return (
    <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
      <StolenKeyNote />
      <FieldGroup>
        <Field data-invalid={errors.request ? true : undefined}>
          <FieldLabel htmlFor="rotation-request">{t("Anahtar yenileme isteği")}</FieldLabel>
          <Textarea
            id="rotation-request"
            rows={5}
            spellCheck={false}
            autoComplete="off"
            className="font-mono text-xs break-all"
            placeholder="osrot1...."
            aria-invalid={errors.request ? true : undefined}
            {...form.register("request")}
          />
          <FieldDescription>{t("İstek yalnızca açık anahtarları içerir ve cihazın mevcut anahtarıyla imzalıdır.")}</FieldDescription>
          <FieldError errors={[errors.request]} />
        </Field>
      </FieldGroup>
      {serverError ? (
        <Alert variant="destructive">
          <AlertDescription>{serverError}</AlertDescription>
        </Alert>
      ) : null}
      <DialogFooter>
        <Button type="submit" disabled={isSubmitting}>
          {isSubmitting ? <Spinner data-icon="inline-start" /> : null}
          {t("İsteği doğrula")}
        </Button>
      </DialogFooter>
    </form>
  )
}

interface FingerprintStepProps {
  inspected: RotationInspectResponse
  onBack: () => void
  onNext: (fingerprint: string) => void
}

function FingerprintStep({ inspected, onBack, onNext }: FingerprintStepProps) {
  const { t } = useI18n()
  const form = useForm<FingerprintForm>({ resolver: zodResolver(fingerprintSchema), defaultValues: { fingerprint: "" } })
  const { errors } = form.formState

  return (
    <form onSubmit={form.handleSubmit((v) => onNext(v.fingerprint))} noValidate className="flex flex-col gap-4">
      <dl className="flex flex-col gap-2 rounded-lg border bg-muted/40 p-3 text-sm">
        <div className="flex justify-between gap-4">
          <dt className="text-muted-foreground">{t("Cihaz")}</dt>
          <dd className="font-medium">{inspected.deviceName}</dd>
        </div>
        <div className="flex justify-between gap-4">
          <dt className="text-muted-foreground">{t("Cihaz kimliği")}</dt>
          <dd className="font-mono text-xs">{inspected.deviceId}…</dd>
        </div>
        <div className="flex justify-between gap-4">
          <dt className="text-muted-foreground">{t("İstek zamanı")}</dt>
          <dd>{formatDateTime(inspected.createdAt)}</dd>
        </div>
      </dl>
      <FieldGroup>
        <Field data-invalid={errors.fingerprint ? true : undefined}>
          <FieldLabel htmlFor="rotation-fingerprint">{t("Yeni parmak izi")}</FieldLabel>
          <Input
            id="rotation-fingerprint"
            autoComplete="off"
            spellCheck={false}
            autoFocus
            className="font-mono uppercase"
            placeholder="XXXX-XXXX-XXXX-XXXX"
            aria-invalid={errors.fingerprint ? true : undefined}
            {...form.register("fingerprint")}
          />
          <FieldDescription>
            {t("Cihazın ekranında yazanı gir. Eşleşmezse istek yolda değiştirilmiş olabilir ve anahtarlar yenilenmez.")}
          </FieldDescription>
          <FieldError errors={[errors.fingerprint]} />
        </Field>
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
