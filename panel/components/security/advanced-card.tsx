"use client"

import { Controller, useForm, useWatch, type UseFormRegisterReturn } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { RotateCcw, SlidersHorizontal } from "lucide-react"
import { toast } from "sonner"

import { useReadOnly } from "@/components/app/read-only"
import { TransportCard } from "@/components/security/transport-card"
import { TrafficCard } from "@/components/security/traffic-card"
import { RDeskCard } from "@/components/security/rdesk-card"
import { useAppStatus } from "@/components/app/use-app-status"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { errorMessage, post } from "@/lib/api"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import { RestartsConnectionBadge, useRestartConfirm } from "@/components/settings/restarts-connection"
import type { AppStatus } from "@/lib/types"
import { cn } from "@/lib/utils"

const KIB = 1024
const MIB = 1024 * KIB
const GIB = 1024 * MIB

const MTU_DEFAULT = 1280
const MTU_MAX = 1420
const RATE_MIN = 64 * KIB
const RATE_MAX = 10 * GIB
const BURST_MIN = 64 * KIB
const BURST_MAX = GIB

type Unit = "KiB" | "MiB"
const unitBytes: Record<Unit, number> = { KiB: KIB, MiB: MIB }

const number = (message: string) => z.number({ error: message }).min(0, msg("Negatif olamaz"))

const advancedSchema = z
  .object({
    forceRelay: z.boolean(),
    mtu: number(msg("MTU gir; varsayılan için 0")).int(msg("Tam sayı gir")),
    relayRate: number(msg("Hız gir; varsayılan için 0")),
    relayRateUnit: z.enum(["KiB", "MiB"]),
    relayBurst: number(msg("Miktar gir; varsayılan için 0")),
    relayBurstUnit: z.enum(["KiB", "MiB"]),
  })
  .superRefine((v, ctx) => {
    if (v.mtu !== 0 && (v.mtu < MTU_DEFAULT || v.mtu > MTU_MAX)) {
      ctx.addIssue({
        code: "custom",
        path: ["mtu"],
        message: tx("0 (varsayılan {default}) veya {min}-{max} arası olmalı", { default: MTU_DEFAULT, min: MTU_DEFAULT, max: MTU_MAX }),
      })
    } else if (v.forceRelay && v.mtu > MTU_DEFAULT) {
      ctx.addIssue({ code: "custom", path: ["mtu"], message: tx("Her zaman aktarıcı kullanılırken MTU en fazla {max} olabilir", { max: MTU_DEFAULT }) })
    }
    const rate = toBytes(v.relayRate, v.relayRateUnit)
    if (rate !== 0 && (rate < RATE_MIN || rate > RATE_MAX)) {
      ctx.addIssue({ code: "custom", path: ["relayRate"], message: msg("0 (varsayılan) veya 64 KiB/s ile 10 GiB/s arası olmalı") })
    }
    const burst = toBytes(v.relayBurst, v.relayBurstUnit)
    if (burst !== 0 && (burst < BURST_MIN || burst > BURST_MAX)) {
      ctx.addIssue({ code: "custom", path: ["relayBurst"], message: msg("0 (varsayılan) veya 64 KiB ile 1 GiB arası olmalı") })
    }
  })

type AdvancedForm = z.infer<typeof advancedSchema>

function toBytes(value: number, unit: Unit): number {
  return Math.round(value * unitBytes[unit])
}

/** Shows a byte count in MiB when it is a whole number of MiB, else in KiB. */
function fromBytes(bytes: number): { value: number; unit: Unit } {
  if (bytes === 0 || bytes % MIB === 0) return { value: bytes / MIB, unit: "MiB" }
  return { value: Math.round((bytes / KIB) * 1000) / 1000, unit: "KiB" }
}

function defaultsFrom(status: AppStatus): AdvancedForm {
  const rate = fromBytes(status.coordinator?.relayRate ?? 0)
  const burst = fromBytes(status.coordinator?.relayBurst ?? 0)
  return {
    forceRelay: status.device?.forceRelay ?? false,
    mtu: status.device?.mtu ?? 0,
    relayRate: rate.value,
    relayRateUnit: rate.unit,
    relayBurst: burst.value,
    relayBurstUnit: burst.unit,
  }
}

/** Tunnel MTU, forced relay and the local coordinator's relay limits (F-019, F-022, F-026). */
export function AdvancedCard() {
  const { status, isApp } = useAppStatus()
  if (!isApp || !status?.device?.name) return null
  return (
    <>
      <AdvancedSettingsForm status={status} />
      <TransportCard status={status} />
      <TrafficCard />
      <RDeskCard />
    </>
  )
}

/** Only the tunnel MTU, forced relay and relay limit form; the settings page places the other cards itself. */
export function AdvancedSettingsCard() {
  const { status, isApp } = useAppStatus()
  if (!isApp || !status?.device?.name) return null
  return <AdvancedSettingsForm status={status} />
}

function AdvancedSettingsForm({ status }: { status: AppStatus }) {
  const { t, ts } = useI18n()
  const { mutate } = useAppStatus()
  const readOnly = useReadOnly()
  const form = useForm<AdvancedForm>({ resolver: zodResolver(advancedSchema), defaultValues: defaultsFrom(status) })
  const { errors, isSubmitting, isDirty } = form.formState
  const forceRelay = useWatch({ control: form.control, name: "forceRelay" })
  const relayRateUnit = useWatch({ control: form.control, name: "relayRateUnit" })
  const relayBurstUnit = useWatch({ control: form.control, name: "relayBurstUnit" })
  const hasCoordinator = status.coordinator !== null
  const restartConfirm = useRestartConfirm() // #799

  async function onSubmit(values: AdvancedForm) {
    const device = status.device
    // Only changed fields are sent; the server keeps the others.
    const body: { mtu?: number; forceRelay?: boolean; relayRate?: number; relayBurst?: number } = {}
    if (values.mtu !== (device?.mtu ?? 0)) body.mtu = values.mtu
    if (values.forceRelay !== (device?.forceRelay ?? false)) body.forceRelay = values.forceRelay
    if (status.coordinator) {
      const rate = toBytes(values.relayRate, values.relayRateUnit)
      const burst = toBytes(values.relayBurst, values.relayBurstUnit)
      if (rate !== status.coordinator.relayRate) body.relayRate = rate
      if (burst !== status.coordinator.relayBurst) body.relayBurst = burst
    }
    if (Object.keys(body).length === 0) {
      toast.info(t("Değişiklik yok."))
      form.reset(values)
      return
    }
    if (!(await restartConfirm.ask(Object.keys(body)))) return
    try {
      const res = await post<AppStatus>("/api/app/advanced", body)
      await mutate(res, { revalidate: false })
      form.reset(defaultsFrom(res))
      toast.success(t("Gelişmiş ayarlar kaydedildi. Tünel kısa süreliğine yeniden başlatılıyor."))
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }

  return (
    <Card className="lg:col-span-3">
      {restartConfirm.dialog}
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <SlidersHorizontal className="size-4 text-muted-foreground" />
            {t("Tünel ve aktarıcı")}
            <RestartsConnectionBadge prefKey="mtu" />
          </CardTitle>
          <CardDescription className="text-pretty">
            {hasCoordinator
              ? t("Kaydedince tünel ve koordinatör birkaç saniyeliğine yeniden başlar.")
              : t("Kaydedince tünel birkaç saniyeliğine yeniden başlar.")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FieldGroup>
            <Controller
              control={form.control}
              name="forceRelay"
              render={({ field }) => (
                <Field orientation="horizontal" className="rounded-lg border p-3">
                  <FieldContent>
                    <FieldLabel htmlFor="force-relay">{t("Her zaman aktarıcı kullan")}</FieldLabel>
                    <FieldDescription className="text-pretty">
                      {t(
                        "Bu cihaz yalnızca koordinatörle UDP konuşur; diğer cihazlarla doğrudan bağlantı denenmez. Doğrudan UDP'yi engelleyen ağlarda işe yarar ama trafik koordinatör üzerinden geçtiği için daha yavaştır. Açıkken MTU en fazla {mtu} olmalı.",
                        { mtu: MTU_DEFAULT }
                      )}
                    </FieldDescription>
                  </FieldContent>
                  <Switch
                    id="force-relay"
                    checked={field.value}
                    disabled={readOnly}
                    onCheckedChange={(on) => {
                      field.onChange(on)
                      if (on && form.getValues("mtu") > MTU_DEFAULT) form.setValue("mtu", 0, { shouldDirty: true, shouldValidate: true })
                    }}
                  />
                </Field>
              )}
            />
            <Field data-invalid={errors.mtu ? true : undefined}>
              <FieldLabel htmlFor="tunnel-mtu">{t("Tünel MTU")}</FieldLabel>
              <Input
                id="tunnel-mtu"
                type="number"
                inputMode="numeric"
                min={0}
                max={forceRelay ? MTU_DEFAULT : MTU_MAX}
                className="sm:max-w-40"
                disabled={readOnly}
                aria-invalid={errors.mtu ? true : undefined}
                {...form.register("mtu", { valueAsNumber: true })}
              />
              <FieldDescription>
                {t("0 = varsayılan ({default}). Aksi halde {min}-{max} arası. Emin değilsen değiştirme; yüksek MTU bazı ağlarda bağlantıyı bozar.", {
                  default: MTU_DEFAULT,
                  min: MTU_DEFAULT,
                  max: forceRelay ? MTU_DEFAULT : MTU_MAX,
                })}
              </FieldDescription>
              <FieldError errors={[errors.mtu]} />
            </Field>
            {hasCoordinator ? (
              <FieldSet className="rounded-lg border p-3">
                <FieldLegend variant="label">{t("Bu bilgisayardaki koordinatörün aktarma sınırları")}</FieldLegend>
                <FieldDescription>
                  {t(
                    "Doğrudan bağlanamayan cihazların trafiği koordinatör üzerinden aktarılır. Sınırlar cihaz başınadır; 0 = varsayılan (20 MiB/s hız, 4 MiB ani yük)."
                  )}
                </FieldDescription>
                <div className="grid gap-4 sm:grid-cols-2">
                  <AmountField
                    id="relay-rate"
                    label={t("Aktarma hızı")}
                    suffix="/s"
                    hint={t("64 KiB/s ile 10 GiB/s arası.")}
                    error={errors.relayRate?.message}
                    disabled={readOnly}
                    unit={relayRateUnit}
                    onUnit={(u) => form.setValue("relayRateUnit", u, { shouldDirty: true, shouldValidate: form.formState.isSubmitted })}
                    input={form.register("relayRate", { valueAsNumber: true })}
                  />
                  <AmountField
                    id="relay-burst"
                    label={t("Ani yük (burst)")}
                    suffix=""
                    hint={t("64 KiB ile 1 GiB arası.")}
                    error={errors.relayBurst?.message}
                    disabled={readOnly}
                    unit={relayBurstUnit}
                    onUnit={(u) => form.setValue("relayBurstUnit", u, { shouldDirty: true, shouldValidate: form.formState.isSubmitted })}
                    input={form.register("relayBurst", { valueAsNumber: true })}
                  />
                </div>
              </FieldSet>
            ) : null}
          </FieldGroup>
          {status.device?.error ? (
            <Alert variant="destructive" className="mt-4">
              <AlertDescription>{ts(status.device.error)}</AlertDescription>
            </Alert>
          ) : null}
        </CardContent>
        {readOnly ? null : (
          <CardFooter className="flex flex-wrap gap-2">
            <Button type="submit" disabled={isSubmitting || !isDirty}>
              {isSubmitting ? <Spinner data-icon="inline-start" /> : null}
              {t("Kaydet ve yeniden başlat")}
            </Button>
            <Button type="button" variant="outline" disabled={isSubmitting || !isDirty} onClick={() => form.reset(defaultsFrom(status))}>
              <RotateCcw data-icon="inline-start" />
              {t("Geri al")}
            </Button>
          </CardFooter>
        )}
      </form>
    </Card>
  )
}

interface AmountFieldProps {
  id: string
  label: string
  suffix: string
  hint: string
  error?: string
  disabled: boolean
  unit: Unit
  onUnit: (unit: Unit) => void
  input: UseFormRegisterReturn
}

function AmountField({ id, label, suffix, hint, error, disabled, unit, onUnit, input }: AmountFieldProps) {
  const { t } = useI18n()
  return (
    <Field data-invalid={error ? true : undefined}>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <div className="flex gap-2">
        <Input
          id={id}
          type="number"
          inputMode="decimal"
          min={0}
          step="any"
          disabled={disabled}
          aria-invalid={error ? true : undefined}
          {...input}
        />
        <div role="radiogroup" aria-label={t("{label} birimi", { label })} className="flex shrink-0 rounded-lg border bg-card p-0.5">
          {(["KiB", "MiB"] as const).map((u) => (
            <button
              key={u}
              type="button"
              role="radio"
              aria-checked={unit === u}
              disabled={disabled}
              onClick={() => onUnit(u)}
              className={cn(
                "rounded-md px-2.5 py-1 text-sm whitespace-nowrap transition-colors",
                unit === u ? "bg-secondary font-medium text-foreground" : "text-muted-foreground hover:text-foreground"
              )}
            >
              {u}
              {suffix}
            </button>
          ))}
        </div>
      </div>
      <FieldDescription>{hint}</FieldDescription>
      {error ? <FieldError>{error}</FieldError> : null}
    </Field>
  )
}
