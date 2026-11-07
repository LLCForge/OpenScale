"use client"

import { Controller, useForm, useWatch } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { Network, RotateCcw } from "lucide-react"
import { toast } from "sonner"

import { useAppStatus } from "@/components/app/use-app-status"
import { useReadOnly } from "@/components/app/read-only"
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
import type { AppStatus, TransportSettings } from "@/lib/types"

// Bounds mirror internal/node and internal/coordinator; the service checks them again.
const PSK_MIN_MIN = 2
const PSK_MAX_MIN = 24 * 60
const KEEPALIVE_MIN = 10
const KEEPALIVE_MAX = 120
const LAZY_MIN_MIN = 1
const LAZY_MAX_MIN = 24 * 60
const TCP_MAX_CONNS = 4096
const ADDR_MAX = 255

const hostPort = /^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+):\d{1,5}$/
const listenAddr = /^(\[[0-9a-fA-F:.]+\]|[0-9.]*):\d{1,5}$/

const whole = (message: string) => z.number({ error: message }).int(msg("Tam sayı gir")).min(0, msg("Negatif olamaz"))

const transportSchema = z
  .object({
    postQuantum: z.boolean(),
    pskRotationMin: whole(msg("Dakika gir; varsayılan için 0")),
    tcpFallback: z.string().trim().max(ADDR_MAX, msg("Adres çok uzun")),
    disableTcpFallback: z.boolean(),
    keepaliveSec: whole(msg("Saniye gir; varsayılan için 0")),
    adaptiveKeepalive: z.boolean(),
    lazyPeers: z.boolean(),
    lazyIdleMin: whole(msg("Dakika gir; varsayılan için 0")),
    coordinatorTcpListen: z.string().trim().max(ADDR_MAX, msg("Adres çok uzun")),
    coordinatorTcpMaxConns: whole(msg("Sayı gir; varsayılan için 0")),
  })
  .superRefine((v, ctx) => {
    if (v.pskRotationMin !== 0 && (v.pskRotationMin < PSK_MIN_MIN || v.pskRotationMin > PSK_MAX_MIN)) {
      ctx.addIssue({ code: "custom", path: ["pskRotationMin"], message: tx("0 (varsayılan 10) veya {min}-{max} dakika", { min: PSK_MIN_MIN, max: PSK_MAX_MIN }) })
    }
    if (v.keepaliveSec !== 0 && (v.keepaliveSec < KEEPALIVE_MIN || v.keepaliveSec > KEEPALIVE_MAX)) {
      ctx.addIssue({ code: "custom", path: ["keepaliveSec"], message: tx("0 (varsayılan 25) veya {min}-{max} saniye", { min: KEEPALIVE_MIN, max: KEEPALIVE_MAX }) })
    }
    if (v.lazyIdleMin !== 0 && (v.lazyIdleMin < LAZY_MIN_MIN || v.lazyIdleMin > LAZY_MAX_MIN)) {
      ctx.addIssue({ code: "custom", path: ["lazyIdleMin"], message: tx("0 (varsayılan 10) veya {min}-{max} dakika", { min: LAZY_MIN_MIN, max: LAZY_MAX_MIN }) })
    }
    if (v.tcpFallback !== "" && !hostPort.test(v.tcpFallback)) {
      ctx.addIssue({ code: "custom", path: ["tcpFallback"], message: msg("ana-makine:port biçiminde yaz, ör. vpn.ornek.com:443") })
    }
    if (v.coordinatorTcpListen !== "" && !listenAddr.test(v.coordinatorTcpListen)) {
      ctx.addIssue({ code: "custom", path: ["coordinatorTcpListen"], message: msg(":443 veya IP:port biçiminde yaz") })
    }
    if (v.coordinatorTcpMaxConns > TCP_MAX_CONNS) {
      ctx.addIssue({ code: "custom", path: ["coordinatorTcpMaxConns"], message: tx("En fazla {max}", { max: TCP_MAX_CONNS }) })
    }
  })

type TransportForm = z.infer<typeof transportSchema>

const defaultTransport: TransportSettings = {
  postQuantum: true,
  pskRotationSec: 0,
  tcpFallback: "",
  disableTcpFallback: false,
  keepaliveSec: 0,
  adaptiveKeepalive: false,
  lazyPeers: false,
  lazyIdleSec: 0,
}

function defaultsFrom(status: AppStatus): TransportForm {
  const t = status.device?.transport ?? defaultTransport
  return {
    postQuantum: t.postQuantum,
    pskRotationMin: Math.round(t.pskRotationSec / 60),
    tcpFallback: t.tcpFallback,
    disableTcpFallback: t.disableTcpFallback,
    keepaliveSec: t.keepaliveSec,
    adaptiveKeepalive: t.adaptiveKeepalive,
    lazyPeers: t.lazyPeers,
    lazyIdleMin: Math.round(t.lazyIdleSec / 60),
    coordinatorTcpListen: status.coordinator?.tcpListen ?? "",
    coordinatorTcpMaxConns: status.coordinator?.tcpMaxConns ?? 0,
  }
}

type TransportBody = Partial<{
  postQuantum: boolean
  pskRotationSec: number
  tcpFallback: string
  disableTcpFallback: boolean
  keepaliveSec: number
  adaptiveKeepalive: boolean
  lazyPeers: boolean
  lazyIdleSec: number
  coordinatorTcpListen: string
  coordinatorTcpMaxConns: number
}>

/** Changed fields only; the server keeps the others. */
function changes(values: TransportForm, before: TransportForm, hasCoordinator: boolean): TransportBody {
  const body: TransportBody = {}
  if (values.postQuantum !== before.postQuantum) body.postQuantum = values.postQuantum
  if (values.pskRotationMin !== before.pskRotationMin) body.pskRotationSec = values.pskRotationMin * 60
  if (values.tcpFallback !== before.tcpFallback) body.tcpFallback = values.tcpFallback
  if (values.disableTcpFallback !== before.disableTcpFallback) body.disableTcpFallback = values.disableTcpFallback
  if (values.keepaliveSec !== before.keepaliveSec) body.keepaliveSec = values.keepaliveSec
  if (values.adaptiveKeepalive !== before.adaptiveKeepalive) body.adaptiveKeepalive = values.adaptiveKeepalive
  if (values.lazyPeers !== before.lazyPeers) body.lazyPeers = values.lazyPeers
  if (values.lazyIdleMin !== before.lazyIdleMin) body.lazyIdleSec = values.lazyIdleMin * 60
  if (hasCoordinator) {
    if (values.coordinatorTcpListen !== before.coordinatorTcpListen) body.coordinatorTcpListen = values.coordinatorTcpListen
    if (values.coordinatorTcpMaxConns !== before.coordinatorTcpMaxConns) body.coordinatorTcpMaxConns = values.coordinatorTcpMaxConns
  }
  return body
}

/** Faz 4 tunnel options: post-quantum PSK, TCP fallback, keepalive and lazy peers (ADR-0032, ADR-0033). */
export function TransportCard({ status }: { status: AppStatus }) {
  const { t } = useI18n()
  const { mutate } = useAppStatus()
  const readOnly = useReadOnly()
  const before = defaultsFrom(status)
  const form = useForm<TransportForm>({ resolver: zodResolver(transportSchema), defaultValues: before })
  const { errors, isSubmitting, isDirty } = form.formState
  const disableTcp = useWatch({ control: form.control, name: "disableTcpFallback" })
  const lazy = useWatch({ control: form.control, name: "lazyPeers" })
  const hasCoordinator = status.coordinator !== null
  const restartConfirm = useRestartConfirm() // #799

  async function onSubmit(values: TransportForm) {
    const body = changes(values, before, hasCoordinator)
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
      toast.success(t("Bağlantı ayarları kaydedildi. Tünel kısa süreliğine yeniden başlatılıyor."))
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }

  const switchRow = (name: "postQuantum" | "disableTcpFallback" | "adaptiveKeepalive" | "lazyPeers", id: string, label: string, hint: string) => (
    <Controller
      control={form.control}
      name={name}
      render={({ field }) => (
        <Field orientation="horizontal" className="rounded-lg border p-3">
          <FieldContent>
            <FieldLabel htmlFor={id}>{label}</FieldLabel>
            <FieldDescription className="text-pretty">{hint}</FieldDescription>
          </FieldContent>
          <Switch id={id} checked={field.value} disabled={readOnly} onCheckedChange={field.onChange} />
        </Field>
      )}
    />
  )

  return (
    <Card className="lg:col-span-3">
      {restartConfirm.dialog}
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Network className="size-4 text-muted-foreground" />
            {t("Bağlantı ve şifreleme")}
            <RestartsConnectionBadge prefKey="post-quantum" />
          </CardTitle>
          <CardDescription className="text-pretty">
            {t("Kuantum sonrası anahtar, TCP yedeği ve tembel eşler; kaydedince tünel birkaç saniyeliğine yeniden başlar.")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FieldGroup>
            {switchRow(
              "postQuantum",
              "post-quantum",
              t("Kuantum sonrası anahtar (ML-KEM-768)"),
              t("Destekleyen her eşle WireGuard'a ek bir ön paylaşımlı anahtar anlaşılır. Eski sürümlü eşlerle bağlantı klasik şifrelemeyle sürer.")
            )}
            <Field data-invalid={errors.pskRotationMin ? true : undefined}>
              <FieldLabel htmlFor="psk-rotation">{t("Anahtar yenileme aralığı (dakika)")}</FieldLabel>
              <Input
                id="psk-rotation"
                type="number"
                inputMode="numeric"
                min={0}
                className="sm:max-w-40"
                disabled={readOnly}
                aria-invalid={errors.pskRotationMin ? true : undefined}
                {...form.register("pskRotationMin", { valueAsNumber: true })}
              />
              <FieldDescription>{t("0 = varsayılan (10 dakika). {min} ile {max} dakika arası.", { min: PSK_MIN_MIN, max: PSK_MAX_MIN })}</FieldDescription>
              <FieldError errors={[errors.pskRotationMin]} />
            </Field>
            {switchRow(
              "disableTcpFallback",
              "disable-tcp",
              t("Koordinatöre TCP yedeğini kullanma"),
              t("Varsayılan olarak UDP engellenince koordinatöre TCP (443) üzerinden bağlanılır. Kapatınca yalnızca UDP denenir.")
            )}
            <Field data-invalid={errors.tcpFallback ? true : undefined}>
              <FieldLabel htmlFor="tcp-fallback">{t("TCP yedek adresi")}</FieldLabel>
              <Input
                id="tcp-fallback"
                placeholder={t("koordinatör:443")}
                className="font-mono sm:max-w-80"
                disabled={readOnly || disableTcp}
                aria-invalid={errors.tcpFallback ? true : undefined}
                {...form.register("tcpFallback")}
              />
              <FieldDescription>{t("Boş = koordinatörün adresi, port 443.")}</FieldDescription>
              <FieldError errors={[errors.tcpFallback]} />
            </Field>
            <Field data-invalid={errors.keepaliveSec ? true : undefined}>
              <FieldLabel htmlFor="keepalive">{t("Keepalive (saniye)")}</FieldLabel>
              <Input
                id="keepalive"
                type="number"
                inputMode="numeric"
                min={0}
                className="sm:max-w-40"
                disabled={readOnly}
                aria-invalid={errors.keepaliveSec ? true : undefined}
                {...form.register("keepaliveSec", { valueAsNumber: true })}
              />
              <FieldDescription>
                {t("0 = varsayılan (25 saniye). {min}-{max} saniye. NAT eşlemesini çabuk unutan ağlarda kısalt.", {
                  min: KEEPALIVE_MIN,
                  max: KEEPALIVE_MAX,
                })}
              </FieldDescription>
              <FieldError errors={[errors.keepaliveSec]} />
            </Field>
            {switchRow(
              "adaptiveKeepalive",
              "adaptive-keepalive",
              t("Uyarlanan keepalive"),
              t("Bağlantı kopup geri gelince aralık kısalır, uzun süre sorunsuz kalınca yeniden uzar.")
            )}
            {switchRow(
              "lazyPeers",
              "lazy-peers",
              t("Tembel eşler"),
              t("Eşler yalnızca trafik olunca WireGuard'a eklenir, boşta kalınca çıkarılır. Çok cihazlı ağlarda bellek ve el sıkışma yükünü azaltır.")
            )}
            <Field data-invalid={errors.lazyIdleMin ? true : undefined}>
              <FieldLabel htmlFor="lazy-idle">{t("Boşta kalma süresi (dakika)")}</FieldLabel>
              <Input
                id="lazy-idle"
                type="number"
                inputMode="numeric"
                min={0}
                className="sm:max-w-40"
                disabled={readOnly || !lazy}
                aria-invalid={errors.lazyIdleMin ? true : undefined}
                {...form.register("lazyIdleMin", { valueAsNumber: true })}
              />
              <FieldDescription>{t("0 = varsayılan (10 dakika).")}</FieldDescription>
              <FieldError errors={[errors.lazyIdleMin]} />
            </Field>
            {hasCoordinator ? (
              <FieldSet className="rounded-lg border p-3">
                <FieldLegend variant="label">{t("Bu bilgisayardaki koordinatörün TCP dinleyicisi")}</FieldLegend>
                <FieldDescription className="text-pretty">
                  {t("UDP'si engelli cihazlar koordinatöre bu adresten TCP ile bağlanır. Boş = kapalı. Güvenlik duvarında bu TCP portunu aç.")}
                </FieldDescription>
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field data-invalid={errors.coordinatorTcpListen ? true : undefined}>
                    <FieldLabel htmlFor="coord-tcp-listen">{t("Dinleme adresi")}</FieldLabel>
                    <Input
                      id="coord-tcp-listen"
                      placeholder=":443"
                      className="font-mono"
                      disabled={readOnly}
                      aria-invalid={errors.coordinatorTcpListen ? true : undefined}
                      {...form.register("coordinatorTcpListen")}
                    />
                    <FieldError errors={[errors.coordinatorTcpListen]} />
                  </Field>
                  <Field data-invalid={errors.coordinatorTcpMaxConns ? true : undefined}>
                    <FieldLabel htmlFor="coord-tcp-max">{t("En fazla bağlantı")}</FieldLabel>
                    <Input
                      id="coord-tcp-max"
                      type="number"
                      inputMode="numeric"
                      min={0}
                      disabled={readOnly}
                      aria-invalid={errors.coordinatorTcpMaxConns ? true : undefined}
                      {...form.register("coordinatorTcpMaxConns", { valueAsNumber: true })}
                    />
                    <FieldDescription>{t("0 = varsayılan (256).")}</FieldDescription>
                    <FieldError errors={[errors.coordinatorTcpMaxConns]} />
                  </Field>
                </div>
                {status.coordinator?.tcpAddr ? (
                  <FieldDescription>{t("Şu an dinliyor: {address}", { address: status.coordinator.tcpAddr })}</FieldDescription>
                ) : null}
              </FieldSet>
            ) : null}
          </FieldGroup>
          {status.device?.coordinatorOverTcp ? (
            <Alert className="mt-4">
              <AlertDescription>{t("Koordinatöre şu an TCP ile bağlı: bu ağ UDP'yi engelliyor.")}</AlertDescription>
            </Alert>
          ) : null}
        </CardContent>
        {readOnly ? null : (
          <CardFooter className="flex flex-wrap gap-2">
            <Button type="submit" disabled={isSubmitting || !isDirty}>
              {isSubmitting ? <Spinner data-icon="inline-start" /> : null}
              {t("Kaydet ve yeniden başlat")}
            </Button>
            <Button type="button" variant="outline" disabled={isSubmitting || !isDirty} onClick={() => form.reset(before)}>
              <RotateCcw data-icon="inline-start" />
              {t("Geri al")}
            </Button>
          </CardFooter>
        )}
      </form>
    </Card>
  )
}
