"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { useForm, useWatch } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { ArrowLeft, ArrowRight, KeyRound, Network, Ticket, TriangleAlert } from "lucide-react"
import { toast } from "sonner"

import { useAppStatus } from "@/components/app/use-app-status"
import { BrandWordmark } from "@/components/brand"
import { LanguageCorner } from "@/components/language-switcher"
import { JoiningCard } from "@/components/welcome/joining-card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { Textarea } from "@/components/ui/textarea"
import { errorMessage, post } from "@/lib/api"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { AppStatus } from "@/lib/types"

type Choice = "none" | "create" | "join"

const deviceName = z
  .string()
  .trim()
  .max(63, msg("En fazla 63 karakter"))
  .regex(/^[a-zA-Z0-9 _-]*$/, msg("Yalnızca harf, rakam, boşluk ve tire"))

export function WelcomeView() {
  const { t, ts } = useI18n()
  const router = useRouter()
  const { status, isLoading, mutate } = useAppStatus(2_000)
  const [choice, setChoice] = useState<Choice>("none")

  const mode = status?.mode
  useEffect(() => {
    if (mode === "admin" || mode === "member") router.replace("/")
  }, [mode, router])

  if (isLoading || !status) {
    return (
      <Shell>
        <Skeleton className="h-72 w-full max-w-2xl rounded-2xl" />
      </Shell>
    )
  }

  if (status.mode === "joining" && status.joining) {
    return (
      <Shell>
        <JoiningCard joining={status.joining} onCancelled={() => mutate()} />
      </Shell>
    )
  }

  return (
    <Shell>
      <div className="flex w-full max-w-2xl flex-col gap-6">
        {status.error ? (
          <Alert variant="destructive">
            <TriangleAlert />
            <AlertTitle>{t("Katılım tamamlanamadı")}</AlertTitle>
            <AlertDescription>{ts(status.error)}</AlertDescription>
          </Alert>
        ) : null}
        {choice === "none" ? <ChoiceCards onChoose={setChoice} /> : null}
        {choice === "create" ? (
          <CreateForm status={status} onBack={() => setChoice("none")} onDone={() => mutate()} />
        ) : null}
        {choice === "join" ? <JoinForm status={status} onBack={() => setChoice("none")} onDone={() => mutate()} /> : null}
      </div>
    </Shell>
  )
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <main className="flex min-h-svh flex-col items-center justify-center gap-10 bg-background px-4 py-12">
      <BrandWordmark size="lg" />
      {children}
      <LanguageCorner />
    </main>
  )
}

function ChoiceCards({ onChoose }: { onChoose: (c: Choice) => void }) {
  const { t } = useI18n()
  return (
    <section aria-labelledby="welcome-title" className="flex flex-col gap-6">
      <div className="flex flex-col gap-2 text-center">
        <h1 id="welcome-title" className="text-2xl font-semibold tracking-tight text-balance">
          {t("OpenScale'e hoş geldin")}
        </h1>
        <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
          {t("Bu bilgisayar ilk cihazınsa yeni bir ağ kur. Ağın zaten varsa yönetici bilgisayardan aldığın davet koduyla katıl.")}
        </p>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <ChoiceButton
          icon={Network}
          title={t("Yeni ağ kur")}
          text={t("Bu bilgisayar ağın yöneticisi ve buluşma noktası olur. Diğer cihazları buradan davet edersin.")}
          onClick={() => onChoose("create")}
        />
        <ChoiceButton
          icon={Ticket}
          title={t("Davet koduyla katıl")}
          text={t("Yönetici bilgisayarda oluşturduğun davet kodunu yapıştır, ekranda çıkan kodu orada onayla.")}
          onClick={() => onChoose("join")}
        />
      </div>
    </section>
  )
}

function ChoiceButton({
  icon: Icon,
  title,
  text,
  onClick,
}: {
  icon: React.ComponentType<{ className?: string }>
  title: string
  text: string
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="group flex flex-col gap-3 rounded-2xl border bg-card p-6 text-left transition-colors hover:border-primary/60 hover:bg-accent/40 focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
    >
      <span className="flex size-10 items-center justify-center rounded-lg bg-primary/15 text-primary">
        <Icon className="size-5" />
      </span>
      <span className="flex items-center gap-2 text-base font-semibold">
        {title}
        <ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" />
      </span>
      <span className="text-sm leading-relaxed text-muted-foreground">{text}</span>
    </button>
  )
}

function FormCard({ title, description, onBack, children }: { title: string; description: string; onBack: () => void; children: React.ReactNode }) {
  const { t } = useI18n()
  return (
    <section className="flex flex-col gap-6 rounded-2xl border bg-card p-6 shadow-xl shadow-black/20 sm:p-8">
      <div className="flex flex-col gap-2">
        <Button variant="ghost" size="sm" className="-ml-2 self-start text-muted-foreground" onClick={onBack}>
          <ArrowLeft data-icon="inline-start" />
          {t("Geri")}
        </Button>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        <p className="text-sm leading-relaxed text-muted-foreground text-pretty">{description}</p>
      </div>
      {children}
    </section>
  )
}

const createSchema = z
  .object({
    deviceName,
    endpointHost: z
      .string()
      .trim()
      .min(1, msg("Adres gerekli"))
      .max(253, msg("Adres çok uzun"))
      .regex(/^[a-zA-Z0-9.:-]+$/, msg("IP adresi veya alan adı girin (port olmadan)")),
    passphrase: z.string().min(12, msg("En az 12 karakter")).max(1024, msg("Parola çok uzun")),
    confirm: z.string(),
    // F-087: the "every device to every device" rule is a choice, off by default.
    allowAll: z.boolean(),
  })
  .refine((v) => v.passphrase === v.confirm, { path: ["confirm"], message: msg("Parolalar aynı değil") })

type CreateValues = z.infer<typeof createSchema>

function CreateForm({ status, onBack, onDone }: { status: AppStatus; onBack: () => void; onDone: () => void }) {
  const { t } = useI18n()
  const router = useRouter()
  const form = useForm<CreateValues>({
    resolver: zodResolver(createSchema),
    defaultValues: { deviceName: status.hostname, endpointHost: status.suggestedEndpoint, passphrase: "", confirm: "", allowAll: false },
  })
  const { errors, isSubmitting } = form.formState
  const allowAll = useWatch({ control: form.control, name: "allowAll" })

  async function onSubmit(values: CreateValues) {
    try {
      await post("/api/app/create", {
        passphrase: values.passphrase,
        deviceName: values.deviceName,
        endpointHost: values.endpointHost,
        allowAll: values.allowAll,
      })
      form.reset()
      toast.success(t("Ağ kuruldu. Tünel ve koordinatör başlatılıyor."))
      onDone()
      router.replace("/devices")
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }

  return (
    <FormCard
      title={t("Yeni ağ kur")}
      description={t(
        "Kök anahtar bu bilgisayarda parolayla şifrelenmiş olarak saklanır. Cihaz eklemek ve kural değiştirmek her zaman bu parolayı ister.",
      )}
      onBack={onBack}
    >
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-6">
        <FieldGroup>
          <Field data-invalid={errors.deviceName ? true : undefined}>
            <FieldLabel htmlFor="create-name">{t("Bu bilgisayarın adı")}</FieldLabel>
            <Input id="create-name" autoComplete="off" {...form.register("deviceName")} />
            <FieldError errors={[errors.deviceName]} />
          </Field>
          <Field data-invalid={errors.endpointHost ? true : undefined}>
            <FieldLabel htmlFor="create-endpoint">{t("Bu bilgisayarın adresi")}</FieldLabel>
            <Input id="create-endpoint" autoComplete="off" spellCheck={false} className="font-mono" {...form.register("endpointHost")} />
            <FieldDescription>
              {t(
                "Diğer cihazlar bu bilgisayara bu adresle ulaşır. Aynı evdeki cihazlar için yerel IP yeterli. Dışarıdan bağlanacaksan modemde port yönlendirmesi yap veya dinamik DNS alan adını yaz.",
              )}
            </FieldDescription>
            <FieldError errors={[errors.endpointHost]} />
          </Field>
          <Field data-invalid={errors.passphrase ? true : undefined}>
            <FieldLabel htmlFor="create-pass">{t("Kök anahtar parolası")}</FieldLabel>
            <Input id="create-pass" type="password" autoComplete="new-password" {...form.register("passphrase")} />
            <FieldDescription>{t("En az 12 karakter. Kaybolursa ağ yönetilemez; güvenli bir yere not al.")}</FieldDescription>
            <FieldError errors={[errors.passphrase]} />
          </Field>
          <Field data-invalid={errors.confirm ? true : undefined}>
            <FieldLabel htmlFor="create-confirm">{t("Parola tekrar")}</FieldLabel>
            <Input id="create-confirm" type="password" autoComplete="new-password" {...form.register("confirm")} />
            <FieldError errors={[errors.confirm]} />
          </Field>
          <Field orientation="horizontal">
            <Checkbox id="create-allow-all" checked={allowAll} onCheckedChange={(v) => form.setValue("allowAll", v === true)} />
            <FieldContent>
              <FieldLabel htmlFor="create-allow-all">{t("Bütün cihazlar birbirine her porttan erişebilsin")}</FieldLabel>
              <FieldDescription className="text-pretty">
                {t(
                  "Kapalıysa ağ kuralsız başlar ve her şey reddedilir; erişimi Erişim kuralları sayfasından tek tek açarsın. Açmak kolay başlangıç sağlar ama bir cihaz ele geçirilirse diğerlerinin tüm portlarına ulaşılabilir.",
                )}
              </FieldDescription>
            </FieldContent>
          </Field>
        </FieldGroup>
        <Button type="submit" size="lg" className="h-11" disabled={isSubmitting}>
          {isSubmitting ? <Spinner data-icon="inline-start" /> : <KeyRound data-icon="inline-start" />}
          {isSubmitting ? t("Anahtarlar oluşturuluyor...") : t("Ağı kur")}
        </Button>
      </form>
    </FormCard>
  )
}

const joinSchema = z.object({
  code: z
    .string()
    .trim()
    .min(1, msg("Davet kodu gerekli"))
    .max(2048, msg("Kod çok uzun"))
    .refine((v) => v.replace(/\s+/g, "").startsWith("osinv1."), msg("Davet kodu osinv1. ile başlar")),
  name: deviceName,
})

type JoinValues = z.infer<typeof joinSchema>

function JoinForm({ status, onBack, onDone }: { status: AppStatus; onBack: () => void; onDone: () => void }) {
  const { t } = useI18n()
  const form = useForm<JoinValues>({ resolver: zodResolver(joinSchema), defaultValues: { code: "", name: status.hostname } })
  const { errors, isSubmitting } = form.formState

  async function onSubmit(values: JoinValues) {
    try {
      await post("/api/app/join", { code: values.code, name: values.name })
      form.reset()
      onDone()
    } catch (err) {
      form.setError("code", { message: errorMessage(err) })
    }
  }

  return (
    <FormCard
      title={t("Davet koduyla katıl")}
      description={t(
        "Yönetici bilgisayarda Cihazlar > Cihaz davet et ile bir kod oluştur ve buraya yapıştır. Kodu yalnızca kendin taşı; e-postayla veya başkasının eliyle gönderme.",
      )}
      onBack={onBack}
    >
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-6">
        <FieldGroup>
          <Field data-invalid={errors.code ? true : undefined}>
            <FieldLabel htmlFor="join-code">{t("Davet kodu")}</FieldLabel>
            <Textarea
              id="join-code"
              rows={4}
              spellCheck={false}
              autoComplete="off"
              placeholder="osinv1...."
              className="font-mono text-xs break-all"
              {...form.register("code")}
            />
            <FieldError errors={[errors.code]} />
          </Field>
          <Field data-invalid={errors.name ? true : undefined}>
            <FieldLabel htmlFor="join-name">{t("Bu bilgisayarın adı")}</FieldLabel>
            <Input id="join-name" autoComplete="off" {...form.register("name")} />
            <FieldDescription>{t("Yönetici onaylarken adı değiştirebilir.")}</FieldDescription>
            <FieldError errors={[errors.name]} />
          </Field>
        </FieldGroup>
        <Button type="submit" size="lg" className="h-11" disabled={isSubmitting}>
          {isSubmitting ? <Spinner data-icon="inline-start" /> : <Ticket data-icon="inline-start" />}
          {t("Katıl")}
        </Button>
      </form>
    </FormCard>
  )
}
