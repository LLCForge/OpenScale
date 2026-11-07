"use client"

import { Fragment, useState } from "react"
import useSWR, { useSWRConfig } from "swr"
import { useForm, Controller } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { Copy, KeyRound, LogOut, ShieldAlert, UserMinus, Users } from "lucide-react"
import { toast } from "sonner"

import { CodeLine } from "@/components/copy-field"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { errorMessage, fetcher, post } from "@/lib/api"
import { formatDate, formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { MembershipResponse, PreauthResult, SignResult } from "@/lib/membership-types"
import { MAX_TAGS, parseTagText, tagTextSchema } from "@/lib/references"
import { cn } from "@/lib/utils"

const passphrase = z.string().min(1, msg("Kök anahtar parolası gerekli")).max(1024, msg("Parola çok uzun"))
const refreshKeys = ["/api/devices", "/api/overview", "/api/history", "/api/network", "/api/invites"]
const inactiveChoices = [30, 90, 180]

/** Fills the {name} slots of a translated sentence with elements. */
function fill(text: string, parts: Record<string, React.ReactNode>): React.ReactNode[] {
  return text.split(/(\{\w+\})/).map((piece, i) => {
    const m = /^\{(\w+)\}$/.exec(piece)
    return m && m[1] in parts ? <Fragment key={i}>{parts[m[1]]}</Fragment> : piece
  })
}

/** A change that needs the root passphrase, described for the dialog. */
interface PendingSign {
  title: string
  description: string
  action: string
  destructive?: boolean
  run: (passphrase: string) => Promise<SignResult>
}

/**
 * Membership upkeep (ADR-0028): devices that asked to leave, identities
 * seen at two places at once, inactive devices removed with one signature,
 * preauthorized enrollment keys for servers and the minimum client version.
 */
export function MembershipPanel() {
  const { t, ts } = useI18n()
  const [days, setDays] = useState(30)
  const { data, mutate } = useSWR<MembershipResponse>(`/api/membership?days=${days}`, fetcher, { refreshInterval: 30_000 })
  const { mutate: globalMutate } = useSWRConfig()
  const [selected, setSelected] = useState<string[]>([])
  const [signing, setSigning] = useState<PendingSign | null>(null)
  const [preauthOpen, setPreauthOpen] = useState(false)

  async function refresh() {
    await Promise.all([mutate(), ...refreshKeys.map((k) => globalMutate(k))])
  }

  const inactive = data?.inactive ?? []
  const leaves = data?.leaves ?? []
  const alerts = data?.alerts ?? []

  return (
    <Card className={cn((alerts.length > 0 || leaves.length > 0) && "border-primary/60")}>
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex flex-col gap-1.5">
          <CardTitle className="flex items-center gap-2 text-base">
            <Users className="size-4 text-muted-foreground" />
            {t("Üyelik bakımı")}
          </CardTitle>
          <CardDescription className="text-pretty">
            {t("Ayrılmak isteyen, kimliği kopyalanmış veya uzun süredir görülmeyen cihazlar; her çıkarma senin imzanla olur.")}
          </CardDescription>
        </div>
        <Button variant="outline" className="shrink-0" onClick={() => setPreauthOpen(true)}>
          <KeyRound data-icon="inline-start" />
          {t("Ön onaylı kayıt anahtarı")}
        </Button>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        {alerts.length > 0 ? (
          <section aria-labelledby="clone-alerts" className="flex flex-col gap-2">
            <h3 id="clone-alerts" className="flex items-center gap-2 text-sm font-medium text-destructive">
              <ShieldAlert className="size-4" />
              {t("Aynı kimlik iki yerde kullanılıyor")}
            </h3>
            {alerts.map((a) => (
              <div key={a.name} className="flex flex-col gap-1 rounded-xl border border-destructive/40 p-3 text-sm">
                <span className="font-medium">{a.name}</span>
                <span className="text-xs text-muted-foreground text-pretty">
                  {t(
                    "{first} ile {last} arasında uç noktası {count} kez gidip geldi{endpoints}. Cihazın diski kopyalanmış olabilir: kopyayı kapatın, gerekirse cihazı iptal edip yeniden davet edin.",
                    {
                      first: formatDateTime(a.first),
                      last: formatDateTime(a.last),
                      count: a.flips,
                      endpoints: a.endpoints.length > 0 ? ` (${a.endpoints.join(", ")})` : "",
                    },
                  )}
                </span>
              </div>
            ))}
          </section>
        ) : null}

        {leaves.length > 0 ? (
          <section aria-labelledby="leave-requests" className="flex flex-col gap-2">
            <h3 id="leave-requests" className="flex items-center gap-2 text-sm font-medium">
              <LogOut className="size-4 text-muted-foreground" />
              {t("Ayrılmak isteyen cihazlar")}
            </h3>
            <ul className="flex flex-col divide-y rounded-xl border text-sm">
              {leaves.map((l) => (
                <li key={l.deviceId} className="flex items-center justify-between gap-4 px-4 py-2.5">
                  <span className="flex flex-col">
                    <span className="font-medium">{l.name}</span>
                    <span className="text-xs text-muted-foreground">{t("İmzalı istek: {time}", { time: formatDateTime(l.requestedAt) })}</span>
                  </span>
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() =>
                      setSigning({
                        title: t("{name} ağdan çıkarılsın mı?", { name: l.name }),
                        description: t("Cihaz kendi anahtarıyla ayrılmak istedi. Onaylarsan anahtarları iptal listesine girer."),
                        action: t("Çıkar"),
                        destructive: true,
                        run: (p) => post<SignResult>("/api/membership/leave-apply", { passphrase: p, deviceId: l.deviceId }),
                      })
                    }
                  >
                    <UserMinus data-icon="inline-start" />
                    {t("Çıkar")}
                  </Button>
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        <section aria-labelledby="inactive-devices" className="flex flex-col gap-3">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <h3 id="inactive-devices" className="text-sm font-medium">
              {t("Hareketsiz cihazlar")}
            </h3>
            <div role="radiogroup" aria-label={t("Hareketsizlik süresi")} className="flex w-fit rounded-lg border bg-card p-0.5">
              {inactiveChoices.map((d) => (
                <button
                  key={d}
                  type="button"
                  role="radio"
                  aria-checked={days === d}
                  onClick={() => {
                    setDays(d)
                    setSelected([])
                  }}
                  className={cn(
                    "rounded-md px-3 py-1.5 text-sm transition-colors",
                    days === d ? "bg-secondary font-medium text-foreground" : "text-muted-foreground hover:text-foreground"
                  )}
                >
                  {t("{count} gün", { count: d })}
                </button>
              ))}
            </div>
          </div>
          {inactive.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t("{count} gündür görülmeyen cihaz yok.", { count: days })}</p>
          ) : (
            <>
              <ul className="flex flex-col divide-y rounded-xl border text-sm">
                {inactive.map((d) => {
                  const id = `inactive-${d.name}`
                  return (
                    <li key={d.name} className="flex items-center gap-3 px-4 py-2.5">
                      <Checkbox
                        id={id}
                        disabled={d.admin}
                        checked={selected.includes(d.name)}
                        onCheckedChange={(on) => setSelected((cur) => (on ? [...cur, d.name] : cur.filter((n) => n !== d.name)))}
                      />
                      <label htmlFor={id} className="flex flex-1 flex-col">
                        <span className="font-medium">
                          {d.name}
                          {d.admin ? <span className="text-xs font-normal text-muted-foreground"> {t("(yönetici cihaz)")}</span> : null}
                          {d.ephemeral ? <span className="text-xs font-normal text-muted-foreground"> {t("(geçici)")}</span> : null}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {d.lastSeen
                            ? t("Son görülme {time}", { time: formatDateTime(d.lastSeen) })
                            : t("Hiç görülmedi; eklenme {date}", { date: formatDate(d.addedAt) })}{" "}
                          · {t("{count} gün", { count: d.days })}
                        </span>
                      </label>
                    </li>
                  )
                })}
              </ul>
              <Button
                variant="destructive"
                className="w-fit"
                disabled={selected.length === 0}
                onClick={() =>
                  setSigning({
                    title: t("{count} cihaz ağdan çıkarılsın mı?", { count: selected.length }),
                    description: t("{names} kalıcı olarak iptal edilir; tek imzayla tek sürüm oluşur.", { names: selected.join(", ") }),
                    action: t("Seçilenleri çıkar"),
                    destructive: true,
                    run: async (p) => {
                      const res = await post<SignResult>("/api/membership/remove", { passphrase: p, names: selected })
                      setSelected([])
                      return res
                    },
                  })
                }
              >
                <UserMinus data-icon="inline-start" />
                {t("Seçilenleri çıkar")}
              </Button>
            </>
          )}
          <p className="text-xs text-muted-foreground text-pretty">
            {t(
              "Son görülme bu bilgisayarın tünelinden ve koordinatörden öğrenilir ve yalnızca burada saklanır. Geçici cihazlar üyelikleri bitince bir sonraki imzalı sürümde kendiliğinden düşer.",
            )}
          </p>
        </section>

        <MinVersionForm current={data?.minClientVersion ?? ""} onSign={setSigning} />
        {data?.liveError ? <p className="text-xs text-muted-foreground">{ts(data.liveError)}</p> : null}
        {data && data.recoveryKeys === 0 ? (
          <p className="text-xs text-muted-foreground text-pretty">
            {t("Kurtarma anahtarı yok: kök anahtar ele geçirilirse ağ yeniden kurulmalı. Oluşturmak için yönetici bilgisayarda:")}
            <code className="ml-1 font-mono">openscale network recovery-key add</code>
          </p>
        ) : null}
      </CardContent>

      <SignDialog pending={signing} onClose={() => setSigning(null)} onDone={refresh} />
      <PreauthDialog open={preauthOpen} onOpenChange={setPreauthOpen} onDone={refresh} />
    </Card>
  )
}

const versionSchema = z.object({ version: z.string().trim().regex(/^(|\d{1,5}\.\d{1,5}\.\d{1,5})$/, msg("Sürüm 1.2.3 biçiminde olmalı")) })

function MinVersionForm({ current, onSign }: { current: string; onSign: (p: PendingSign) => void }) {
  const { t } = useI18n()
  const form = useForm<z.infer<typeof versionSchema>>({ resolver: zodResolver(versionSchema), values: { version: current } })
  const { errors } = form.formState
  return (
    <form
      noValidate
      className="flex flex-col gap-2"
      onSubmit={form.handleSubmit((v) =>
        onSign({
          title: v.version ? t("Asgari sürüm {version} olsun mu?", { version: v.version }) : t("Asgari sürüm kaldırılsın mı?"),
          description: t(
            "Bu sürümün altındaki istemcileri koordinatör açık bir hata iletisiyle reddeder. Yönetici cihazlar hiçbir zaman reddedilmez.",
          ),
          action: t("İmzala"),
          run: (p) => post<SignResult>("/api/membership/min-version", { passphrase: p, version: v.version }),
        })
      )}
    >
      <Field data-invalid={errors.version ? true : undefined}>
        <FieldLabel htmlFor="min-version">{t("Asgari istemci sürümü")}</FieldLabel>
        <div className="flex gap-2">
          <Input id="min-version" className="w-40 font-mono" placeholder={t("yok")} autoComplete="off" {...form.register("version")} />
          <Button type="submit" variant="outline">
            {t("Kaydet")}
          </Button>
        </div>
        <FieldDescription>{t("Bilinen açığı olan eski sürümleri ağdan uzak tutar. Boş bırakmak sınırı kaldırır.")}</FieldDescription>
        <FieldError errors={[errors.version]} />
      </Field>
    </form>
  )
}

const signSchema = z.object({ passphrase })

function SignDialog({ pending, onClose, onDone }: { pending: PendingSign | null; onClose: () => void; onDone: () => Promise<void> }) {
  const { t } = useI18n()
  const form = useForm<z.infer<typeof signSchema>>({ resolver: zodResolver(signSchema), defaultValues: { passphrase: "" } })
  const { errors, isSubmitting } = form.formState

  async function onSubmit(values: z.infer<typeof signSchema>) {
    if (!pending) return
    try {
      const res = await pending.run(values.passphrase)
      toast.success(t("Ağ belgesi sürüm {version} olarak imzalandı.", { version: res.version }))
      form.reset()
      await onDone()
      onClose()
    } catch (err) {
      form.setValue("passphrase", "")
      form.setError("passphrase", { message: errorMessage(err) })
    }
  }

  return (
    <Dialog
      open={pending !== null}
      onOpenChange={(v) => {
        if (!v) {
          form.reset()
          onClose()
        }
      }}
    >
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{pending?.title}</DialogTitle>
          <DialogDescription className="text-pretty">{pending?.description}</DialogDescription>
        </DialogHeader>
        <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-6">
          <Field data-invalid={errors.passphrase ? true : undefined}>
            <FieldLabel htmlFor="membership-pass">{t("Kök anahtar parolası")}</FieldLabel>
            <Input id="membership-pass" type="password" autoComplete="current-password" autoFocus {...form.register("passphrase")} />
            <FieldError errors={[errors.passphrase]} />
          </Field>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t("Vazgeç")}
            </Button>
            <Button type="submit" variant={pending?.destructive ? "destructive" : "default"} disabled={isSubmitting}>
              {isSubmitting ? <Spinner data-icon="inline-start" /> : null}
              {pending?.action}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

const preauthSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, msg("Ad gerekli"))
    .max(63, msg("En fazla 63 karakter"))
    .regex(/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/, msg("Küçük harf, rakam ve tire; tireyle başlayıp bitemez")),
  tags: tagTextSchema,
  ephemeral: z.boolean(),
  exitNode: z.boolean(),
  hours: z.number().int().min(1, msg("En az 1 saat")).max(87600, msg("Çok uzun")),
  passphrase,
})
type PreauthValues = z.infer<typeof preauthSchema>

function PreauthDialog({ open, onOpenChange, onDone }: { open: boolean; onOpenChange: (v: boolean) => void; onDone: () => Promise<void> }) {
  const { t } = useI18n()
  const [created, setCreated] = useState<PreauthResult | null>(null)
  const form = useForm<PreauthValues>({
    resolver: zodResolver(preauthSchema),
    defaultValues: { name: "", tags: "", ephemeral: true, exitNode: false, hours: 24, passphrase: "" },
  })
  const { errors, isSubmitting } = form.formState

  function close(v: boolean) {
    if (!v) {
      setCreated(null)
      form.reset()
    }
    onOpenChange(v)
  }

  async function onSubmit(values: PreauthValues) {
    if (values.ephemeral && values.hours > 720) {
      form.setError("hours", { message: msg("Geçici cihazın üyeliği en fazla 720 saat (30 gün) olabilir") })
      return
    }
    try {
      const res = await post<PreauthResult>("/api/membership/preauth", {
        passphrase: values.passphrase,
        name: values.name,
        tags: parseTagText(values.tags),
        hours: values.hours,
        ephemeral: values.ephemeral,
        exitNode: values.exitNode,
      })
      setCreated(res)
      form.reset()
      await onDone()
    } catch (err) {
      form.setValue("passphrase", "")
      form.setError("passphrase", { message: errorMessage(err) })
    }
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{created ? t("Kayıt anahtarı hazır") : t("Ön onaylı kayıt anahtarı")}</DialogTitle>
          <DialogDescription className="text-pretty">
            {created
              ? t("Bu anahtar cihazın özel anahtarlarını içerir ve yalnızca bir kez gösterilir. Parola gibi taşı, tek bir sunucuda kullan.")
              : t("Sunucu veya konteyner, onay beklemeden katılır: cihaz şimdi senin imzanla belgeye eklenir. Yönetici rolü verilemez.")}
          </DialogDescription>
        </DialogHeader>
        {created ? (
          <div className="flex flex-col gap-3">
            <CodeLine value={created.key} label={t("Kayıt anahtarını kopyala")} secret nowrap />
            <p className="text-xs leading-relaxed text-muted-foreground">
              {fill(
                t("{name} ({ip}) eklendi; üyelik sonu {time}. Sunucuda: {join} ardından {up}.", {
                  name: created.name,
                  ip: created.ipv4,
                  time: formatDateTime(created.expiresAt),
                }),
                {
                  join: <code className="font-mono">{t("openscale preauth-join --key @dosya")}</code>,
                  up: <code className="font-mono">openscale up</code>,
                },
              )}
            </p>
            <DialogFooter>
              <Button onClick={() => close(false)}>
                <Copy data-icon="inline-start" />
                {t("Tamam")}
              </Button>
            </DialogFooter>
          </div>
        ) : (
          <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-6">
            <FieldGroup>
              <Field data-invalid={errors.name ? true : undefined}>
                <FieldLabel htmlFor="preauth-name">{t("Cihaz adı")}</FieldLabel>
                <Input id="preauth-name" autoComplete="off" spellCheck={false} {...form.register("name")} />
                <FieldError errors={[errors.name]} />
              </Field>
              <Field data-invalid={errors.tags ? true : undefined}>
                <FieldLabel htmlFor="preauth-tags">{t("Etiketler (isteğe bağlı)")}</FieldLabel>
                <Input id="preauth-tags" autoComplete="off" spellCheck={false} className="font-mono" placeholder={t("ci, sunucu")} {...form.register("tags")} />
                <FieldDescription>{t("Kurallar cihaza tag:ad ile erişim verir. En fazla {max}.", { max: MAX_TAGS })}</FieldDescription>
                <FieldError errors={[errors.tags]} />
              </Field>
              <Field data-invalid={errors.hours ? true : undefined}>
                <FieldLabel htmlFor="preauth-hours">{t("Üyelik süresi (saat)")}</FieldLabel>
                <Input id="preauth-hours" type="number" min={1} className="w-32" {...form.register("hours", { valueAsNumber: true })} />
                <FieldError errors={[errors.hours]} />
              </Field>
              <Field orientation="horizontal">
                <Controller
                  control={form.control}
                  name="ephemeral"
                  render={({ field }) => <Switch id="preauth-ephemeral" checked={field.value} onCheckedChange={field.onChange} />}
                />
                <FieldLabel htmlFor="preauth-ephemeral">{t("Geçici cihaz (süre bitince kendiliğinden düşer)")}</FieldLabel>
              </Field>
              <Field orientation="horizontal">
                <Controller
                  control={form.control}
                  name="exitNode"
                  render={({ field }) => <Switch id="preauth-exit" checked={field.value} onCheckedChange={field.onChange} />}
                />
                <FieldLabel htmlFor="preauth-exit">{t("Çıkış düğümü olabilsin")}</FieldLabel>
              </Field>
              <Field data-invalid={errors.passphrase ? true : undefined}>
                <FieldLabel htmlFor="preauth-pass">{t("Kök anahtar parolası")}</FieldLabel>
                <Input id="preauth-pass" type="password" autoComplete="current-password" {...form.register("passphrase")} />
                <FieldError errors={[errors.passphrase]} />
              </Field>
            </FieldGroup>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => close(false)}>
                {t("Vazgeç")}
              </Button>
              <Button type="submit" disabled={isSubmitting}>
                {isSubmitting ? <Spinner data-icon="inline-start" /> : <KeyRound data-icon="inline-start" />}
                {t("Anahtar oluştur")}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}
