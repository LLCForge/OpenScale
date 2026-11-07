"use client"

import { useState } from "react"
import useSWR from "swr"
import { useForm, useWatch } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { CircleCheck, CircleX, Route } from "lucide-react"

import { Writable } from "@/components/app/read-only"
import { DetailSection } from "@/components/devices/detail-card"
import { QueryState } from "@/components/query-state"
import { headCell, ListTable } from "@/components/settings/list-table"
import { EmptyNote, SettingBadge } from "@/components/settings/settings-layout"
import { SignChange } from "@/components/sign-change"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import { errorMessage, fetcher, post } from "@/lib/api"
import { msg, useI18n } from "@/lib/i18n/i18n"
import { radioGroupKeyDown } from "@/components/settings/radio-keys"
import { cn } from "@/lib/utils"

/** Rule scope warning from GET /api/policy/report (ADR-0120, #112). */
export interface PolicyWarning {
  rule: number
  code: string
  message: string
}

/** Result of one policy test kept in the document (#101). */
interface PolicyTestResult {
  index: number
  test: string
  passed: boolean
  got: string
}

interface PolicyReport {
  warnings: PolicyWarning[]
  tests: PolicyTestResult[]
}

interface CheckResult {
  allowed: boolean
  reason: "self" | "deny" | "allow" | "default_deny"
  rule: number
  ruleText: string
  overriddenAllow: number
}

/** Rule scope warnings and test results of the current document (P09). */
export function usePolicyReport() {
  return useSWR<PolicyReport>("/api/policy/report", fetcher)
}

/** The policy tests kept in the document (#101); they run before every signature. */
export function PolicyTestsSection() {
  const { t, ts } = useI18n()
  const { data, error, isLoading, mutate } = usePolicyReport()
  const tests = data?.tests ?? []
  const failed = tests.filter((x) => !x.passed).length
  return (
    <DetailSection
      // i18n-ignore: bağlantı kimliği, görünmez
      id="kural-testleri"
      title={t("Kural testleri")}
      description={t("Belgedeki testler her imzadan önce çalışır; biri başarısızsa belge imzalanmaz. Testler metin düzenleyicide eklenir.")}
      framed={false}
      action={
        tests.length > 0 ? (
          failed === 0 ? (
            <SettingBadge tone="success">{t("{count} test geçti", { count: tests.length })}</SettingBadge>
          ) : (
            <SettingBadge tone="danger">{t("{count} test kaldı", { count: failed })}</SettingBadge>
          )
        ) : null
      }
    >
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {tests.length === 0 ? (
          <EmptyNote>{t("Belgede kural testi yok.")}</EmptyNote>
        ) : (
          <ListTable label={t("Kural testleri")}>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className={headCell}>{t("Test")}</TableHead>
                <TableHead className={cn(headCell, "w-32")}>{t("Sonuç")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {tests.map((x) => (
                <TableRow key={x.index}>
                  <TableCell className="font-mono text-[0.8125rem] whitespace-normal break-all">{x.test}</TableCell>
                  <TableCell>
                    {x.passed ? (
                      <SettingBadge tone="success">{t("Geçti")}</SettingBadge>
                    ) : (
                      <span className="flex flex-col items-start gap-1">
                        <SettingBadge tone="danger">{t("Kaldı")}</SettingBadge>
                        {x.got ? <span className="text-sm text-muted-foreground">{t("Sonuç: {result}", { result: ts(x.got) })}</span> : null}
                      </span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </ListTable>
        )}
      </QueryState>
    </DetailSection>
  )
}

const checkSchema = z
  .object({
    from: z.string().trim().min(1, msg("Kaynak cihazı yaz")).max(63, msg("Çok uzun")),
    to: z.string().trim().min(1, msg("Hedef cihazı yaz")).max(63, msg("Çok uzun")),
    protocol: z.enum(["tcp", "udp", "icmp"]),
    port: z.string().trim().max(16, msg("Çok uzun")),
    ignoreTime: z.boolean(),
  })
  .superRefine((v, ctx) => {
    if ((v.protocol === "tcp" || v.protocol === "udp") && v.port === "") {
      ctx.addIssue({ code: "custom", path: ["port"], message: msg("Port veya adını yaz (ör. 22, rdp)") })
    }
  })

type CheckForm = z.infer<typeof checkSchema>

const checkProtocols: { value: CheckForm["protocol"]; label: string }[] = [
  { value: "tcp", label: "TCP" },
  { value: "udp", label: "UDP" },
  { value: "icmp", label: "Ping" },
]

/** Tries how the rules answer one connection (#102). */
export function RuleSimulator({ devices }: { devices: string[] }) {
  const { t } = useI18n()
  const [result, setResult] = useState<CheckResult | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const form = useForm<CheckForm>({
    resolver: zodResolver(checkSchema),
    defaultValues: { from: "", to: "", protocol: "tcp", port: "", ignoreTime: false },
  })
  const { errors, isSubmitting } = form.formState
  const protocol = useWatch({ control: form.control, name: "protocol" })
  const ignoreTime = useWatch({ control: form.control, name: "ignoreTime" })

  async function onSubmit(values: CheckForm) {
    setFailure(null)
    try {
      const res = await post<CheckResult>("/api/policy/check", {
        from: values.from,
        to: values.to,
        protocol: values.protocol,
        port: values.protocol === "icmp" ? "" : values.port,
        ignoreTime: values.ignoreTime,
      })
      setResult(res)
    } catch (err) {
      setResult(null)
      setFailure(errorMessage(err))
    }
  }

  return (
    <DetailSection
      // i18n-ignore: bağlantı kimliği, görünmez
      id="kural-simulatoru"
      title={t("Kural simülatörü")}
      description={t("Bir bağlantının kurallarca nasıl karşılanacağını dene; reddet kuralı her zaman izinden önce gelir.")}
      framed={false}
    >
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4 border-y py-5">
        <datalist id="policy-sim-devices">
          {devices.map((d) => (
            <option key={d} value={d} />
          ))}
        </datalist>
        <FieldGroup className="grid gap-4 md:grid-cols-2">
          <Field data-invalid={errors.from ? true : undefined}>
            <FieldLabel htmlFor="sim-from">{t("Kaynak cihaz")}</FieldLabel>
            <Input id="sim-from" list="policy-sim-devices" autoComplete="off" className="font-mono" {...form.register("from")} />
            <FieldError errors={[errors.from]} />
          </Field>
          <Field data-invalid={errors.to ? true : undefined}>
            <FieldLabel htmlFor="sim-to">{t("Hedef cihaz")}</FieldLabel>
            <Input id="sim-to" list="policy-sim-devices" autoComplete="off" className="font-mono" {...form.register("to")} />
            <FieldError errors={[errors.to]} />
          </Field>
          <FieldSet>
            <FieldLegend variant="label">{t("Protokol")}</FieldLegend>
            <div role="radiogroup" aria-label={t("Protokol")} className="flex flex-wrap gap-2" onKeyDown={radioGroupKeyDown}>
              {checkProtocols.map((p) => (
                <Button
                  key={p.value}
                  type="button"
                  role="radio"
                  aria-checked={protocol === p.value}
                  tabIndex={protocol === p.value ? 0 : -1}
                  variant={protocol === p.value ? "default" : "outline"}
                  size="sm"
                  onClick={() => form.setValue("protocol", p.value, { shouldValidate: true })}
                >
                  {p.label}
                </Button>
              ))}
            </div>
          </FieldSet>
          <Field data-invalid={errors.port ? true : undefined} data-disabled={protocol === "icmp" ? true : undefined}>
            <FieldLabel htmlFor="sim-port">{t("Port")}</FieldLabel>
            <Input id="sim-port" className="font-mono" placeholder={t("22 veya rdp")} disabled={protocol === "icmp"} {...form.register("port")} />
            <FieldError errors={[errors.port]} />
          </Field>
        </FieldGroup>
        <Field orientation="horizontal">
          <Checkbox
            id="sim-ignore-time"
            checked={ignoreTime}
            onCheckedChange={(v) => form.setValue("ignoreTime", v === true)}
          />
          <FieldLabel htmlFor="sim-ignore-time">{t("Zamana bağlı kuralları her zaman etkin say")}</FieldLabel>
        </Field>
        <div className="flex">
          <Button type="submit" variant="outline" disabled={isSubmitting}>
            {isSubmitting ? <Spinner data-icon="inline-start" /> : <Route data-icon="inline-start" />}
            {t("Dene")}
          </Button>
        </div>
      </form>
      {failure ? (
        <Alert variant="destructive">
          <AlertDescription>{failure}</AlertDescription>
        </Alert>
      ) : null}
      {result ? <CheckResultAlert result={result} /> : null}
    </DetailSection>
  )
}

function CheckResultAlert({ result }: { result: CheckResult }) {
  const { t } = useI18n()
  let detail: string
  switch (result.reason) {
    case "allow":
      detail = t("Kural {number} izin veriyor: {rule}", { number: result.rule + 1, rule: result.ruleText })
      break
    case "deny":
      detail =
        result.overriddenAllow >= 0
          ? t("Kural {number} reddediyor: {rule}. Kural {allow} izin verirdi; reddet kuralı her zaman önce gelir.", {
              number: result.rule + 1,
              rule: result.ruleText,
              allow: result.overriddenAllow + 1,
            })
          : t("Kural {number} reddediyor: {rule}", { number: result.rule + 1, rule: result.ruleText })
      break
    case "self":
      detail = t("Bir cihaz kendisiyle eşleşmez.")
      break
    default:
      detail = t("Hiçbir kural izin vermiyor; varsayılan olarak reddedilir.")
  }
  return (
    <Alert variant={result.allowed ? "default" : "destructive"} aria-live="polite">
      {result.allowed ? <CircleCheck /> : <CircleX />}
      <AlertTitle>{result.allowed ? t("İzin verilir") : t("Reddedilir")}</AlertTitle>
      <AlertDescription className="text-sm text-pretty">{detail}</AlertDescription>
    </Alert>
  )
}

const MAX_TEXT = 1 << 20

/**
 * The whole policy as commented JSON (#104, #228): validated, tested and
 * shown as a diff before it is signed into the document.
 */
export function PolicyTextEditor() {
  const { t } = useI18n()
  const [payload, setPayload] = useState<Record<string, unknown> | null>(null)
  return (
    <DetailSection
      // i18n-ignore: bağlantı kimliği, görünmez
      id="politika-metni"
      title={t("Politika metni")}
      description={t(
        "Gruplar, adlandırılmış adresler, kurallar ve testler yorumlu JSON olarak. Kaydetmeden önce doğrulanır, testler çalışır ve fark gösterilir; imza yine ağ belgesinin kendisine atılır."
      )}
      framed={false}
    >
      <div className="flex flex-col gap-4 border-y py-5">
        {payload ? (
          <SignChange
            endpoint="/api/policy/text"
            payload={payload}
            confirmLabel={t("İmzala ve uygula")}
            inline
            onBack={() => setPayload(null)}
            onDone={() => setPayload(null)}
          />
        ) : (
          <PolicyTextStep onNext={setPayload} />
        )}
      </div>
    </DetailSection>
  )
}

const textSchema = z.object({
  text: z.string().min(2, msg("Politika boş olamaz")).max(MAX_TEXT, msg("Dosya 1 MiB'tan büyük olamaz")),
  confirmBroad: z.boolean(),
})

type TextForm = z.infer<typeof textSchema>

function PolicyTextStep({ onNext }: { onNext: (payload: Record<string, unknown>) => void }) {
  const { data, error, isLoading } = useSWR<{ text: string }>("/api/policy/text", fetcher, { revalidateOnFocus: false })
  if (isLoading) return <Skeleton className="h-72 w-full" />
  if (error || !data) {
    return (
      <Alert variant="destructive">
        <AlertDescription>{errorMessage(error)}</AlertDescription>
      </Alert>
    )
  }
  return <PolicyTextForm key={data.text} initial={data.text} onNext={onNext} />
}

function PolicyTextForm({ initial, onNext }: { initial: string; onNext: (payload: Record<string, unknown>) => void }) {
  const { t } = useI18n()
  const form = useForm<TextForm>({ resolver: zodResolver(textSchema), defaultValues: { text: initial, confirmBroad: false } })
  const { errors } = form.formState
  const confirmBroad = useWatch({ control: form.control, name: "confirmBroad" })

  return (
    <form onSubmit={form.handleSubmit((v) => onNext({ text: v.text, confirmBroad: v.confirmBroad }))} noValidate className="flex flex-col gap-4">
      <FieldGroup>
        <Field data-invalid={errors.text ? true : undefined}>
          <FieldLabel htmlFor="policy-text">{t("Politika dosyası")}</FieldLabel>
          <Textarea
            id="policy-text"
            spellCheck={false}
            className="min-h-96 font-mono text-[0.8125rem] leading-relaxed"
            aria-invalid={errors.text ? true : undefined}
            {...form.register("text")}
          />
          <FieldDescription className="text-pretty">
            {t("Yorumlar // veya # ile başlar. Port yerine ad yazılabilir (ör. rdp, ssh, https). CLI karşılığı: openscale policy export / import.")}
          </FieldDescription>
          <FieldError errors={[errors.text]} />
        </Field>
        <Field orientation="horizontal">
          <Checkbox id="policy-confirm-broad" checked={confirmBroad} onCheckedChange={(v) => form.setValue("confirmBroad", v === true)} />
          <FieldLabel htmlFor="policy-confirm-broad" className="text-pretty">
            {t("Dosya herkesten herkese erişim açan yeni bir kural eklerse bunu bilerek onaylıyorum")}
          </FieldLabel>
        </Field>
      </FieldGroup>
      <Writable>
        <div className="flex">
          <Button type="submit">{t("Değişikliği göster")}</Button>
        </div>
      </Writable>
    </form>
  )
}
