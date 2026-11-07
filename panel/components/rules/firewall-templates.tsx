"use client"

import { useState } from "react"
import useSWR from "swr"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { ArrowRight, TriangleAlert } from "lucide-react"

import { DetailSection } from "@/components/devices/detail-card"
import { SignChangeDialog } from "@/components/sign-change"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { errorMessage, fetcher, post } from "@/lib/api"
import { msg, useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

interface TemplateInfo {
  kind: string
  title: string
  description: string
  needsTargets: boolean
  needsPorts: boolean
  ranges: boolean
  isolate: boolean
}

interface PlanRule {
  from: string[]
  to: string[]
  protocol?: string
  ports?: string[]
  action?: string
}

interface ReachChange {
  from: string
  to: string
  probe: string
  before: boolean
  after: boolean
}

interface TemplatePlan {
  kind: string
  added: PlanRule[] | null
  disabled: number[]
  warnings: string[]
  exitUsersChanged: boolean
  reach: ReachChange[]
  reachTruncated: boolean
  base: string
}

const splitList = (s: string) =>
  s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean)

const formSchema = z.object({
  subject: z.string().trim().min(1, msg("Konu gerekli")).max(69, msg("Konu çok uzun")),
  targets: z.string().max(1200, msg("Hedef listesi çok uzun")),
  ports: z.string().max(400, msg("Port listesi çok uzun")),
})
type TemplateForm = z.infer<typeof formSchema>

const PROTOCOLS = ["tcp", "udp", "any"] as const
const PROTOCOL_LABELS: Record<(typeof PROTOCOLS)[number], string> = { tcp: "TCP", udp: "UDP", any: "ANY" }

/**
 * Ready-made firewall templates (#727, #243, ADR-0215, ADR-0232). The
 * server computes the plan; signing goes through the usual dry run and
 * root key. IoT isolation also takes a CIDR range behind a subnet router,
 * for cameras that do not run OpenScale.
 */
export function FirewallTemplatesSection() {
  const { t, ts } = useI18n()
  const { data } = useSWR<{ templates: TemplateInfo[] }>("/api/fwtemplate", fetcher)
  const [kind, setKind] = useState("iot-isolation")
  const [protocol, setProtocol] = useState<(typeof PROTOCOLS)[number]>("tcp")
  const [isolate, setIsolate] = useState(false)
  const [plan, setPlan] = useState<TemplatePlan | null>(null)
  const [payload, setPayload] = useState<Record<string, unknown> | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [signing, setSigning] = useState(false)
  const form = useForm<TemplateForm>({ resolver: zodResolver(formSchema), defaultValues: { subject: "", targets: "", ports: "" } })
  const { errors, isSubmitting } = form.formState
  const info = data?.templates.find((x) => x.kind === kind)
  if (!data || !info) return null

  async function preview(values: TemplateForm) {
    if (!info) return
    setError(null)
    setPlan(null)
    const body: Record<string, unknown> = {
      kind,
      subject: values.subject.trim(),
      targets: info.needsTargets ? splitList(values.targets) : [],
      ports: info.needsPorts && protocol !== "any" ? splitList(values.ports) : [],
      protocol: info.needsPorts ? protocol : "",
      isolate: info.isolate && isolate,
    }
    try {
      const res = await post<TemplatePlan>("/api/fwtemplate/preview", body)
      setPlan(res)
      setPayload({ ...body, base: res.base })
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  return (
    <DetailSection
      id="sablonlar"
      title={t("Güvenlik duvarı şablonları")}
      description={t("Hazır paketler sıradan imzalı kurallar üretir; önce önizlemede neyin değiştiğini görürsün.")}
      framed={false}
    >
      <div className="flex flex-col gap-4 rounded-lg border p-4">
        <div role="radiogroup" aria-label={t("Şablon")} className="flex flex-wrap gap-2">
          {data.templates.map((x) => (
            <button
              key={x.kind}
              type="button"
              role="radio"
              aria-checked={x.kind === kind}
              onClick={() => {
                setKind(x.kind)
                setPlan(null)
              }}
              className={cn(
                "rounded-md border px-3 py-1.5 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring",
                x.kind === kind ? "border-primary bg-primary/10 text-foreground" : "text-muted-foreground hover:text-foreground",
              )}
            >
              {ts(x.title)}
            </button>
          ))}
        </div>
        <p className="text-sm text-muted-foreground text-pretty">{ts(info.description)}</p>
        <form onSubmit={form.handleSubmit(preview)} noValidate className="flex flex-col gap-4">
          <FieldGroup>
            <Field data-invalid={errors.subject ? true : undefined}>
              <FieldLabel htmlFor="tpl-subject">{t("Konu")}</FieldLabel>
              <Input id="tpl-subject" className="font-mono" autoComplete="off" spellCheck={false} placeholder={info.ranges ? t("tag:iot veya 192.168.1.16/28") : t("cihaz, tag:x veya group:x")} {...form.register("subject")} />
              <FieldDescription>
                {info.ranges
                  ? t("Cihaz adı, tag:x, group:x ya da bir IP/CIDR aralığı veya host:ad. Alt ağ yönlendirici arkasındaki bir aralık OpenScale kurmamış cihazları (kamera gibi) kapsar.")
                  : t("Cihaz adı, tag:x veya group:x.")}
              </FieldDescription>
              <FieldError errors={[errors.subject]} />
            </Field>
            {info.needsTargets ? (
              <Field>
                <FieldLabel htmlFor="tpl-targets">{t("Hedefler")}</FieldLabel>
                <Input id="tpl-targets" className="font-mono" autoComplete="off" spellCheck={false} placeholder={t("ha, nas")} {...form.register("targets")} />
                <FieldDescription>{t("Konunun bağlanabileceği cihazlar; virgülle ayır.")}</FieldDescription>
              </Field>
            ) : null}
            {info.needsPorts ? (
              <Field>
                <FieldLabel htmlFor="tpl-ports">{t("Portlar")}</FieldLabel>
                <div className="flex flex-wrap items-center gap-2">
                  <div role="radiogroup" aria-label={t("Protokol")} className="flex gap-1">
                    {PROTOCOLS.map((p) => (
                      <Button key={p} type="button" size="sm" variant={protocol === p ? "default" : "outline"} role="radio" aria-checked={protocol === p} onClick={() => setProtocol(p)}>
                        {PROTOCOL_LABELS[p]}
                      </Button>
                    ))}
                  </div>
                  <Input id="tpl-ports" className="max-w-60 font-mono" autoComplete="off" disabled={protocol === "any"} placeholder={t("8123, 1883")} {...form.register("ports")} />
                </div>
              </Field>
            ) : null}
            {info.isolate ? (
              <Field orientation="horizontal">
                <Checkbox id="tpl-isolate" checked={isolate} onCheckedChange={(c) => setIsolate(c === true)} />
                <div className="flex flex-col gap-1">
                  <FieldLabel htmlFor="tpl-isolate">{t("Kendi aralarında ve internete kapalı")}</FieldLabel>
                  <FieldDescription>{t("Konudaki cihazlar birbirine bağlanamaz ve çıkış düğümünü kullanamaz.")}</FieldDescription>
                </div>
              </Field>
            ) : null}
          </FieldGroup>
          <div>
            <Button type="submit" variant="outline" disabled={isSubmitting}>
              {isSubmitting ? <Spinner data-icon="inline-start" /> : null}
              {t("Önizle")}
            </Button>
          </div>
        </form>
        {error ? (
          <Alert variant="destructive">
            <TriangleAlert />
            <AlertTitle>{t("Şablon uygulanamaz")}</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        {plan ? <PlanView plan={plan} onSign={() => setSigning(true)} /> : null}
      </div>
      {payload ? (
        <SignChangeDialog
          open={signing}
          onOpenChange={(v) => {
            setSigning(v)
            if (!v) setPlan(null)
          }}
          title={t("Şablonu imzala")}
          description={t("Önizlemedeki kurallar belgeye yazılır. Belge önizlemeden sonra değiştiyse imza reddedilir; yeniden önizle.")}
          endpoint="/api/fwtemplate/apply"
          payload={payload}
          confirmLabel={t("İmzala ve uygula")}
        />
      ) : null}
    </DetailSection>
  )
}

function ruleText(r: PlanRule): string {
  const what = r.protocol === "any" || !r.protocol ? "any" : `${r.protocol}/${(r.ports ?? []).join(",")}`
  return `${r.action === "deny" ? "deny " : ""}${r.from.join(",")} -> ${r.to.join(",")} ${what}`
}

function PlanView({ plan, onSign }: { plan: TemplatePlan; onSign: () => void }) {
  const { t, ts } = useI18n()
  const added = plan.added ?? []
  return (
    <div className="flex flex-col gap-3 text-sm">
      <div className="flex flex-col gap-1">
        <h3 className="font-medium">{t("Eklenecek kurallar")}</h3>
        <ul className="flex flex-col gap-1">
          {added.map((r, i) => (
            <li key={i} className="font-mono break-all">
              {ruleText(r)}
            </li>
          ))}
        </ul>
        {plan.disabled.length > 0 ? (
          <p className="text-muted-foreground">{t("Kapatılacak dar kurallar: {list}", { list: plan.disabled.map((i) => `#${i + 1}`).join(", ") })}</p>
        ) : null}
        {plan.exitUsersChanged ? <p className="text-muted-foreground">{t("Çıkış düğümü kullanıcıları da değişir.")}</p> : null}
      </div>
      {plan.warnings.length > 0 ? (
        <Alert>
          <TriangleAlert />
          <AlertTitle>{t("Dikkat")}</AlertTitle>
          <AlertDescription>
            <ul className="flex list-disc flex-col gap-1 pl-4">
              {plan.warnings.map((w) => (
                <li key={w} className="text-pretty">
                  {ts(w)}
                </li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      ) : null}
      {plan.reach.length > 0 ? (
        <div className="flex flex-col gap-1">
          <h3 className="font-medium">{t("Erişim değişiklikleri")}</h3>
          <ul className="flex flex-col gap-1">
            {plan.reach.slice(0, 40).map((r, i) => (
              <li key={i} className="flex flex-wrap items-center gap-2">
                <span className="font-mono">{r.from}</span>
                <ArrowRight aria-hidden="true" className="size-3.5 text-muted-foreground" />
                <span className="font-mono">{r.to}</span>
                <span className="text-muted-foreground">{r.probe}</span>
                <Badge variant={r.after ? "default" : "secondary"}>{r.after ? t("açılır") : t("kapanır")}</Badge>
              </li>
            ))}
          </ul>
          {plan.reachTruncated || plan.reach.length > 40 ? <p className="text-muted-foreground">{t("Liste kısaltıldı.")}</p> : null}
        </div>
      ) : null}
      <div>
        <Button onClick={onSign}>{t("İmzalamaya geç")}</Button>
      </div>
    </div>
  )
}
