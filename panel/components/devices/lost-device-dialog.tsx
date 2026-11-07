"use client"

import { useState } from "react"
import useSWR from "swr"

import { radioGroupKeyDown } from "@/components/settings/radio-keys"
import { SignChange } from "@/components/sign-change"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldContent, FieldDescription, FieldLabel, FieldSet, FieldLegend } from "@/components/ui/field"
import { Skeleton } from "@/components/ui/skeleton"
import { errorMessage, fetcher } from "@/lib/api"
import { formatAgo, formatDateTime } from "@/lib/format"
import { useI18n } from "@/lib/i18n/i18n"
import { accessSummary, type ExposureRule, type LostReport } from "@/lib/p02-types"
import { cn } from "@/lib/utils"

// "Bu cihazı kaybettim" (#367): one screen with what the lost device could
// reach, what could reach it, the passwords worth changing, and the two
// ways out (permanent removal or only ending the membership).

type Action = "revoke" | "expire"
type Step = { kind: "review" } | { kind: "sign"; action: Action; dropRules: boolean }

export function LostDeviceDialog({ name, onClose }: { name: string | null; onClose: () => void }) {
  const { t } = useI18n()
  const [step, setStep] = useState<Step>({ kind: "review" })
  function close(open: boolean) {
    if (open) return
    setStep({ kind: "review" })
    onClose()
  }
  return (
    <Dialog open={name !== null} onOpenChange={close}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{t("Kayıp cihaz: {name}", { name: name ?? "" })}</DialogTitle>
          <DialogDescription className="text-pretty">
            {step.kind === "review"
              ? t("Cihazın ağda neye ulaşabildiğine bak, sonra onu ağdan çıkar. Değişiklik imzalanana kadar hiçbir şey değişmez.")
              : step.action === "revoke"
                ? t("Cihazın anahtarları kalıcı olarak iptal edilir ve adı geçtiği her yerden kaldırılır. Geri gelmesi için yeni davetle katılması gerekir.")
                : t("Üyelik şimdi biter; cihaz yeni bağlantı kuramaz. Anahtarları iptal edilmez, üyelik sonradan uzatılabilir.")}
          </DialogDescription>
        </DialogHeader>
        {name && step.kind === "review" ? (
          <Review name={name} onCancel={() => close(false)} onNext={(action, dropRules) => setStep({ kind: "sign", action, dropRules })} />
        ) : null}
        {name && step.kind === "sign" ? (
          <SignChange
            endpoint="/api/p02/devices/lost"
            payload={{ name, action: step.action, dropRules: step.action === "expire" && step.dropRules }}
            confirmLabel={step.action === "revoke" ? t("İmzala ve kalıcı olarak çıkar") : t("İmzala ve üyeliği bitir")}
            destructive
            confirmText={step.action === "revoke" ? name : undefined}
            onBack={() => setStep({ kind: "review" })}
            onCancel={() => close(false)}
            onDone={() => close(false)}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

function Review({ name, onCancel, onNext }: { name: string; onCancel: () => void; onNext: (action: Action, dropRules: boolean) => void }) {
  const { t, ts } = useI18n()
  const { data, error } = useSWR<LostReport>(`/api/p02/devices/lost?name=${encodeURIComponent(name)}`, fetcher, { revalidateOnFocus: false })
  const [action, setAction] = useState<Action>("revoke")
  const [dropRules, setDropRules] = useState(true)
  const [done, setDone] = useState<Set<string>>(new Set())

  if (error) {
    return (
      <>
        <Alert variant="destructive">
          <AlertDescription>{errorMessage(error)}</AlertDescription>
        </Alert>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onCancel}>
            {t("Vazgeç")}
          </Button>
        </DialogFooter>
      </>
    )
  }
  if (!data) {
    return (
      <div className="flex flex-col gap-2" aria-busy="true" aria-label={t("Cihazın erişimleri yükleniyor")}>
        <Skeleton className="h-4 w-1/3" />
        <Skeleton className="h-32 w-full" />
      </div>
    )
  }

  const checklist = data.checklist ?? []
  return (
    <div className="flex max-h-[65vh] flex-col gap-5 overflow-y-auto pr-1">
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-muted-foreground">{t("Son görülme")}</dt>
        <dd>{data.lastSeen ? <span title={formatDateTime(data.lastSeen)}>{formatAgo(data.lastSeen)}</span> : t("Bilinmiyor")}</dd>
        <dt className="text-muted-foreground">{t("Adres")}</dt>
        <dd className="font-mono text-[0.8125rem]">{data.ipv4}</dd>
        {data.routes && data.routes.length > 0 ? (
          <>
            <dt className="text-muted-foreground">{t("Yönlendirdiği ağlar")}</dt>
            <dd className="font-mono text-[0.8125rem]">{data.routes.join(", ")}</dd>
          </>
        ) : null}
      </dl>

      <ExposureList
        title={t("Bu cihazın erişebildikleri")}
        rules={data.outbound ?? []}
        side="to"
        empty={t("Bu cihaz başka cihaza bağlantı başlatamıyor.")}
      />
      <ExposureList title={t("Bu cihaza erişebilenler")} rules={data.inbound ?? []} side="from" empty={t("Hiçbir cihaz bu cihaza bağlanamıyor.")} />

      {checklist.length > 0 ? (
        <FieldSet>
          <FieldLegend variant="label">{t("Değiştirilmesi gereken parolalar")}</FieldLegend>
          <FieldDescription>{t("Bu liste yalnızca bu sayfada tutulur; işaretlediklerin hiçbir yere kaydedilmez.")}</FieldDescription>
          <ul className="flex flex-col gap-2">
            {checklist.map((item) => (
              <li key={item}>
                <label className="flex items-start gap-2.5 text-sm">
                  <Checkbox
                    className="mt-0.5"
                    checked={done.has(item)}
                    onCheckedChange={(v) =>
                      setDone((s) => {
                        const next = new Set(s)
                        if (v === true) next.add(item)
                        else next.delete(item)
                        return next
                      })
                    }
                  />
                  <span className={cn("text-pretty", done.has(item) && "text-muted-foreground line-through")}>{ts(item)}</span>
                </label>
              </li>
            ))}
          </ul>
        </FieldSet>
      ) : null}

      <FieldSet>
        <FieldLegend variant="label">{t("Ne yapılsın")}</FieldLegend>
        <div role="radiogroup" aria-label={t("Kayıp cihaz için işlem")} onKeyDown={radioGroupKeyDown} className="flex flex-col gap-2">
          <ActionOption
            checked={action === "revoke"}
            onSelect={() => setAction("revoke")}
            title={t("Kalıcı olarak çıkar (önerilen)")}
            description={t("Anahtarlar iptal edilir, cihaz adının geçtiği kurallar ve gruplar temizlenir. Geri alınamaz.")}
          />
          <ActionOption
            checked={action === "expire"}
            onSelect={() => setAction("expire")}
            title={t("Yalnızca üyeliği bitir")}
            description={t("Cihazın geri bulunma ihtimali varsa. Cihaz belgede kalır; üyelik uzatılınca yeniden bağlanır.")}
          />
        </div>
        {action === "expire" ? (
          <Field orientation="horizontal">
            <Checkbox id="lost-drop-rules" checked={dropRules} onCheckedChange={(v) => setDropRules(v === true)} />
            <FieldContent>
              <FieldLabel htmlFor="lost-drop-rules">{t("Yalnızca bu cihaz için kalan kuralları da sil")}</FieldLabel>
              <FieldDescription>{t("Başka cihazların da geçtiği kurallar olduğu gibi kalır.")}</FieldDescription>
            </FieldContent>
          </Field>
        ) : null}
      </FieldSet>

      <DialogFooter className="sticky bottom-0">
        <Button type="button" variant="outline" onClick={onCancel}>
          {t("Vazgeç")}
        </Button>
        <Button type="button" variant="destructive" onClick={() => onNext(action, dropRules)}>
          {t("Değişikliği göster")}
        </Button>
      </DialogFooter>
    </div>
  )
}

function ExposureList({ title, rules, side, empty }: { title: string; rules: ExposureRule[]; side: "from" | "to"; empty: string }) {
  const { t } = useI18n()
  return (
    <section className="flex flex-col gap-2">
      <h3 className="text-sm font-medium">{title}</h3>
      {rules.length === 0 ? (
        <p className="text-sm text-muted-foreground">{empty}</p>
      ) : (
        <ul className="flex flex-col divide-y rounded-lg border">
          {rules.map((r) => (
            <li key={`${side}-${r.index}`} className="flex flex-col gap-0.5 px-3 py-2 text-sm">
              <span className="flex flex-wrap items-baseline gap-x-2">
                <span className="font-mono text-[0.8125rem] break-all">{(side === "to" ? r.to : r.from).join(", ")}</span>
                <span className="text-muted-foreground">{accessSummary(r)}</span>
              </span>
              {r.description ? <span className="text-muted-foreground">{r.description}</span> : null}
              {r.onlyThisDevice ? <span className="text-muted-foreground">{t("Cihaz çıkınca bu kural boş kalır ve silinir.")}</span> : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

interface ActionOptionProps {
  checked: boolean
  onSelect: () => void
  title: string
  description: string
}

/** One choice of the action radio group (the group handles the arrow keys). */
function ActionOption({ checked, onSelect, title, description }: ActionOptionProps) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={checked}
      tabIndex={checked ? 0 : -1}
      onClick={onSelect}
      className={cn(
        "flex items-start gap-3 rounded-lg border px-3 py-2.5 text-left outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50",
        checked ? "border-foreground/40 bg-secondary" : "hover:bg-muted/50"
      )}
    >
      <span
        aria-hidden="true"
        className={cn("mt-1 flex size-3.5 shrink-0 items-center justify-center rounded-full border", checked && "border-foreground")}
      >
        {checked ? <span className="size-1.5 rounded-full bg-foreground" /> : null}
      </span>
      <span className="flex flex-col gap-0.5">
        <span className="text-sm font-medium">{title}</span>
        <span className="text-sm text-muted-foreground text-pretty">{description}</span>
      </span>
    </button>
  )
}
