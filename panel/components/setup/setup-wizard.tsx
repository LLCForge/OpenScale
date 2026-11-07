"use client"

import { Fragment, useState } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import useSWR from "swr"
import { ArrowLeft, ArrowRight, CircleCheck, HardDriveDownload, Plus, ShieldCheck } from "lucide-react"

import { BrandWordmark } from "@/components/brand"
import { LanguageCorner } from "@/components/language-switcher"
import { CodeLine } from "@/components/copy-field"
import { AddDeviceDialog } from "@/components/devices/add-device-dialog"
import { BundleDownload } from "@/components/network/bundle-download"
import { CoordinatorForm, type CoordinatorValues } from "@/components/network/coordinator-dialog"
import { QueryState } from "@/components/query-state"
import { BackupDialog } from "@/components/security/backup-dialog"
import { DevicePreview } from "@/components/setup/device-preview"
import { MissingSteps } from "@/components/setup/missing-steps"
import { SignChange } from "@/components/sign-change"
import { Button } from "@/components/ui/button"
import { fetcher } from "@/lib/api"
import { msg, useI18n } from "@/lib/i18n/i18n"
import type { Device, DevicesResponse, NetworkInfo, Overview, Rule, RulesResponse } from "@/lib/types"
import { cn } from "@/lib/utils"

type StepId = "backup" | "coordinator" | "first" | "second" | "rule" | "join" | "test"

// The backup comes first (#792): a root key without a backup is lost with
// this computer, so a wizard opened again resumes there.
const steps: StepId[] = ["backup", "coordinator", "first", "second", "rule", "join", "test"]

/** Step names for the missing steps list; join and test are not tracked. */
const stepTitles: Partial<Record<StepId, string>> = {
  backup: msg("Kök anahtar yedeği"),
  coordinator: msg("Koordinatör"),
  first: msg("İlk cihaz"),
  second: msg("İkinci cihaz"),
  rule: msg("Bağlantı testi kuralı"),
}

/** Fills the {name} slots of a translated sentence with elements. */
function fill(text: string, parts: Record<string, React.ReactNode>): React.ReactNode[] {
  return text.split(/(\{\w+\})/).map((piece, i) => {
    const m = /^\{(\w+)\}$/.exec(piece)
    return m && m[1] in parts ? <Fragment key={i}>{parts[m[1]]}</Fragment> : piece
  })
}

function hasPingRule(rules: Rule[], a: Device, b: Device): boolean {
  return rules.some(
    (r) =>
      (r.from.includes(a.name) || r.from.includes("*")) &&
      (r.to.includes(b.name) || r.to.includes("*")) &&
      (r.protocol === "icmp" || r.protocol === "any")
  )
}

export function SetupWizard() {
  const { t } = useI18n()
  const network = useSWR<NetworkInfo>("/api/network", fetcher)
  const devices = useSWR<DevicesResponse>("/api/devices", fetcher)
  const rules = useSWR<RulesResponse>("/api/rules", fetcher)
  const overview = useSWR<Overview>("/api/overview", fetcher)
  const error = network.error ?? devices.error ?? rules.error ?? overview.error
  const loading = network.isLoading || devices.isLoading || rules.isLoading || overview.isLoading

  return (
    <main className="flex min-h-svh flex-col items-center gap-10 bg-background px-4 py-10">
      <BrandWordmark size="lg" />
      <LanguageCorner />
      <div className="w-full max-w-6xl">
        <QueryState
          error={error}
          isLoading={loading}
          onRetry={() => {
            network.mutate()
            devices.mutate()
            rules.mutate()
            overview.mutate()
          }}
        >
          {network.data && devices.data && rules.data && overview.data ? (
            <Wizard
              network={network.data}
              devices={devices.data.devices}
              rules={rules.data.rules}
              backupCount={overview.data.backupCount}
              onBackup={() => overview.mutate()}
            />
          ) : null}
        </QueryState>
      </div>
      <p className="text-sm text-muted-foreground">
        {t("OpenScale'i zaten biliyor musun?")}{" "}
        <Link href="/" className="font-medium text-foreground underline-offset-4 hover:underline">
          {t("Panele geç")}
        </Link>
      </p>
    </main>
  )
}

interface WizardProps {
  network: NetworkInfo
  devices: Device[]
  rules: Rule[]
  backupCount: number
  onBackup: () => void
}

function Wizard({ network, devices, rules, backupCount, onBackup }: WizardProps) {
  const { t } = useI18n()
  const router = useRouter()
  const [first, second] = devices
  const done: Record<StepId, boolean> = {
    backup: backupCount > 0,
    coordinator: network.coordinator !== null,
    first: devices.length >= 1,
    second: devices.length >= 2,
    rule: Boolean(first && second && hasPingRule(rules, first, second)),
    join: false,
    test: false,
  }
  const firstOpen = steps.findIndex((s) => !done[s])
  const [index, setIndex] = useState(firstOpen === -1 ? steps.length - 1 : firstOpen)
  const step = steps[index]
  // The backup may be postponed; it stays in the missing steps list.
  const canNext = index < steps.length - 1 && (done[step] || step === "join" || step === "backup")
  const missing = steps.filter((s) => stepTitles[s] !== undefined && !done[s])

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
      <section className="flex flex-col gap-8 rounded-xl border bg-card p-6 sm:p-8">
        <div className="flex justify-center gap-2" aria-label={t("Adım {current} / {total}", { current: index + 1, total: steps.length })}>
          {steps.map((s, i) => (
            <button
              key={s}
              type="button"
              aria-label={t("Adım {n}", { n: i + 1 })}
              aria-current={i === index ? "step" : undefined}
              onClick={() => setIndex(i)}
              className={cn("h-1 w-10 rounded-full transition-colors", i <= index ? "bg-primary" : "bg-muted-foreground/30")}
            />
          ))}
        </div>

        <MissingSteps
          steps={missing.map((s) => ({ id: s, title: t(stepTitles[s] ?? s) }))}
          current={step}
          onSelect={(id) => setIndex(steps.indexOf(id as StepId))}
        />

        <StepBody step={step} network={network} devices={devices} done={done} first={first} second={second} onBackup={onBackup} />

        <div className="flex items-center justify-between gap-3 border-t pt-6">
          <Button variant="ghost" onClick={() => setIndex((i) => Math.max(0, i - 1))} disabled={index === 0}>
            <ArrowLeft data-icon="inline-start" />
            {t("Geri")}
          </Button>
          {step === "test" ? (
            <Button onClick={() => router.push("/")}>
              {t("Çalışıyor, panele geç")}
              <ArrowRight data-icon="inline-end" />
            </Button>
          ) : (
            <Button onClick={() => setIndex((i) => i + 1)} disabled={!canNext}>
              {step === "join" ? t("Tüneller açık, devam") : step === "backup" && !done.backup ? t("Sonra yap, devam") : t("Devam")}
              <ArrowRight data-icon="inline-end" />
            </Button>
          )}
        </div>
      </section>

      <aside className="flex min-h-80 items-center justify-center rounded-xl border bg-card p-6 sm:p-8">
        <DevicePreview first={first} second={second} connected={done.rule} />
      </aside>
    </div>
  )
}

interface StepBodyProps {
  step: StepId
  network: NetworkInfo
  devices: Device[]
  done: Record<StepId, boolean>
  first?: Device
  second?: Device
  onBackup: () => void
}

function StepTitle({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-3 text-center">
      <h1 className="text-2xl font-semibold tracking-tight text-balance">{title}</h1>
      <div className="max-w-xl text-sm leading-relaxed text-muted-foreground text-pretty">{children}</div>
    </div>
  )
}

function DoneNote({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-center gap-2 rounded-lg border bg-muted/40 px-4 py-3 text-sm">
      <CircleCheck className="size-4 text-success" />
      {children}
    </div>
  )
}

function StepBody({ step, network, devices, done, first, second, onBackup }: StepBodyProps) {
  const { t } = useI18n()
  const [coordinator, setCoordinator] = useState<CoordinatorValues | null>(null)
  const [adding, setAdding] = useState(false)
  const [signingRule, setSigningRule] = useState(false)
  const [backingUp, setBackingUp] = useState(false)

  switch (step) {
    case "backup":
      return (
        <div className="flex flex-col gap-6">
          <StepTitle title={t("Kök anahtarını yedekle")}>
            {t(
              "Kök anahtar ağının tek yetkilisidir ve yalnızca bu bilgisayarda durur. Yedek ayrı bir parolayla şifrelenir; bir USB belleğe veya başka bir diske kaydet. Bu bilgisayar bozulursa ağın yedekten geri gelir.",
            )}
          </StepTitle>
          {done.backup ? (
            <DoneNote>{t("Kök anahtarın yedeği alınmış.")}</DoneNote>
          ) : (
            <div className="flex flex-col items-center gap-3">
              <Button size="lg" onClick={() => setBackingUp(true)}>
                <HardDriveDownload data-icon="inline-start" />
                {t("Yedeği şimdi al")}
              </Button>
              <p className="text-center text-sm text-muted-foreground text-pretty">
                {t("Kurulumu yarıda bırakırsan sihirbaz bir dahaki açılışta bu adımdan devam eder.")}
              </p>
            </div>
          )}
          <BackupDialog open={backingUp} onOpenChange={setBackingUp} onCreated={onBackup} />
        </div>
      )
    case "coordinator":
      return (
        <div className="flex flex-col gap-6">
          <StepTitle title={t("Koordinatörünü bağla")}>
            {t(
              "Koordinatör, cihazlarının birbirini bulduğu buluşma noktasıdır. Kendi VPS'inde veya ev sunucunda çalışır; ağ belgesini değiştiremez ve trafiğini göremez. Sunucuda şu komutu çalıştırıp çıkan bilgileri aşağıya gir:",
            )}
          </StepTitle>
          <CodeLine value="openscale coordinator keygen --state-dir /var/lib/openscale-coordinator" nowrap />
          {done.coordinator && !coordinator ? (
            <DoneNote>
              {fill(t("Koordinatör tanımlı: {endpoint}"), {
                endpoint: <span className="font-mono">{network.coordinator?.endpoint}</span>,
              })}
            </DoneNote>
          ) : null}
          {!done.coordinator && !coordinator ? <CoordinatorForm submitLabel={t("Değişikliği göster")} onSubmit={setCoordinator} inline /> : null}
          {coordinator ? (
            <SignChange
              endpoint="/api/network/coordinator"
              payload={coordinator}
              confirmLabel={t("İmzala ve kaydet")}
              onBack={() => setCoordinator(null)}
              onDone={() => setCoordinator(null)}
              inline
            />
          ) : null}
        </div>
      )
    case "first":
    case "second": {
      const isFirst = step === "first"
      const device = isFirst ? first : second
      return (
        <div className="flex flex-col gap-6">
          <StepTitle title={isFirst ? t("İlk cihazını ekle") : t("Sıra ikinci cihazında")}>
            {isFirst
              ? t(
                  "Ağdaki her cihaz kendi özel IP adresini ve adını alır. Eklemek istediğin bilgisayarda anahtarları üret; özel anahtarlar o cihazdan hiç çıkmaz.",
                )
              : t(
                  "Ağdaki her cihaz kendi özel IP adresini ve adını alır. Eklemek istediğin ikinci cihazda anahtarları üret; özel anahtarlar o cihazdan hiç çıkmaz.",
                )}
          </StepTitle>
          <CodeLine value="openscale keygen" />
          {device ? (
            <DoneNote>
              {fill(t("{name} eklendi · {ip}"), {
                name: <span className="font-medium">{device.name}</span>,
                ip: <span className="font-mono">{device.ipv4}</span>,
              })}
            </DoneNote>
          ) : (
            <div className="flex flex-col items-center gap-3">
              <Button size="lg" onClick={() => setAdding(true)}>
                <Plus data-icon="inline-start" />
                {t("Kayıt isteğini yapıştır")}
              </Button>
              <p className="text-center text-sm text-muted-foreground">{t("Cihazın ekranındaki parmak izini panelde elle yazman istenecek.")}</p>
            </div>
          )}
          <AddDeviceDialog open={adding} onOpenChange={setAdding} />
        </div>
      )
    }
    case "rule":
      return (
        <div className="flex flex-col gap-6">
          <StepTitle title={t("Bağlantı testi için kural oluştur")}>
            {t(
              "OpenScale'de varsayılan olarak her şey kapalıdır. Test için {from} cihazının {to} cihazına ping atabilmesine izin veren bir kural imzalayalım. Diğer erişimleri daha sonra Erişim Kontrolü'nden eklersin.",
              { from: first?.name ?? "", to: second?.name ?? "" },
            )}
          </StepTitle>
          {done.rule ? (
            <DoneNote>
              {t("{from} → {to} ICMP kuralı var", { from: first?.name ?? "", to: second?.name ?? "" })}
            </DoneNote>
          ) : first && second ? (
            signingRule ? (
              <SignChange
                endpoint="/api/rules"
                payload={{ from: [first.name], to: [second.name], protocol: "icmp", ports: [], description: t("Bağlantı testi") }}
                confirmLabel={t("İmzala ve ekle")}
                onBack={() => setSigningRule(false)}
                onDone={() => setSigningRule(false)}
                inline
              />
            ) : (
              <div className="flex justify-center">
                <Button size="lg" onClick={() => setSigningRule(true)}>
                  <ShieldCheck data-icon="inline-start" />
                  {t("{from} → {to} ping kuralını oluştur", { from: first.name, to: second.name })}
                </Button>
              </div>
            )
          ) : (
            <DoneNote>{t("Önce iki cihaz ekle.")}</DoneNote>
          )}
        </div>
      )
    case "join":
      return (
        <div className="flex flex-col gap-6">
          <StepTitle title={t("Cihazlarını ağa kat ve tüneli aç")}>
            {t("Katılım paketini her cihaza kopyala. Paketin gerçekten senin ağından geldiğini, komuttaki kök parmak izi kanıtlar:")}{" "}
            <span className="font-mono text-foreground">{network.rootFingerprint}</span>
          </StepTitle>
          <div className="flex justify-center">
            <BundleDownload bundle={network.bundle} variant="default" />
          </div>
          <ol className="flex flex-col gap-4">
            <li className="flex flex-col gap-2">
              <span className="text-sm">{t("1. Her cihazda paketle ağa katıl")}</span>
              <CodeLine value={`openscale join --bundle @openscale-bundle.txt --root-fingerprint ${network.rootFingerprint}`} nowrap />
            </li>
            <li className="flex flex-col gap-2">
              <span className="text-sm">{t("2. Yönetici yetkisiyle tüneli aç (Windows: yönetici PowerShell, Linux: sudo)")}</span>
              <CodeLine value="openscale up" />
            </li>
          </ol>
          <p className="text-center text-sm text-muted-foreground">
            {t("Bu bilgisayar da bir cihazsa, panelde yaptığın değişiklikleri koordinatöre anında iletmesi için:")}{" "}
            <code className="font-mono">{`openscale up --network-dir <${t("ağ klasörü")}>`}</code>
          </p>
          {devices.length < 2 ? <DoneNote>{t("Önce iki cihaz ekle.")}</DoneNote> : null}
        </div>
      )
    case "test":
      return (
        <div className="flex flex-col gap-6">
          <StepTitle title={t("Bağlantıyı test edelim")}>{t("Cihazların birbirini görebiliyor mu? Kısa bir ping yeterli.")}</StepTitle>
          <ol className="flex flex-col gap-5">
            <li className="flex gap-4">
              <span className="flex size-7 shrink-0 items-center justify-center rounded-full border text-xs text-muted-foreground">1</span>
              <div className="flex min-w-0 flex-1 flex-col gap-2">
                <span className="text-sm leading-relaxed">
                  {fill(t("{from} cihazından {to} cihazına ping at. Bağlantı çalışıyorsa yanıt gelir."), {
                    from: <span className="font-medium">{first?.name}</span>,
                    to: <span className="font-medium">{second?.name}</span>,
                  })}
                </span>
                <CodeLine value={`ping ${second?.ipv4 ?? t("<ikinci cihazın IP'si>")}`} />
              </div>
            </li>
            <li className="flex gap-4">
              <span className="flex size-7 shrink-0 items-center justify-center rounded-full border text-xs text-muted-foreground">2</span>
              <p className="text-sm leading-relaxed text-muted-foreground">
                {t(
                  "Yanıt gelmiyorsa: iki cihazda da `openscale up` çalışıyor mu, koordinatör portu (51820/UDP) açık mı ve belge sürümleri aynı mı kontrol et. Ters yönde ping için ayrıca kural gerekir.",
                )}
              </p>
            </li>
          </ol>
        </div>
      )
  }
}
