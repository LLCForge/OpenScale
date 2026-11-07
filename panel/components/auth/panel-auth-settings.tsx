"use client"

import { useState } from "react"
import useSWR from "swr"
import { KeyRound, Smartphone, TriangleAlert } from "lucide-react"
import { toast } from "sonner"

import { LockNowButton, setHideOnShare, useHideOnShare, type LockStatus } from "@/components/auth/privacy-guard"
import { useAuthStatus, withReauth } from "@/components/auth/reauth"
import { useRemoteSession } from "@/components/auth/session"
import { CodedError, fromB64url, optionalGet, postCoded, toB64url, webAuthnError, webAuthnUsable } from "@/components/auth/strict-api"
import { CopyButton } from "@/components/copy-field"
import { NativeSelect } from "@/components/native-select"
import { PageHeader } from "@/components/page-header"
import { EmptyNote, SettingRow, SettingsSection } from "@/components/settings/settings-layout"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { errorMessage } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"

// Ayarlar > Panel girişi ve gizlilik: second factors (ADR-0198, ADR-0199),
// re-authentication and admin mode (ADR-0202), idle lock (ADR-0206),
// screen sharing guard (ADR-0209), SSH host keys (ADR-0203) and the panel
// name inside the tunnel (ADR-0191). None of these changes the signed
// network document; some ask for a fresh proof of identity.

export function PanelAuthSettingsView() {
  const { t } = useI18n()
  const remote = useRemoteSession()
  return (
    <div className="flex flex-col gap-10">
      <PageHeader
        title={t("Panel girişi ve gizlilik")}
        description={t(
          "Panele kimlerin, hangi ikinci doğrulamayla girebileceği ve ekran başında olmadığınızda panelin nasıl korunacağı. Bu ayarlar ağ belgesini değiştirmez."
        )}
      />
      {remote ? (
        <EmptyNote>{t("Bu ayarlar yalnızca yönetici bilgisayarın kendi panelinde değiştirilebilir.")}</EmptyNote>
      ) : (
        <>
          <SecurityKeys />
          <TOTPSection />
          <AuthSwitches />
          <LockSection />
          <ShareSection />
          <HostKeysSection />
          <PanelNameSection />
        </>
      )}
    </div>
  )
}

interface RegisterChallenge {
  challenge: string
  rp_id: string
  user_id: string
  user_name: string
  exclude_credentials?: string[]
  timeout_ms: number
}

function SecurityKeys() {
  const { t } = useI18n()
  const { data, mutate } = useAuthStatus()
  const [name, setName] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const keys = data?.webauthn ?? []
  const usable = webAuthnUsable()
  const [hostBefore, hostAfter = ""] = t("Bu adreste güvenlik anahtarı eklenemez. Paneli {host} adresiyle açın.").split("{host}")

  async function add() {
    setBusy(true)
    setError("")
    try {
      const ch = await withReauth(() => postCoded<RegisterChallenge>("/api/auth/webauthn/register/begin", {}))
      const cred = await navigator.credentials.create({
        publicKey: {
          challenge: fromB64url(ch.challenge),
          rp: { id: ch.rp_id, name: "OpenScale" },
          user: { id: fromB64url(ch.user_id), name: ch.user_name, displayName: "OpenScale panel" },
          pubKeyCredParams: [
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -8 },
          ],
          excludeCredentials: (ch.exclude_credentials ?? []).map((id) => ({ type: "public-key" as const, id: fromB64url(id) })),
          attestation: "none",
          authenticatorSelection: { userVerification: "discouraged" },
          timeout: ch.timeout_ms,
        },
      })
      if (!(cred instanceof PublicKeyCredential) || !(cred.response instanceof AuthenticatorAttestationResponse)) {
        throw new Error(t("Güvenlik anahtarı yanıt vermedi."))
      }
      await postCoded("/api/auth/webauthn/register", {
        client_data_json: toB64url(cred.response.clientDataJSON),
        attestation_object: toB64url(cred.response.attestationObject),
        name: name.trim().slice(0, 64),
      })
      setName("")
      toast.success(t("Güvenlik anahtarı eklendi."))
      await mutate()
    } catch (err) {
      setError(webAuthnError(err))
    } finally {
      setBusy(false)
    }
  }

  async function remove(id: string) {
    try {
      await withReauth(() => postCoded("/api/auth/webauthn/remove", { id }))
      toast.success(t("Güvenlik anahtarı kaldırıldı."))
      await mutate()
    } catch (err) {
      toast.error(err instanceof Error ? errorMessage(err) : t("Anahtar kaldırılamadı."))
    }
  }

  return (
    <SettingsSection
      id="guvenlik-anahtarlari" // i18n-ignore: sayfa içi bağlantı kimliği
      title={t("Güvenlik anahtarları")}
      description={t(
        "YubiKey gibi bir anahtar, parolanın yanında ikinci doğrulama olur. Tarayıcılar anahtarı yalnızca ad ile açılan adreste (localhost) kullanır."
      )}
    >
      {keys.length === 0 ? (
        <EmptyNote>{t("Kayıtlı güvenlik anahtarı yok.")}</EmptyNote>
      ) : (
        <div className="overflow-x-auto rounded-lg border" data-slot="card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">{t("Ad")}</TableHead>
                <TableHead scope="col">{t("Eklenme")}</TableHead>
                <TableHead scope="col">{t("Son kullanım")}</TableHead>
                <TableHead scope="col">
                  <span className="sr-only">{t("İşlem")}</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {keys.map((k) => (
                <TableRow key={k.id}>
                  <TableCell className="font-medium">{k.name}</TableCell>
                  <TableCell className="tabular-nums">{formatDateTime(k.created_at)}</TableCell>
                  <TableCell className="tabular-nums">{k.last_used ? formatDateTime(k.last_used) : t("Hiç")}</TableCell>
                  <TableCell className="text-right">
                    <Button size="sm" variant="ghost" onClick={() => remove(k.id)}>
                      {t("Kaldır")}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      <div className="flex flex-col gap-2 rounded-lg border p-4" data-slot="card">
        {usable ? (
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <Field className="sm:max-w-xs">
              <FieldLabel htmlFor="webauthn-name">{t("Anahtarın adı")}</FieldLabel>
              <Input id="webauthn-name" placeholder={t("Güvenlik anahtarı")} maxLength={64} value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <Button onClick={add} disabled={busy} className="w-fit">
              {busy ? <Spinner data-icon="inline-start" /> : <KeyRound data-icon="inline-start" />}
              {t("Anahtar ekle")}
            </Button>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground text-pretty">
            {hostBefore}
            <span className="font-mono">localhost</span>
            {hostAfter}
          </p>
        )}
        {error ? <FieldError>{error}</FieldError> : null}
      </div>
    </SettingsSection>
  )
}

interface EnrollAnswer {
  uri: string
  secret: string
  remote: boolean
}

function TOTPSection() {
  const { t } = useI18n()
  const { data, mutate } = useAuthStatus()
  const [step, setStep] = useState<"idle" | "form" | "code">("idle")
  const [passphrase, setPassphrase] = useState("")
  const [remotePassword, setRemotePassword] = useState("")
  const [enroll, setEnroll] = useState<EnrollAnswer | null>(null)
  const [code, setCode] = useState("")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)

  async function begin(e: React.FormEvent) {
    e.preventDefault()
    if (!passphrase) return setError(t("Kök anahtar parolası gerekli."))
    setBusy(true)
    setError("")
    try {
      const body: Record<string, string> = { passphrase }
      if (remotePassword) body.remote_password = remotePassword
      const res = await withReauth(() => postCoded<EnrollAnswer>("/api/auth/totp/enroll/begin", body))
      setEnroll(res)
      setStep("code")
    } catch (err) {
      setError(err instanceof Error ? errorMessage(err) : t("Kayıt başlatılamadı."))
    } finally {
      setPassphrase("")
      setRemotePassword("")
      setBusy(false)
    }
  }

  async function finish(e: React.FormEvent) {
    e.preventDefault()
    if (!/^\d{6}$/.test(code)) return setError(t("Altı haneli kodu girin."))
    setBusy(true)
    setError("")
    try {
      await postCoded("/api/auth/totp/enroll/finish", { code })
      toast.success(t("Kimlik doğrulama uygulaması eklendi."))
      setEnroll(null)
      setStep("idle")
      await mutate()
    } catch (err) {
      setError(err instanceof Error ? errorMessage(err) : t("Kod doğrulanamadı."))
    } finally {
      setCode("")
      setBusy(false)
    }
  }

  async function remove() {
    try {
      await withReauth(() => postCoded("/api/auth/totp/remove", {}))
      toast.success(t("Kimlik doğrulama uygulaması kaldırıldı."))
      await mutate()
    } catch (err) {
      toast.error(err instanceof Error ? errorMessage(err) : t("Kaldırılamadı."))
    }
  }

  return (
    <SettingsSection
      id="totp"
      title={t("Kimlik doğrulama uygulaması (yedek)")}
      description={t("Güvenlik anahtarı yanınızda değilken 6 haneli kodla giriş. Kodun tohumu parolanızla mühürlü saklanır.")}
    >
      <div className="flex flex-col gap-4 rounded-lg border p-4" data-slot="card">
        {data?.totp ? (
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-sm">
              {data.totp_remote ? t("Kayıtlı. Uzak panelde de kullanılabilir.") : t("Kayıtlı. Yalnızca bu bilgisayarın panelinde kullanılır.")}
            </p>
            <Button size="sm" variant="ghost" onClick={remove} className="w-fit">
              {t("Kaldır")}
            </Button>
          </div>
        ) : null}
        {step === "idle" && !data?.totp ? (
          <Button variant="outline" className="w-fit" onClick={() => setStep("form")}>
            <Smartphone data-icon="inline-start" />
            {t("Kimlik doğrulama uygulaması ekle")}
          </Button>
        ) : null}
        {step === "form" ? (
          <form onSubmit={begin} noValidate className="flex flex-col gap-4">
            <FieldGroup className="grid gap-4 md:grid-cols-2">
              <Field data-invalid={error ? true : undefined}>
                <FieldLabel htmlFor="totp-pass">{t("Kök anahtar parolası")}</FieldLabel>
                <Input id="totp-pass" type="password" autoComplete="current-password" maxLength={1024} value={passphrase} onChange={(e) => setPassphrase(e.target.value)} />
              </Field>
              <Field>
                <FieldLabel htmlFor="totp-remote">{t("Uzak erişim parolası (isteğe bağlı)")}</FieldLabel>
                <Input id="totp-remote" type="password" autoComplete="off" maxLength={1024} value={remotePassword} onChange={(e) => setRemotePassword(e.target.value)} />
                <FieldDescription>{t("Girerseniz kod uzak panelde de kullanılır.")}</FieldDescription>
              </Field>
            </FieldGroup>
            <FieldError>{error}</FieldError>
            <div className="flex gap-2">
              <Button type="submit" disabled={busy}>
                {busy ? <Spinner data-icon="inline-start" /> : null}
                {t("Devam")}
              </Button>
              <Button type="button" variant="ghost" onClick={() => { setStep("idle"); setError("") }}>
                {t("Vazgeç")}
              </Button>
            </div>
          </form>
        ) : null}
        {step === "code" && enroll ? (
          <form onSubmit={finish} noValidate className="flex flex-col gap-4">
            <Alert>
              <TriangleAlert />
              <AlertDescription>{t("Bu kodu kimseyle paylaşmayın. Sayfayı kapatınca bir daha gösterilmez.")}</AlertDescription>
            </Alert>
            <div className="flex flex-col gap-1">
              <span className="text-sm text-muted-foreground">{t("Uygulamaya elle girilecek anahtar")}</span>
              <div className="flex items-center gap-1 rounded-md border bg-muted/40 px-3 py-2">
                <code data-secret="" className="min-w-0 flex-1 break-all tracking-wider">{enroll.secret}</code>
                <CopyButton value={enroll.secret} label={t("Anahtarı kopyala")} secret />
              </div>
              <div className="flex items-center gap-1 text-xs text-muted-foreground">
                <span>{t("Bağlantıyı destekleyen uygulamalar için:")}</span>
                <CopyButton value={enroll.uri} label={t("Kayıt bağlantısını kopyala")} secret />
              </div>
            </div>
            <Field data-invalid={error ? true : undefined} className="sm:max-w-xs">
              <FieldLabel htmlFor="totp-code">{t("Uygulamadaki kod")}</FieldLabel>
              <Input
                id="totp-code"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                className="font-mono tabular-nums tracking-widest"
              />
              <FieldError>{error}</FieldError>
              <FieldDescription>{t("Beş dakika içinde tamamlayın.")}</FieldDescription>
            </Field>
            <Button type="submit" disabled={busy} className="w-fit">
              {busy ? <Spinner data-icon="inline-start" /> : null}
              {t("Kaydı bitir")}
            </Button>
          </form>
        ) : null}
      </div>
    </SettingsSection>
  )
}

type SwitchKey = "reauth_critical" | "admin_mode" | "admin_token" | "local_mfa"

const switches: { key: SwitchKey; title: string; description: string }[] = [
  {
    key: "reauth_critical",
    title: msg("Kritik işlemlerde yeniden doğrulama iste"),
    description: msg("Önerilen: açık. Anahtar ekleme, kaldırma gibi işlemler taze bir doğrulama ister."),
  },
  {
    key: "admin_mode",
    title: msg("Yönetici kipi: değişiklikler 15 dakika sonra kapanır"),
    description: msg("Doğrulamadan 15 dakika sonra panel salt okunur olur; yeniden doğrulayınca açılır."),
  },
  {
    key: "admin_token",
    title: msg("YubiKey çekilince yönetici kipini hemen kapat"),
    description: msg("Anahtarı geri takmak yetmez; yeni bir doğrulama gerekir."),
  },
  {
    key: "local_mfa",
    title: msg("Bu bilgisayarda da ikinci doğrulama iste"),
    description: msg("En az bir güvenlik anahtarı veya kimlik doğrulama uygulaması kayıtlı olmalı."),
  },
]

function AuthSwitches() {
  const { t } = useI18n()
  const { data, mutate } = useAuthStatus()
  const [busy, setBusy] = useState<SwitchKey | null>(null)
  if (!data) return null

  async function change(key: SwitchKey, on: boolean) {
    setBusy(key)
    try {
      await withReauth(() => postCoded("/api/auth/settings", { [key]: on }))
      await mutate()
    } catch (err) {
      toast.error(err instanceof Error ? errorMessage(err) : t("Ayar kaydedilemedi."))
    } finally {
      setBusy(null)
    }
  }

  return (
    // i18n-ignore: sayfa içi bağlantı kimliği
    <SettingsSection id="dogrulama-ayarlari" title={t("Doğrulama kuralları")}>
      <div className="flex flex-col divide-y rounded-lg border px-4" data-slot="card">
        {switches.map((s) => (
          <SettingRow
            key={s.key}
            title={t(s.title)}
            description={t(s.description)}
            htmlFor={`auth-${s.key}`}
            action={<Switch id={`auth-${s.key}`} checked={data[s.key]} disabled={busy !== null} onCheckedChange={(v) => change(s.key, v === true)} />}
          />
        ))}
      </div>
    </SettingsSection>
  )
}

const lockChoices = [0, 5, 10, 15, 30]

function LockSection() {
  const { t } = useI18n()
  const { data, mutate } = useSWR<LockStatus | null>("/api/app/privacy/lock", optionalGet)
  const [busy, setBusy] = useState(false)
  if (data === null) return null
  if (!data) return null
  const choices = lockChoices.includes(data.minutes) ? lockChoices : [...lockChoices, data.minutes].sort((a, b) => a - b)

  async function change(minutes: number) {
    setBusy(true)
    try {
      await postCoded("/api/app/privacy/lock/settings", { minutes })
      await mutate()
    } catch (err) {
      if (err instanceof CodedError && err.status === 409) toast.error(t("Bu bilgisayarda kilidi açacak bir yöntem yok."))
      else toast.error(err instanceof Error ? errorMessage(err) : t("Ayar kaydedilemedi."))
    } finally {
      setBusy(false)
    }
  }

  return (
    <SettingsSection id="bosta-kilit" title={t("Boşta kilit")} action={<LockNowButton />}>
      <div className="flex flex-col divide-y rounded-lg border px-4" data-slot="card">
        <SettingRow
          title={t("Boşta kalınca paneli kilitle")}
          description={t(
            "Süre dolunca panel bulanıklaşır ve devam etmek için parola ister. Kilit sunucuda uygulanır; sayfa değiştirilse de veri gelmez."
          )}
          htmlFor="lock-minutes"
          action={
            <NativeSelect id="lock-minutes" value={String(data.minutes)} disabled={busy || data.method === "none"} onChange={(e) => change(Number(e.target.value))}>
              {choices.map((m) => (
                <option key={m} value={m}>
                  {m === 0 ? t("Kapalı") : t("{count} dakika", { count: m })}
                </option>
              ))}
            </NativeSelect>
          }
        />
      </div>
    </SettingsSection>
  )
}

function ShareSection() {
  const { t } = useI18n()
  const on = useHideOnShare()
  return (
    <SettingsSection id="ekran-paylasimi" title={t("Ekran paylaşımı")}>
      <div className="flex flex-col divide-y rounded-lg border px-4" data-slot="card">
        <SettingRow
          title={t("Ekran paylaşılırken sırları otomatik gizle")}
          description={t(
            "Zoom, Teams, OBS gibi bir uygulama açıkken anahtarlar, parmak izleri, adresler ve kodlar bulanıklaşır; üzerine gelince 10 saniye görünür. Tarayıcıdan yapılan paylaşımlar algılanamaz. Bu tercih yalnızca bu tarayıcıda saklanır."
          )}
          htmlFor="hide-on-share"
          action={<Switch id="hide-on-share" checked={on} onCheckedChange={(v) => setHideOnShare(v === true)} />}
        />
      </div>
    </SettingsSection>
  )
}

interface HostKey {
  host: string
  type: string
  fingerprint: string
  first_seen: string
  last_seen: string
}

function HostKeysSection() {
  const { t } = useI18n()
  const { data, mutate } = useSWR<{ hosts: HostKey[] | null } | null>("/api/ssh/hostkeys", optionalGet)
  if (!data) return null
  const hosts = data.hosts ?? []

  async function forget(host: string) {
    try {
      await withReauth(() => postCoded("/api/ssh/hostkeys/forget", { host }))
      toast.success(t("Kayıt silindi."))
      await mutate()
    } catch (err) {
      toast.error(err instanceof Error ? errorMessage(err) : t("Kayıt silinemedi."))
    }
  }

  return (
    <SettingsSection
      id="ssh-anahtarlari" // i18n-ignore: sayfa içi bağlantı kimliği
      title={t("SSH sunucu anahtarları")}
      description={t("Panel terminalinin ilk bağlantıda kaydettiği anahtarlar. Anahtar değişirse bağlantı kurulmaz.")}
    >
      {hosts.length === 0 ? (
        <EmptyNote>{t("Kayıtlı sunucu anahtarı yok.")}</EmptyNote>
      ) : (
        <div className="overflow-x-auto rounded-lg border" data-slot="card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">{t("Cihaz")}</TableHead>
                <TableHead scope="col">{t("Parmak izi")}</TableHead>
                <TableHead scope="col">{t("İlk görülme")}</TableHead>
                <TableHead scope="col">{t("Son görülme")}</TableHead>
                <TableHead scope="col">
                  <span className="sr-only">{t("İşlem")}</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {hosts.map((h) => (
                <TableRow key={h.host}>
                  <TableCell className="font-medium">{h.host}</TableCell>
                  <TableCell className="max-w-72 font-mono text-xs break-all whitespace-normal">
                    {h.type} {h.fingerprint}
                  </TableCell>
                  <TableCell className="tabular-nums">{formatDateTime(h.first_seen)}</TableCell>
                  <TableCell className="tabular-nums">{formatDateTime(h.last_seen)}</TableCell>
                  <TableCell className="text-right">
                    <Button size="sm" variant="ghost" onClick={() => forget(h.host)}>
                      {t("Kaydı sil")}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </SettingsSection>
  )
}

interface PanelName {
  name: string
  url: string
  hosts: string[] | null
  note: string
}

function PanelNameSection() {
  const { t, ts } = useI18n()
  const { data } = useSWR<PanelName | null>("/api/g3/panel-name", optionalGet, { shouldRetryOnError: false })
  if (!data) return null
  return (
    <SettingsSection
      id="panel-adresi"
      title={t("Uzak panel adresi")}
      description={t("Bu ad yalnızca tünel içinde çözülür ve imzalı belgeden gelir; başka bir ad panelde kabul edilmez.")}
    >
      <div className="flex flex-col gap-2 rounded-lg border p-4 text-sm" data-slot="card">
        {data.name ? (
          <>
            <div className="flex items-center gap-1">
              <span className="text-muted-foreground">{t("Uzak panel adresi:")}</span>
              <span className="font-mono text-xs break-all">{data.url}</span>
              <CopyButton value={data.url} label={t("Adresi kopyala")} />
            </div>
            <p className="text-muted-foreground">{t("Sunan cihazlar: {hosts}", { hosts: (data.hosts ?? []).join(", ") || "-" })}</p>
          </>
        ) : (
          <p className="text-muted-foreground text-pretty">{ts(data.note)}</p>
        )}
      </div>
    </SettingsSection>
  )
}
