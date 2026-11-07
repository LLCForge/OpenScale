"use client"

import { useState } from "react"
import useSWR from "swr"
import { toast } from "sonner"
import { Plus, Trash2 } from "lucide-react"

import { Writable } from "@/components/app/read-only"
import { PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { EmptyNote, SettingBadge, SettingRow, SettingsColumn, SettingsSection, SignatureBadge, ValueBox } from "@/components/settings/settings-layout"
import { SignChangeDialog } from "@/components/sign-change"
import { Button } from "@/components/ui/button"
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { errorMessage, fetcher, post } from "@/lib/api"
import { formatDateTime, formatNumber } from "@/lib/format"
import { tx, useI18n } from "@/lib/i18n/i18n"

import { categoryLabels, type BlockingSettings, type ExtensionsView, type PluginEntry, type PluginPin, type TopView } from "./types"

const listLimit = 256

/** Lines of a textarea as a clean, deduplicated name list. */
function toNames(text: string): string[] {
  const out: string[] = []
  for (const raw of text.split(/\r?\n/)) {
    const n = raw.trim().toLowerCase().replace(/\.$/, "")
    if (n && !out.includes(n)) out.push(n)
  }
  return out.slice(0, listLimit)
}

function count(n: number | undefined): string {
  return formatNumber(n ?? 0)
}

/** Name of a blocking category in the interface language. */
function categoryName(c: string): string {
  const label = categoryLabels[c]
  return label ? tx(label) : c
}

interface Pending {
  title: string
  description: string
  endpoint: string
  payload: Record<string, unknown>
  destructive?: boolean
}

/** Engelleme ve eklentiler (ADR-0212..0220): signed blocking settings, counters and plugins. */
export function BlockingView() {
  const { t } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<ExtensionsView>("/api/g7/extensions", fetcher, { refreshInterval: 15000 })
  const [pending, setPending] = useState<Pending | null>(null)

  function signBlocking(next: BlockingSettings, title: string, description: string) {
    setPending({ title, description, endpoint: "/api/g7/blocking", payload: { blocking: next } })
  }

  return (
    <SettingsColumn>
      <PageHeader
        title={t("Engelleme ve eklentiler")}
        description={t(
          "Reklam, izleyici ve telemetri engeli çıkış düğümünün DNS çözücüsünde çalışır. Kategoriler, abonelikler ve eklenti sabitlemeleri imzalı belgededir; koordinatör bunları değiştiremez.",
        )}
      />
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {data && (
          <>
            <StatsSection view={data} />
            <CategoriesSection view={data} onSign={signBlocking} />
            <SubscriptionsSection view={data} onSign={signBlocking} />
            <AllowSection view={data} onSign={signBlocking} />
            <PluginsSection view={data} onPending={setPending} />
          </>
        )}
      </QueryState>
      {pending && (
        <SignChangeDialog
          open
          onOpenChange={(o) => !o && setPending(null)}
          title={pending.title}
          description={pending.description}
          endpoint={pending.endpoint}
          payload={pending.payload}
          destructive={pending.destructive}
          confirmLabel={t("İmzala ve yayınla")}
          onSigned={() => {
            void mutate()
          }}
        />
      )}
    </SettingsColumn>
  )
}

function current(view: ExtensionsView): BlockingSettings {
  return view.blocking ?? {}
}

function StatsSection({ view }: { view: ExtensionsView }) {
  const { t, ts } = useI18n()
  const rt = view.runtime
  if (!rt.active) {
    return (
      <SettingsSection
        title={t("Çalışma durumu")}
        description={t("Sayaçlar yalnızca çıkış düğümü olan bu bilgisayarda görünür. Hangi ad sorulduğu hiç saklanmaz.")}
      >
        <EmptyNote>
          {view.exit_nodes.length > 0
            ? t("Engelleme bu bilgisayarda çalışmıyor. Çıkış düğümleri: {nodes}.", { nodes: view.exit_nodes.join(", ") })
            : t("Ağda çıkış düğümü yok. Engelleme bir cihaz çıkış düğümü olunca çalışır.")}
        </EmptyNote>
      </SettingsSection>
    )
  }
  const blocked = rt.adblock?.blocked ?? {}
  return (
    <SettingsSection
      title={t("Çalışma durumu")}
      description={t("Belge sürüm {version}. Yalnızca sayaçlar tutulur; sorulan adlar saklanmaz.", { version: rt.version })}
    >
      {rt.error && <SettingRow title={t("Uyarı")} description={ts(rt.error)} badge={<SettingBadge tone="warning">{t("Eksik")}</SettingBadge>} />}
      <dl className="grid grid-cols-2 gap-x-6 gap-y-3 py-3 text-sm sm:grid-cols-3">
        {view.categories.map((c) => (
          <div key={c} className="flex flex-col gap-0.5">
            <dt className="text-muted-foreground">{categoryName(c)}</dt>
            <dd className="font-medium tabular-nums">{count(blocked[c])}</dd>
          </div>
        ))}
        <div className="flex flex-col gap-0.5">
          <dt className="text-muted-foreground">.onion (NXDOMAIN)</dt>
          <dd className="font-medium tabular-nums">{count(rt.onion)}</dd>
        </div>
        <div className="flex flex-col gap-0.5">
          <dt className="text-muted-foreground">{t("DoH adları")}</dt>
          <dd className="font-medium tabular-nums">{count(rt.doh)}</dd>
        </div>
        <div className="flex flex-col gap-0.5">
          <dt className="text-muted-foreground">{t("Eklenti engeli")}</dt>
          <dd className="font-medium tabular-nums">{count(rt.plugin_blocked)}</dd>
        </div>
      </dl>
      <TopList />
    </SettingsSection>
  )
}

function TopList() {
  const { t } = useI18n()
  const { data, mutate } = useSWR<TopView>("/api/g7/adblock/top", fetcher, { refreshInterval: 10000 })
  const [busy, setBusy] = useState(false)
  async function toggle(minutes: number) {
    setBusy(true)
    try {
      await post("/api/g7/adblock/top", { minutes })
      await mutate()
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <SettingRow
      title={t("En çok engellenen adlar")}
      description={
        data?.active && data.until
          ? t("Liste yalnızca bellekte tutuluyor, {at} tarihinde silinir.", { at: formatDateTime(data.until) })
          : t("Kapalı. Açınca en çok engellenen adlar en fazla 1 saat, yalnızca bellekte tutulur.")
      }
      action={
        <Writable>
          <Button size="sm" variant="outline" disabled={busy} onClick={() => toggle(data?.active ? 0 : 60)}>
            {data?.active ? t("Kapat ve sil") : t("1 saat aç")}
          </Button>
        </Writable>
      }
    >
      {data && data.names.length > 0 && (
        <ol className="flex flex-col gap-1 text-sm">
          {data.names.map((n) => (
            <li key={n.name} className="flex justify-between gap-4">
              <span className="truncate font-mono text-xs">{n.name}</span>
              <span className="tabular-nums text-muted-foreground">{count(n.count)}</span>
            </li>
          ))}
        </ol>
      )}
    </SettingRow>
  )
}

type Signer = (next: BlockingSettings, title: string, description: string) => void

function CategoriesSection({ view, onSign }: { view: ExtensionsView; onSign: Signer }) {
  const { t } = useI18n()
  const cur = current(view)
  const [selected, setSelected] = useState<string[]>(cur.policy?.default ?? [])
  const [keep, setKeep] = useState((cur.keep ?? []).join("\n"))
  const [doh, setDoh] = useState((cur.block_doh ?? []).join("\n"))
  const telemetryNeedsKeep = selected.includes("os-telemetry") && toNames(keep).length === 0

  function save() {
    const next: BlockingSettings = {
      ...cur,
      policy: selected.length > 0 || cur.policy ? { ...(cur.policy ?? {}), default: selected } : undefined,
      keep: toNames(keep),
      block_doh: toNames(doh),
    }
    onSign(
      next,
      t("Engelleme kategorilerini imzala"),
      t("Seçilen kategoriler varsayılan olarak bütün cihazlara uygulanır. Etiket ve cihaz kayıtları varsa onlar önce gelir."),
    )
  }

  return (
    <SettingsSection title={t("Kategoriler")} description={t("Çıkış düğümü kullanan cihazlarda varsayılan olarak engellenecek kategoriler.")} signed>
      {view.categories.map((c) => (
        <SettingRow
          key={c}
          title={categoryName(c)}
          htmlFor={`cat-${c}`}
          action={
            <Switch
              id={`cat-${c}`}
              checked={selected.includes(c)}
              onCheckedChange={(on) => setSelected((s) => (on ? [...s, c] : s.filter((x) => x !== c)))}
            />
          }
        />
      ))}
      <FieldGroup className="py-3">
        <Field data-invalid={telemetryNeedsKeep || undefined}>
          <FieldLabel htmlFor="keep">{t("Her zaman izin verilen adlar (keep)")}</FieldLabel>
          <Textarea id="keep" rows={3} value={keep} onChange={(e) => setKeep(e.target.value)} placeholder="update.microsoft.com" />
          <FieldDescription>
            {telemetryNeedsKeep
              ? t("Telemetri engeli güncelleme alanlarını kesebilir. Açmak için en az bir güncelleme alanı yazın.")
              : t("Her satıra bir ad. Bu adlar ve altındakiler hiçbir kategoride engellenmez.")}
          </FieldDescription>
        </Field>
        <Field>
          <FieldLabel htmlFor="doh">{t("Engellenen DoH sunucu adları")}</FieldLabel>
          <Textarea id="doh" rows={3} value={doh} onChange={(e) => setDoh(e.target.value)} placeholder="dns.example.net" />
          <FieldDescription>{t("Tarayıcılar bu adları çözemeyince ağın kendi DNS çözücüsüne döner.")}</FieldDescription>
        </Field>
      </FieldGroup>
      <Writable>
        <div className="flex justify-end pb-3">
          <Button onClick={save} disabled={telemetryNeedsKeep}>
            {t("Önizle ve imzala")}
          </Button>
        </div>
      </Writable>
    </SettingsSection>
  )
}

const hex64 = /^[0-9a-f]{64}$/

function SubscriptionsSection({ view, onSign }: { view: ExtensionsView; onSign: Signer }) {
  const { t } = useI18n()
  const cur = current(view)
  const subs = cur.subscriptions ?? []
  const [category, setCategory] = useState(view.categories[0] ?? "ads")
  const [url, setUrl] = useState("")
  const [sha, setSha] = useState("")
  const urlOk = url.startsWith("https://") && url.length <= 2048
  const shaOk = hex64.test(sha.trim().toLowerCase())
  const loaded = new Map(view.runtime.lists.map((l) => [l.sha256, l]))

  function add() {
    const next = { ...cur, subscriptions: [...subs, { category, url: url.trim(), sha256: sha.trim().toLowerCase() }] }
    onSign(
      next,
      t("Liste aboneliğini imzala"),
      t("Çıkış düğümü listeyi yalnızca bu özetle aynıysa kullanır. Liste değişirse yeni özeti yeniden imzalamanız gerekir."),
    )
  }
  function remove(i: number) {
    onSign(
      { ...cur, subscriptions: subs.filter((_, j) => j !== i) },
      t("Liste aboneliğini kaldır"),
      t("Liste bir sonraki belge sürümünde çıkış düğümünden kalkar."),
    )
  }

  return (
    <SettingsSection
      title={t("Abonelikler")}
      description={t("Listeleri yalnızca çıkış düğümü indirir ve imzalı özetle karşılaştırır. Özeti hesaplamak için: openscale blocking digest <dosya> --category <kategori>")}
      signed
    >
      {subs.length === 0 && <EmptyNote>{t("Henüz abonelik yok.")}</EmptyNote>}
      {subs.map((s, i) => {
        const l = loaded.get(s.sha256)
        return (
          <SettingRow
            key={`${s.sha256}-${i}`}
            title={categoryName(s.category)}
            description={<span className="break-all font-mono text-xs">{s.url}</span>}
            badge={
              l ? (
                <SettingBadge tone="success">{t("{count} ad yüklü", { count: count(l.names) })}</SettingBadge>
              ) : (
                <SettingBadge tone="warning">{t("Yüklenmedi")}</SettingBadge>
              )
            }
            action={
              <Writable>
                <Button size="icon" variant="ghost" aria-label={t("Aboneliği kaldır")} onClick={() => remove(i)}>
                  <Trash2 />
                </Button>
              </Writable>
            }
          />
        )
      })}
      <Writable>
        <FieldGroup className="py-3">
          <Field>
            <FieldLabel htmlFor="sub-cat">{t("Kategori")}</FieldLabel>
            <select
              id="sub-cat"
              className="h-9 rounded-md border bg-background px-3 text-sm"
              value={category}
              onChange={(e) => setCategory(e.target.value)}
            >
              {view.categories.map((c) => (
                <option key={c} value={c}>
                  {categoryName(c)}
                </option>
              ))}
            </select>
          </Field>
          <Field data-invalid={(url !== "" && !urlOk) || undefined}>
            <FieldLabel htmlFor="sub-url">{t("Adres (yalnızca https)")}</FieldLabel>
            <Input id="sub-url" value={url} onChange={(e) => setUrl(e.target.value)} inputMode="url" autoComplete="off" />
          </Field>
          <Field data-invalid={(sha !== "" && !shaOk) || undefined}>
            <FieldLabel htmlFor="sub-sha">{t("SHA-256 özeti")}</FieldLabel>
            <Input id="sub-sha" value={sha} onChange={(e) => setSha(e.target.value)} className="font-mono text-xs" autoComplete="off" spellCheck={false} />
            <FieldDescription>{t("64 onaltılık karakter. İncelediğiniz dosyanın özeti olmalı.")}</FieldDescription>
          </Field>
          <div className="flex justify-end">
            <Button onClick={add} disabled={!urlOk || !shaOk || subs.length >= 32}>
              <Plus data-icon="inline-start" />
              {t("Aboneliği ekle")}
            </Button>
          </div>
        </FieldGroup>
      </Writable>
    </SettingsSection>
  )
}

function AllowSection({ view, onSign }: { view: ExtensionsView; onSign: Signer }) {
  const { t } = useI18n()
  const cur = current(view)
  const [exceptions, setExceptions] = useState((cur.policy?.exceptions ?? []).join("\n"))
  const { data: top, mutate } = useSWR<TopView>("/api/g7/adblock/top", fetcher)
  const [device, setDevice] = useState("")
  const [name, setName] = useState("")
  const [busy, setBusy] = useState(false)

  function saveExceptions() {
    const policy = { ...(cur.policy ?? { default: [] }), exceptions: toNames(exceptions) }
    onSign({ ...cur, policy }, t("İzin listesini imzala"), t("Bu adlar hiçbir cihazda engellenmez."))
  }
  async function allowOnce() {
    setBusy(true)
    try {
      await post("/api/g7/adblock/allow-once", { device: device.trim(), name: name.trim(), minutes: 60 })
      setName("")
      await mutate()
      toast.success(t("Ad bir saatliğine engellenmeyecek."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }
  async function revoke(d: string | undefined, n: string) {
    try {
      await post("/api/g7/adblock/allow-once/revoke", { device: d ?? "", name: n })
      await mutate()
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }

  return (
    <SettingsSection
      title={t("İzin listesi")}
      description={t("Kalıcı istisnalar imzalı belgededir. Süreli izin yalnızca çıkış düğümünün belleğinde tutulur ve en çok 24 saat sürer.")}
    >
      <FieldGroup className="py-3">
        <Field>
          <FieldLabel htmlFor="exc">{t("Kalıcı istisnalar")}</FieldLabel>
          <Textarea id="exc" rows={3} value={exceptions} onChange={(e) => setExceptions(e.target.value)} placeholder={t("bankam.example")} />
          <FieldDescription>{t("Her satıra bir ad. Ad ve altındaki bütün adlar engellenmez.")}</FieldDescription>
        </Field>
        <Writable>
          <div className="flex items-center justify-end gap-2">
            <SignatureBadge />
            <Button variant="outline" onClick={saveExceptions}>
              {t("Önizle ve imzala")}
            </Button>
          </div>
        </Writable>
      </FieldGroup>
      <Writable>
        <FieldGroup className="border-t py-3">
          <Field>
            <FieldLabel htmlFor="once-name">{t("Bir saatliğine izin ver")}</FieldLabel>
            <Input id="once-name" value={name} onChange={(e) => setName(e.target.value)} placeholder={t("ad.example")} autoComplete="off" />
          </Field>
          <Field>
            <FieldLabel htmlFor="once-device">{t("Cihaz (boşsa bütün cihazlar)")}</FieldLabel>
            <Input id="once-device" value={device} onChange={(e) => setDevice(e.target.value)} autoComplete="off" />
          </Field>
          <div className="flex justify-end">
            <Button onClick={allowOnce} disabled={busy || name.trim() === "" || !view.runtime.active}>
              {t("İzin ver")}
            </Button>
          </div>
        </FieldGroup>
      </Writable>
      {top && top.once.length > 0 && (
        <ul className="flex flex-col gap-1 pb-3 text-sm">
          {top.once.map((o) => (
            <li key={`${o.device}-${o.name}`} className="flex items-center justify-between gap-3">
              <span className="truncate">
                <span className="font-mono text-xs">{o.name}</span>
                <span className="text-muted-foreground">
                  {" "}
                  · {o.device ? o.device : t("bütün cihazlar")} · {t("{at} tarihine kadar", { at: formatDateTime(o.until) })}
                </span>
              </span>
              <Writable>
                <Button size="sm" variant="ghost" onClick={() => revoke(o.device, o.name)}>
                  {t("Kaldır")}
                </Button>
              </Writable>
            </li>
          ))}
        </ul>
      )}
    </SettingsSection>
  )
}

const statusTone: Record<string, "success" | "warning" | "danger" | "muted"> = {
  loaded: "success",
  unpinned: "warning",
}

function PluginsSection({ view, onPending }: { view: ExtensionsView; onPending: (p: Pending) => void }) {
  const { t, ts } = useI18n()
  const entries = view.runtime.plugins
  const pinnedOnly = view.pins.filter((p) => !entries.some((e) => e.name === p.name))

  function pin(e: PluginEntry) {
    if (!e.module_sha256 || !e.manifest_sha256) return
    const p: PluginPin = { name: e.name, module_sha256: e.module_sha256, manifest_sha256: e.manifest_sha256 }
    onPending({
      title: t("{name} eklentisini sabitle", { name: e.name }),
      description: t("Eklenti şunları görecek: {data}. Dosyalar bu özetlerden farklılaşırsa yüklenmez.", {
        data: e.data_labels.map((l) => ts(l)).join(", "),
      }),
      endpoint: "/api/g7/plugins/pin",
      payload: { pin: p },
    })
  }
  function unpin(name: string) {
    onPending({
      title: t("{name} sabitlemesini kaldır", { name }),
      description: t("Eklenti bir sonraki belge sürümünde çıkış düğümünde çalışmayı bırakır."),
      endpoint: "/api/g7/plugins/unpin",
      payload: { name },
      destructive: true,
    })
  }

  return (
    <SettingsSection
      title={t("Eklentiler")}
      description={t(
        "Eklentiler çıkış düğümünde ağ ve dosya erişimi olmadan, 16 MiB bellek ve kısa süre sınırıyla çalışır. Yalnızca imzalı belgede özeti sabitlenmiş olanlar yüklenir.",
      )}
    >
      {entries.length === 0 && pinnedOnly.length === 0 && <EmptyNote>{t("Bu bilgisayarın eklenti klasöründe eklenti yok.")}</EmptyNote>}
      {entries.map((e) => (
        <SettingRow
          key={e.name}
          title={`${e.name}${e.version ? ` ${e.version}` : ""}`}
          description={
            <span className="flex flex-col gap-1">
              {e.description && <span>{ts(e.description)}</span>}
              <span>
                {t("Görür: {data}", {
                  data:
                    e.data_labels
                      .filter((l) => !e.hooks.includes("http_location") || l !== "HTTP Location")
                      .map((l) => ts(l))
                      .join(", ") || t("hiçbir şey"),
                })}
              </span>
              <span className="text-muted-foreground">
                {t("Kancalar: {hooks} · hata durumunda {onError} · {memory} MiB · {timeout} ms", {
                  hooks: e.hooks.join(", "),
                  onError: e.on_error ?? "pass",
                  memory: e.memory_limit_mib,
                  timeout: e.call_timeout_ms,
                })}
              </span>
              {e.hooks.includes("http_location") && (
                <span className="text-muted-foreground">
                  {t(
                    "HTTP Location kancası bu sürümde çağrılmaz: çıkış düğümü HTTP trafiğini aracı olarak taşımadığı için eklenti yalnızca DNS kancasıyla çalışır ve HTTP adreslerini görmez.",
                  )}
                </span>
              )}
              {e.reason && <span className="text-destructive">{ts(e.reason)}</span>}
              {e.module_sha256 && <ValueBox value={e.module_sha256} label={t("Modül özetini kopyala")} />}
            </span>
          }
          badge={<SettingBadge tone={statusTone[e.status] ?? "danger"}>{ts(e.status_label)}</SettingBadge>}
          action={
            <Writable>
              {e.pinned ? (
                <Button size="sm" variant="ghost" onClick={() => unpin(e.name)}>
                  {t("Sabitlemeyi kaldır")}
                </Button>
              ) : (
                <Button size="sm" variant="outline" onClick={() => pin(e)} disabled={!e.module_sha256}>
                  {t("İncele ve sabitle")}
                </Button>
              )}
            </Writable>
          }
        />
      ))}
      {pinnedOnly.map((p) => (
        <SettingRow
          key={p.name}
          title={p.name}
          description={t("İmzalı belgede sabitli ama bu bilgisayarın eklenti klasöründe yok.")}
          badge={<SettingBadge tone="muted">{t("Dosya yok")}</SettingBadge>}
          action={
            <Writable>
              <Button size="sm" variant="ghost" onClick={() => unpin(p.name)}>
                {t("Sabitlemeyi kaldır")}
              </Button>
            </Writable>
          }
        />
      ))}
      {view.runtime.plugin_events.length > 0 && (
        <SettingRow title={t("Son eklenti olayları")} description={t("Olaylarda sorgu adı veya adres bulunmaz.")}>
          <ul className="flex flex-col gap-1 text-sm">
            {view.runtime.plugin_events.slice(-8).reverse().map((ev, i) => (
              <li key={`${ev.time}-${i}`} className="text-muted-foreground">
                {formatDateTime(ev.time)} · {ev.plugin} · {ev.kind}
              </li>
            ))}
          </ul>
        </SettingRow>
      )}
    </SettingsSection>
  )
}
