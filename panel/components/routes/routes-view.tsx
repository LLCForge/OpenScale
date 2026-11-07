"use client"

import { Fragment, useState } from "react"
import useSWR, { useSWRConfig } from "swr"
import { Plus, ShieldCheck, TriangleAlert } from "lucide-react"
import { toast } from "sonner"

import { useReadOnly, Writable } from "@/components/app/read-only"
import { DetailSection } from "@/components/devices/detail-card"
import { PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { SubnetInventorySection } from "@/components/routes/subnet-inventory"
import { headCell, ListTable, RowMenu } from "@/components/settings/list-table"
import { EmptyNote, SettingBadge, SettingRow, SettingsColumn, SettingsSection } from "@/components/settings/settings-layout"
import { SignChange } from "@/components/sign-change"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { DropdownMenuItem } from "@/components/ui/dropdown-menu"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import { errorMessage, fetcher, post } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import { parseRouteList, type RouteInspect, type RoutesStatus } from "@/lib/routes-types"
import { cn } from "@/lib/utils"

const strategyLabels: Record<RoutesStatus["strategy"], string> = {
  first: msg("İlk boş adres"),
  sequential: msg("Sıralı"),
  random: msg("Rastgele"),
}

/** Puts a node where the translated text has its {name} placeholder. */
function withNode(text: string, name: string, node: React.ReactNode): React.ReactNode {
  const mark = `{${name}}`
  const at = text.indexOf(mark)
  if (at < 0) return text
  return (
    <>
      {text.slice(0, at)}
      {node}
      {text.slice(at + mark.length)}
    </>
  )
}

/** Puts nodes where the translated text has its {name} placeholders. */
function withNodes(text: string, nodes: Record<string, React.ReactNode>): React.ReactNode {
  const parts = text.split(/(\{\w+\})/)
  return (
    <>
      {parts.map((part, i) => {
        const m = /^\{(\w+)\}$/.exec(part)
        const node = m ? nodes[m[1]] : undefined
        return <Fragment key={i}>{node ?? part}</Fragment>
      })}
    </>
  )
}

/** Subnet routes and their approval (ADR-0133). */
export function RoutesView() {
  const { t } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<RoutesStatus>("/api/routes", fetcher)
  const [editing, setEditing] = useState<string | null>(null)
  return (
    <SettingsColumn>
      <PageHeader
        title={t("Rotalar")}
        description={t("Alt ağ yönlendiricileri, OpenScale kurulamayan cihazların ağını (yazıcı, NAS, kamera) özel ağa açar.")}
        actions={
          data ? (
            <Writable>
              <Button variant="outline" onClick={() => setEditing("")}>
                <Plus data-icon="inline-start" />
                {t("Cihaza rota ekle")}
              </Button>
            </Writable>
          ) : null
        }
      />
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {data ? (
          <>
            {data.conflicts.length > 0 ? <ConflictsAlert status={data} /> : null}
            <RoutersSection status={data} onEdit={setEditing} />
            <SubnetInventorySection />
            <ApproveSection onChanged={() => mutate()} />
            <ExternalExitsSection status={data} />
            <AddressingSection status={data} />
            <RouteEditDialog status={data} device={editing} onClose={() => setEditing(null)} onDone={() => mutate()} />
          </>
        ) : null}
      </QueryState>
    </SettingsColumn>
  )
}

function ConflictsAlert({ status }: { status: RoutesStatus }) {
  const { t, ts } = useI18n()
  return (
    <Alert variant="destructive">
      <TriangleAlert className="size-4" aria-hidden="true" />
      <AlertTitle>{t("Bu bilgisayarın ağlarıyla çakışma")}</AlertTitle>
      <AlertDescription>
        <ul className="flex list-disc flex-col gap-1 pl-4">
          {status.conflicts.map((c) => (
            <li key={c.kind + c.prefix + c.message}>{ts(c.message)}</li>
          ))}
        </ul>
      </AlertDescription>
    </Alert>
  )
}

function RoutersSection({ status, onEdit }: { status: RoutesStatus; onEdit: (device: string) => void }) {
  const { t } = useI18n()
  const readOnly = useReadOnly()
  const routers = status.devices.filter((d) => d.routes.length > 0)
  return (
    <DetailSection
      // i18n-ignore: bağlantı kimliği, görünmez
      id="alt-aglar"
      title={t("Onaylı alt ağlar")}
      signed
      description={t("Yönlendirici Linux olmalıdır (iletim ve maskeleme). Windows yönlendirici olamaz; Windows istemciler rotaları kullanabilir.")}
      framed={false}
    >
      {routers.length === 0 ? (
        <EmptyNote>{t("Henüz alt ağ yok. Bir cihaza rota ekle veya yönlendiricinin ilanını aşağıda onayla.")}</EmptyNote>
      ) : (
        <ListTable label={t("Onaylı alt ağlar")}>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className={headCell}>{t("Yönlendirici")}</TableHead>
              <TableHead className={headCell}>{t("Alt ağlar")}</TableHead>
              <TableHead className={cn(headCell, "hidden md:table-cell")}>{t("Erişebilen cihazlar")}</TableHead>
              <TableHead className="w-12">
                <span className="sr-only">{t("İşlemler")}</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {routers.map((d) => (
              <TableRow key={d.name}>
                <TableCell>
                  <span className="flex flex-col gap-0.5">
                    <span className="font-medium">{d.name}</span>
                    <span className="font-mono text-xs text-muted-foreground">{d.ipv4}</span>
                  </span>
                </TableCell>
                <TableCell className="whitespace-normal">
                  <span className="flex flex-col gap-1">
                    {d.routes.map((r) => (
                      <span key={r} className="font-mono text-sm">
                        {r}
                      </span>
                    ))}
                    <span className="text-xs text-pretty text-muted-foreground md:hidden">{clientsText(d.clients)}</span>
                  </span>
                </TableCell>
                <TableCell className="hidden text-sm whitespace-normal text-muted-foreground md:table-cell">{clientsText(d.clients)}</TableCell>
                <TableCell className="text-right">
                  {readOnly ? null : (
                    <RowMenu label={t("{name} rotaları için işlemler", { name: d.name })}>
                      <DropdownMenuItem onClick={() => onEdit(d.name)}>{t("Rotaları düzenle…")}</DropdownMenuItem>
                    </RowMenu>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </ListTable>
      )}
    </DetailSection>
  )
}

function clientsText(clients: string[]): string {
  return clients.length > 0 ? clients.join(", ") : tx("Henüz hiçbir kural erişim vermiyor")
}

function RouteEditDialog({
  status,
  device,
  onClose,
  onDone,
}: {
  status: RoutesStatus
  device: string | null
  onClose: () => void
  onDone: () => void
}) {
  const { t } = useI18n()
  const open = device !== null
  const current = status.devices.find((d) => d.name === device)
  const [name, setName] = useState("")
  const [text, setText] = useState("")
  const [payload, setPayload] = useState<Record<string, unknown> | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [lastDevice, setLastDevice] = useState<string | null>(null)
  if (device !== lastDevice) {
    setLastDevice(device)
    setName(device ?? "")
    setText(current ? current.routes.join(", ") : "")
    setPayload(null)
    setError(null)
  }

  function review() {
    const routes = parseRouteList(text)
    if (!name) {
      setError(msg("Bir cihaz seçin."))
      return
    }
    if (routes === null) {
      setError(msg("Rotalar virgülle ayrılmış CIDR olmalı (ör. 192.168.1.0/24). En fazla 32."))
      return
    }
    setError(null)
    setPayload({ device: name, routes })
  }

  return (
    <Dialog open={open} onOpenChange={(o) => (o ? null : onClose())}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("Alt ağ rotaları")}</DialogTitle>
          <DialogDescription>
            {t("Boş liste cihazın bütün rotalarını kaldırır. Bir kuralın kullandığı rota kaldırılamaz; önce kuralı silin.")}
          </DialogDescription>
        </DialogHeader>
        {payload ? (
          <SignChange
            endpoint="/api/routes/set"
            payload={payload}
            confirmLabel={t("İmzala ve uygula")}
            onBack={() => setPayload(null)}
            onDone={() => {
              onDone()
              onClose()
            }}
          />
        ) : (
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="route-device">{t("Yönlendirici cihaz")}</FieldLabel>
              <select
                id="route-device"
                className="h-9 rounded-md border border-input bg-background px-3 text-sm"
                value={name}
                disabled={device !== ""}
                onChange={(e) => setName(e.target.value)}
              >
                <option value="">{t("Seçin")}</option>
                {status.devices.map((d) => (
                  <option key={d.name} value={d.name}>
                    {d.name} ({d.ipv4})
                  </option>
                ))}
              </select>
            </Field>
            <Field data-invalid={error ? true : undefined}>
              <FieldLabel htmlFor="route-list">{t("Alt ağlar")}</FieldLabel>
              <Input
                id="route-list"
                className="font-mono"
                placeholder="192.168.1.0/24, fd12:3456::/48"
                value={text}
                onChange={(e) => setText(e.target.value)}
              />
              <FieldDescription>{t("Yalnızca özel aralıklar: 10/8, 172.16/12, 192.168/16, 100.64/10 ve fc00::/7.")}</FieldDescription>
              {error ? <FieldError>{error}</FieldError> : null}
            </Field>
            <Button onClick={review}>{t("Değişikliği gözden geçir")}</Button>
          </FieldGroup>
        )}
      </DialogContent>
    </Dialog>
  )
}

function ApproveSection({ onChanged }: { onChanged: () => void }) {
  const { t } = useI18n()
  const [text, setText] = useState("")
  const [busy, setBusy] = useState(false)
  const [inspected, setInspected] = useState<RouteInspect | null>(null)
  const [chosen, setChosen] = useState<string[]>([])
  const [signing, setSigning] = useState(false)
  const { mutate } = useSWRConfig()

  async function inspect() {
    setBusy(true)
    try {
      const res = await post<RouteInspect>("/api/routes/inspect", { advertisement: text.trim() })
      setInspected(res)
      setChosen(res.routes)
    } catch (err) {
      setInspected(null)
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  function toggle(route: string) {
    setChosen((c) => (c.includes(route) ? c.filter((r) => r !== route) : [...c, route]))
  }

  return (
    <DetailSection
      // i18n-ignore: bağlantı kimliği, görünmez
      id="ilanlar"
      title={t("Rota ilanı onayı")}
      signed
      description={withNode(
        t("Yönlendirici cihazda {command} çalıştır ve çıkan satırı buraya yapıştır. İlan cihazın kendi anahtarıyla imzalıdır; onay senin imzanla belgeye girer."),
        "command",
        <code className="font-mono text-[0.8125rem]">openscale route advertise --routes 192.168.1.0/24</code>
      )}
      framed={false}
    >
      <div className="flex flex-col gap-4 border-y py-5">
        <Writable>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="route-advert">{t("Rota ilanı")}</FieldLabel>
              <Textarea
                id="route-advert"
                className="min-h-20 font-mono text-xs"
                placeholder="osroute1...."
                value={text}
                onChange={(e) => {
                  setText(e.target.value)
                  setInspected(null)
                }}
              />
            </Field>
            <Button variant="outline" className="self-start" disabled={busy || text.trim().length === 0} onClick={inspect}>
              {busy ? <Spinner data-icon="inline-start" /> : <ShieldCheck data-icon="inline-start" />}
              {t("İlanı doğrula")}
            </Button>
          </FieldGroup>
        </Writable>
        {inspected ? (
          <div className="flex flex-col gap-3">
            <p className="text-sm text-pretty">
              {withNodes(t("{device} şu alt ağları istiyor ({date}):"), {
                device: <span className="font-medium">{inspected.device}</span>,
                date: formatDateTime(inspected.issuedAt),
              })}
            </p>
            <ListTable label={t("İlan edilen alt ağlar")}>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-10">
                    <span className="sr-only">{t("Seç")}</span>
                  </TableHead>
                  <TableHead className={headCell}>{t("Alt ağ")}</TableHead>
                  <TableHead className={headCell}>{t("Durum")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {inspected.routes.map((r) => (
                  <TableRow key={r}>
                    <TableCell>
                      <Checkbox id={`adv-${r}`} checked={chosen.includes(r)} onCheckedChange={() => toggle(r)} />
                    </TableCell>
                    <TableCell>
                      <label htmlFor={`adv-${r}`} className="font-mono text-sm">
                        {r}
                      </label>
                    </TableCell>
                    <TableCell>
                      {inspected.current.includes(r) ? <SettingBadge>{t("Zaten onaylı")}</SettingBadge> : <SettingBadge tone="warning">{t("Yeni")}</SettingBadge>}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </ListTable>
            <Button className="self-start" disabled={chosen.length === 0} onClick={() => setSigning(true)}>
              {t("Seçilenleri onayla")}
            </Button>
          </div>
        ) : null}
      </div>
      <Dialog open={signing} onOpenChange={setSigning}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("Rotaları onayla")}</DialogTitle>
            <DialogDescription>{t("Onaylanan rotalar kök anahtarla imzalanan yeni belge sürümüne girer.")}</DialogDescription>
          </DialogHeader>
          {signing && inspected ? (
            <SignChange
              endpoint="/api/routes/approve"
              payload={{ advertisement: text.trim(), only: chosen }}
              confirmLabel={t("İmzala ve onayla")}
              onBack={() => setSigning(false)}
              onDone={async () => {
                setSigning(false)
                setInspected(null)
                setText("")
                await mutate("/api/routes")
                onChanged()
              }}
            />
          ) : null}
        </DialogContent>
      </Dialog>
    </DetailSection>
  )
}

function ExternalExitsSection({ status }: { status: RoutesStatus }) {
  const { t } = useI18n()
  return (
    <DetailSection
      // i18n-ignore: bağlantı kimliği, görünmez
      id="duz-wireguard"
      title={t("Düz WireGuard çıkış düğümleri")}
      description={withNodes(
        t("Kendi WireGuard sunucun, DNS çözücüsüyle birlikte çıkış düğümü olarak kullanılabilir. Tanımlamak için {set}, sunucu ayarı için {config}."),
        {
          set: <code className="font-mono text-[0.8125rem]">openscale exit-node external set</code>,
          config: <code className="font-mono text-[0.8125rem]">openscale exit-node external config</code>,
        }
      )}
      framed={false}
    >
      {status.externalExits.length === 0 ? (
        <EmptyNote>{t("Tanımlı düz WireGuard çıkış düğümü yok.")}</EmptyNote>
      ) : (
        <ListTable label={t("Düz WireGuard çıkış düğümleri")}>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className={headCell}>{t("Ad")}</TableHead>
              <TableHead className={headCell}>{t("Uç nokta")}</TableHead>
              <TableHead className={cn(headCell, "hidden sm:table-cell")}>DNS</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {status.externalExits.map((x) => (
              <TableRow key={x.name}>
                <TableCell className="whitespace-normal">
                  <span className="flex flex-col gap-0.5">
                    <span className="font-medium">{x.name}</span>
                    {x.description ? <span className="text-sm text-pretty text-muted-foreground">{x.description}</span> : null}
                  </span>
                </TableCell>
                <TableCell>
                  <span className="flex flex-col gap-0.5">
                    <span className="font-mono text-sm">{x.endpoint}</span>
                    <span className="font-mono text-xs text-muted-foreground sm:hidden">DNS {x.dns}</span>
                  </span>
                </TableCell>
                <TableCell className="hidden font-mono text-sm sm:table-cell">{x.dns}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </ListTable>
      )}
    </DetailSection>
  )
}

function AddressingSection({ status }: { status: RoutesStatus }) {
  const { t } = useI18n()
  return (
    <SettingsSection
      // i18n-ignore: bağlantı kimliği, görünmez
      id="adres-atama"
      title={t("Adres atama")}
      description={withNode(
        t("Yeni cihazlara adres verme yöntemi ve otomatik verilmeyen ayrılmış aralıklar. Değiştirmek için {command}."),
        "command",
        <code className="font-mono text-[0.8125rem]">openscale address strategy</code>
      )}
    >
      <SettingRow
        title={t("Yöntem")}
        description={t("Yeni cihaza hangi boş adresin verileceği.")}
        action={<SettingBadge>{t(strategyLabels[status.strategy])}</SettingBadge>}
      />
      <SettingRow
        title={t("Ayrılmış aralıklar")}
        description={t("Bu aralıklardan otomatik adres verilmez.")}
        action={
          status.reserved.length === 0 ? (
            <span className="text-sm text-muted-foreground">{t("none|Yok")}</span>
          ) : (
            <span className="flex flex-col items-start gap-0.5 font-mono text-sm sm:items-end">
              {status.reserved.map((r) => (
                <span key={r}>{r}</span>
              ))}
            </span>
          )
        }
      />
    </SettingsSection>
  )
}
