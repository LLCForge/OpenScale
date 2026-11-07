"use client"

import Link from "next/link"
import { useEffect, useState } from "react"
import useSWR from "swr"
import { Gauge } from "lucide-react"
import { toast } from "sonner"

import { useReadOnly } from "@/components/app/read-only"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Field, FieldContent, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { errorMessage, fetcher, post } from "@/lib/api"
import { formatNumber } from "@/lib/format"
import { useI18n } from "@/lib/i18n/i18n"
import { formatBytes, type TrafficCost, type TrafficSettings, type TrafficStatus } from "@/lib/wave2"

const COVER_MIN = 256
const COVER_MAX = 64 * 1024
const PROTOCOLS = [
  { id: "pcp", label: "PCP" },
  { id: "natpmp", label: "NAT-PMP" },
  { id: "upnp", label: "UPnP" },
] as const

/** Router port mapping, padding, cover traffic, priority and Tor (ADR-0042, ADR-0043, ADR-0044). */
export function TrafficCard() {
  const { t } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<TrafficStatus>("/api/app/traffic", fetcher)
  if (isLoading) {
    return (
      <Card className="lg:col-span-3">
        <CardContent className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
          <Spinner /> {t("Trafik ayarları yükleniyor")}
        </CardContent>
      </Card>
    )
  }
  if (error || !data) return null
  return <TrafficForm key={JSON.stringify(data.settings)} status={data} onSaved={(s) => mutate(s, { revalidate: false })} />
}

function TrafficForm({ status, onSaved }: { status: TrafficStatus; onSaved: (s: TrafficStatus) => void }) {
  const { t, ts } = useI18n()
  const readOnly = useReadOnly()
  const [v, setV] = useState<TrafficSettings>(status.settings)
  const [cost, setCost] = useState<TrafficCost | null>(null)
  const [costSeen, setCostSeen] = useState(false)
  const [saving, setSaving] = useState(false)

  const coverValid = v.coverTraffic === 0 || (v.coverTraffic >= COVER_MIN && v.coverTraffic <= COVER_MAX)
  const raising =
    (v.padding !== "off" && v.padding !== status.settings.padding) ||
    (v.coverTraffic > 0 && v.coverTraffic !== status.settings.coverTraffic)

  // The cost of the chosen padding and cover rate, fetched from the
  // service so it matches what it will accept.
  useEffect(() => {
    if (!coverValid) return
    let cancelled = false
    const params = new URLSearchParams({ padding: v.padding, cover: String(v.coverTraffic) })
    fetcher<TrafficCost>(`/api/app/traffic/cost?${params.toString()}`)
      .then((c) => {
        if (!cancelled) {
          setCost(c)
          setCostSeen(false)
        }
      })
      .catch(() => {
        if (!cancelled) setCost(null)
      })
    return () => {
      cancelled = true
    }
  }, [v.padding, v.coverTraffic, coverValid])

  const dirty = JSON.stringify(v) !== JSON.stringify(status.settings)
  const canSave = dirty && coverValid && !readOnly && (!raising || (cost !== null && costSeen))

  async function save() {
    setSaving(true)
    try {
      const res = await post<TrafficStatus>("/api/app/traffic", {
        portMap: v.portMap,
        portMapDisable: v.portMapDisable,
        padding: v.padding,
        coverTraffic: v.coverTraffic,
        interactivePriority: v.interactivePriority,
        torSocks: v.torSocks.trim(),
        costAck: cost?.ack ?? "",
      })
      onSaved(res)
      toast.success(t("Trafik ayarları kaydedildi. Tünel kısa süreliğine yeniden başlatılıyor."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  function toggleProtocol(id: string, off: boolean) {
    setV((s) => ({ ...s, portMapDisable: off ? [...s.portMapDisable.filter((p) => p !== id), id] : s.portMapDisable.filter((p) => p !== id) }))
  }

  return (
    <Card className="lg:col-span-3">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Gauge className="size-4 text-muted-foreground" />
          {t("Trafik ve gizlilik")}
        </CardTitle>
        <CardDescription className="text-pretty">
          {t("Varsayılan kapalı. Dolgu ve sahte trafik veri ve pil harcar; maliyet onaylanmadan açılmaz.")}{" "}
          <Link href="/diag#tuketim" className="underline underline-offset-4 hover:text-foreground">
            {t("Tüketimi gör")}
          </Link>
        </CardDescription>
      </CardHeader>
      <CardContent>
        <FieldGroup>
          <Field orientation="horizontal">
            <FieldContent>
              <FieldLabel htmlFor="portmap">{t("Yönlendiricide port aç (UPnP/NAT-PMP/PCP)")}</FieldLabel>
              <FieldDescription>
                {t("Doğrudan bağlantı olasılığını artırır; yönlendiriciye bu cihaz için bir port yönlendirmesi eklenir.")}
                {status.portMap?.active
                  ? ` ${t("Etkin: {protocol} {external}.", { protocol: status.portMap.protocol ?? "", external: status.portMap.external ?? "" })}`
                  : ""}
                {status.portMap?.lastError ? ` ${t("Son hata: {error}", { error: ts(status.portMap.lastError) })}` : ""}
              </FieldDescription>
            </FieldContent>
            <Switch id="portmap" checked={v.portMap} disabled={readOnly} onCheckedChange={(c) => setV((s) => ({ ...s, portMap: c }))} />
          </Field>
          {v.portMap && (
            <div className="flex flex-wrap gap-4">
              {PROTOCOLS.map((p) => (
                <label key={p.id} className="flex items-center gap-2 text-sm">
                  <Checkbox
                    checked={!v.portMapDisable.includes(p.id)}
                    disabled={readOnly}
                    onCheckedChange={(c) => toggleProtocol(p.id, c !== true)}
                  />
                  {p.label}
                </label>
              ))}
            </div>
          )}
          <Field>
            <FieldLabel htmlFor="padding">{t("Paket dolgusu")}</FieldLabel>
            <select
              id="padding"
              className="h-9 rounded-md border border-input bg-background px-3 text-sm"
              value={v.padding}
              disabled={readOnly}
              onChange={(e) => setV((s) => ({ ...s, padding: e.target.value }))}
            >
              <option value="off">{t("Kapalı")}</option>
              <option value="buckets">{t("Kovalar (128/256/512/1024 bayt)")}</option>
              <option value="mtu">{t("Her paket MTU boyunda")}</option>
            </select>
            <FieldDescription>{t("Paket boylarından ne yapıldığının anlaşılmasını zorlaştırır.")}</FieldDescription>
          </Field>
          <Field>
            <FieldLabel htmlFor="cover">{t("Sahte trafik (B/sn, 0: kapalı)")}</FieldLabel>
            <Input
              id="cover"
              type="number"
              inputMode="numeric"
              min={0}
              max={COVER_MAX}
              value={v.coverTraffic}
              disabled={readOnly}
              onChange={(e) => setV((s) => ({ ...s, coverTraffic: Number(e.target.value) || 0 }))}
              aria-invalid={!coverValid}
            />
            <FieldDescription>
              {coverValid
                ? t("Koordinatöre rastgele aralıklarla anlamsız paketler gönderir.")
                : t("0 veya {min}-{max} arası olmalı.", { min: COVER_MIN, max: COVER_MAX })}
            </FieldDescription>
          </Field>
          {raising && cost && (
            <Alert>
              <AlertDescription className="flex flex-col gap-2">
                <span className="font-medium text-foreground">{t("Tahmini maliyet (MTU {mtu})", { mtu: cost.mtu })}</span>
                {v.padding !== "off" && (
                  <span>{t("Dolgu: tipik trafikte yaklaşık %{percent} ek bant genişliği.", { percent: formatNumber(cost.paddingPercent, 0) })}</span>
                )}
                {v.coverTraffic > 0 && (
                  <span>
                    {t("Sahte trafik: saatte {packets} paket (telefonda radyo uyanması), günde {perDay}, 30 günde {per30Days} veri.", {
                      packets: formatNumber(cost.packetsPerHour),
                      perDay: formatBytes(cost.bytesPerDay),
                      per30Days: formatBytes(cost.bytesPer30Days),
                    })}
                  </span>
                )}
                <label className="flex items-center gap-2 text-sm">
                  <Checkbox checked={costSeen} onCheckedChange={(c) => setCostSeen(c === true)} />
                  {t("Maliyeti gördüm, açmak istiyorum")}
                </label>
              </AlertDescription>
            </Alert>
          )}
          <Field orientation="horizontal">
            <FieldContent>
              <FieldLabel htmlFor="prio">{t("Etkileşimli trafiğe öncelik")}</FieldLabel>
              <FieldDescription>{t("SSH, uzak masaüstü, DNS ve ping paketleri büyük aktarımların önüne geçer.")}</FieldDescription>
            </FieldContent>
            <Switch id="prio" checked={v.interactivePriority} disabled={readOnly} onCheckedChange={(c) => setV((s) => ({ ...s, interactivePriority: c }))} />
          </Field>
          <Field>
            <FieldLabel htmlFor="tor">{t("Koordinatöre Tor üzerinden bağlan")}</FieldLabel>
            <Input
              id="tor"
              placeholder="127.0.0.1:9050"
              value={v.torSocks}
              maxLength={64}
              disabled={readOnly}
              onChange={(e) => setV((s) => ({ ...s, torSocks: e.target.value }))}
            />
            <FieldDescription>
              {t(
                "Bu bilgisayarda çalışan Tor istemcisinin SOCKS adresi. Açıkken bütün eşlere aktarıcıdan ulaşılır, bağlantı yavaşlar; Tor kurulu değilse tünel koordinatöre ulaşamaz."
              )}
              {status.torActive ? ` ${t("Şu anda Tor kullanılıyor.")}` : ""}
            </FieldDescription>
          </Field>
          {status.shaping && (status.shaping.coverPackets > 0 || status.shaping.paddedPackets > 0) && (
            <p className="text-sm text-muted-foreground">
              {t("Bu oturumda: {padded} paket dolduruldu ({paddedBytes}), {cover} sahte paket ({coverBytes}).", {
                padded: formatNumber(status.shaping.paddedPackets),
                paddedBytes: formatBytes(status.shaping.paddingBytes),
                cover: formatNumber(status.shaping.coverPackets),
                coverBytes: formatBytes(status.shaping.coverBytes),
              })}
            </p>
          )}
        </FieldGroup>
      </CardContent>
      <CardFooter className="justify-end">
        <Button type="button" onClick={save} disabled={!canSave || saving}>
          {saving && <Spinner />}
          {t("Kaydet")}
        </Button>
      </CardFooter>
    </Card>
  )
}
