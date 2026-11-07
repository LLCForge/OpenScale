"use client"

import { useState } from "react"
import useSWR from "swr"
import { RotateCcw } from "lucide-react"
import { toast } from "sonner"

import { PostQuantumBadge } from "@/components/app/post-quantum-badge"
import { useReadOnly, Writable } from "@/components/app/read-only"
import { useAppStatus } from "@/components/app/use-app-status"
import { DetailSection } from "@/components/devices/detail-card"
import { DiagSectionState } from "@/components/diag/diag-errors"
import { headCell, ListTable, RowMenu } from "@/components/settings/list-table"
import { EmptyNote, SettingBadge } from "@/components/settings/settings-layout"
import { Button } from "@/components/ui/button"
import { DropdownMenuItem } from "@/components/ui/dropdown-menu"
import { Spinner } from "@/components/ui/spinner"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { errorMessage, fetcher, post } from "@/lib/api"
import { isZeroTime, nsToMs, type PathsReply, type PeerPath, type PingResult, type RelayReply } from "@/lib/diag"
import { formatAgo } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

const methodLabels: Record<string, string> = {
  icmp: "ICMP",
  relay: msg("aktarıcı yoklaması"),
  probe: msg("son yol yoklaması"),
}

const relayReasonLabels: Record<string, string> = {
  forced: msg("Aktarıcı zorunlu"),
  udp_blocked: msg("UDP engelli"),
  no_candidates: msg("Adres bilinmiyor"),
  direct_timeout: msg("Doğrudan deneme yanıtsız"),
}

/** Why a relayed peer goes through the relay and what could fix it (#394). */
function RelayReason({ peer }: { peer: PeerPath }) {
  const { t, ts } = useI18n()
  if (!peer.relayed || !peer.relay_reason) return null
  const known = relayReasonLabels[peer.relay_reason]
  const label = known ? t(known) : peer.relay_reason
  return (
    <span className="flex max-w-xs flex-col gap-0.5 whitespace-normal text-sm text-muted-foreground">
      <span className="font-medium text-foreground">{t("Neden: {reason}", { reason: label })}</span>
      {peer.relay_hint ? <span className="text-pretty">{ts(peer.relay_hint)}</span> : null}
    </span>
  )
}

function PathBadge({ peer }: { peer: PeerPath }) {
  const { t } = useI18n()
  if (peer.relayed) return <SettingBadge tone="warning">{t("Aktarıcı")}</SettingBadge>
  if (peer.endpoint) return <SettingBadge tone="success">{t("Doğrudan")}</SettingBadge>
  return <SettingBadge>{t("none|Yok")}</SettingBadge>
}

/**
 * The "Bağlantı" section of the diagnostics page: how every peer is reached
 * (F-016) with ping (F-014) and relay test in each row's menu, and the
 * reconnect action (path reset) at the right of the title. The actions
 * disappear while the panel is read-only; the server refuses them anyway.
 */
export function PathsCard() {
  const { status } = useAppStatus()
  const readOnly = useReadOnly()
  const { t, ts } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<PathsReply>("/api/app/diag/paths", fetcher, { refreshInterval: 10_000 })
  const [busy, setBusy] = useState<string | null>(null)
  const [results, setResults] = useState<Record<string, string>>({})

  async function reconnect() {
    setBusy("reconnect")
    try {
      await post("/api/app/diag/reconnect", {})
      toast.success(t("Yollar sıfırlandı; eşler yeniden yoklanıyor."))
      await mutate()
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  async function ping(name: string) {
    setBusy(`ping-${name}`)
    try {
      const res = await post<PingResult>("/api/app/diag/ping", { peer: name })
      const path = res.path === "direct" ? t("doğrudan") : res.path === "relay" ? t("aktarıcı") : t("yol yok")
      const method = methodLabels[res.method ?? ""]
      const text =
        res.rtt_ms !== undefined
          ? `Ping ${res.rtt_ms.toFixed(1)} ms · ${path} · ${method ? t(method) : res.method}`
          : `Ping: ${res.error ? ts(res.error) : t("yanıt yok")} · ${path}`
      setResults((r) => ({ ...r, [name]: text }))
      await mutate()
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  async function relayTest(name: string) {
    setBusy(`relay-${name}`)
    try {
      const res = await post<RelayReply>("/api/app/diag/relay-test", { peer: name })
      setResults((r) => ({ ...r, [name]: t("Aktarıcı üzerinden {ms} ms", { ms: res.rtt_ms.toFixed(1) }) }))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  const peers = data?.peers ?? []
  return (
    <DetailSection
      id="baglanti"
      title={t("Bağlantı")}
      description={t("Her cihaza doğrudan mı yoksa koordinatörün aktarıcısı üzerinden mi ulaşıldığı, şifrelemenin kuantum sonrası mı klasik mi olduğu, son el sıkışma ve yoklama gecikmesi.")}
      framed={false}
      action={
        <Writable>
          <Button variant="outline" onClick={reconnect} disabled={busy !== null || !status?.device?.running}>
            {busy === "reconnect" ? <Spinner data-icon="inline-start" /> : <RotateCcw data-icon="inline-start" />}
            {t("Yeniden bağlan")}
          </Button>
        </Writable>
      }
    >
      <DiagSectionState section={t("Bağlantı")} error={error} isLoading={isLoading}>
        {peers.length === 0 ? (
          <EmptyNote>{t("Tünel kurulu eş yok. Kurallar bu cihazı başka bir cihazla eşleştirdiğinde burada görünür.")}</EmptyNote>
        ) : (
          <ListTable label={t("Eş yolları")}>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className={headCell}>{t("Cihaz")}</TableHead>
                <TableHead className={headCell}>{t("Yol")}</TableHead>
                <TableHead className={cn(headCell, "hidden md:table-cell")}>{t("Uç nokta")}</TableHead>
                <TableHead className={cn(headCell, "hidden sm:table-cell")}>{t("Son el sıkışma")}</TableHead>
                <TableHead className={cn(headCell, "hidden lg:table-cell")}>{t("Yoklama")}</TableHead>
                <TableHead className="w-12">
                  <span className="sr-only">{t("İşlemler")}</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {peers.map((p) => (
                <TableRow key={p.id}>
                  <TableCell>
                    <span className="flex flex-col gap-0.5">
                      <span className="font-medium">{p.name}</span>
                      <span className="text-sm text-muted-foreground sm:hidden">
                        {isZeroTime(p.last_handshake) ? t("El sıkışma yok") : t("El sıkışma {ago}", { ago: formatAgo(p.last_handshake) })}
                      </span>
                      {busy === `ping-${p.name}` || busy === `relay-${p.name}` ? (
                        <span className="flex items-center gap-1.5 text-sm text-muted-foreground">
                          <Spinner className="size-3" />
                          {t("Ölçülüyor")}
                        </span>
                      ) : results[p.name] ? (
                        <span className="text-sm text-muted-foreground" aria-live="polite">
                          {results[p.name]}
                        </span>
                      ) : null}
                      <RelayReason peer={p} />
                    </span>
                  </TableCell>
                  <TableCell>
                    <span className="flex flex-wrap items-center gap-1">
                      <PathBadge peer={p} />
                      <PostQuantumBadge state={p.post_quantum} />
                    </span>
                  </TableCell>
                  <TableCell className="hidden font-mono text-[0.8125rem] md:table-cell">{p.relayed ? "-" : p.endpoint || "-"}</TableCell>
                  <TableCell className="hidden text-sm sm:table-cell">{isZeroTime(p.last_handshake) ? t("hiç") : formatAgo(p.last_handshake)}</TableCell>
                  <TableCell className="hidden text-sm lg:table-cell">{nsToMs(p.probe_rtt)}</TableCell>
                  <TableCell className="text-right">
                    {readOnly ? null : (
                      <RowMenu label={t("{name} için tanı işlemleri", { name: p.name })} className="w-44">
                        <DropdownMenuItem disabled={busy !== null} onClick={() => ping(p.name)}>
                          Ping
                        </DropdownMenuItem>
                        <DropdownMenuItem disabled={busy !== null} onClick={() => relayTest(p.name)}>
                          {t("Aktarıcı testi")}
                        </DropdownMenuItem>
                      </RowMenu>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </ListTable>
        )}
      </DiagSectionState>
    </DetailSection>
  )
}
