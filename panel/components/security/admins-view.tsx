"use client"

import { useState } from "react"
import useSWR from "swr"
import { UserX } from "lucide-react"

import { Writable } from "@/components/app/read-only"
import { CodeLine } from "@/components/copy-field"
import { PageHeader } from "@/components/page-header"
import { QueryState } from "@/components/query-state"
import { headCell, ListTable } from "@/components/settings/list-table"
import { EmptyNote, SettingBadge, SettingRow, SettingsColumn, SettingsSection, ValueBox } from "@/components/settings/settings-layout"
import { destructiveText, SignChangeDialog } from "@/components/sign-change"
import { Button } from "@/components/ui/button"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { fetcher } from "@/lib/api"
import { formatDate } from "@/lib/format"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import type { AdminList, GrantRecord, SensitiveState } from "@/lib/pa-types"
import { cn } from "@/lib/utils"

type GrantStatus = "valid" | "expired" | "revoked"

function statusOf(g: GrantRecord, list: AdminList): GrantStatus {
  if (list.revoked.includes(g.id)) return "revoked"
  if (list.expired.includes(g.id)) return "expired"
  return "valid"
}

const statusBadge: Record<GrantStatus, { label: string; tone?: "success" | "danger" }> = {
  valid: { label: msg("Geçerli"), tone: "success" },
  expired: { label: msg("Süresi doldu") },
  revoked: { label: msg("Geri alındı"), tone: "danger" },
}

function tokenText(token?: string): string {
  if (!token) return tx("Yok (yazılım anahtarı)")
  if (token.startsWith("piv:")) return `YubiKey PIV ${token.slice(4)}`
  if (token.startsWith("openpgp:")) return `YubiKey OpenPGP ${token.slice(8)}`
  return tx("Donanım anahtarı")
}

/**
 * Ayarlar > Yöneticiler (ADR-0172..0174, ADR-0176): delegated administrator
 * grants with their revocation, the sensitive device two-person rule and
 * the duress passphrase state. Granting stays in the CLI: it needs the
 * administrator's own public key from their computer.
 */
export function AdminsView() {
  const { t } = useI18n()
  const admins = useSWR<AdminList>("/api/g1/admins", fetcher)
  const [revoking, setRevoking] = useState<GrantRecord | null>(null)

  return (
    <SettingsColumn>
      <PageHeader
        title={t("Yöneticiler")}
        description={t("Kök anahtarın süreli ve kapsamlı yetki verdiği yöneticiler, hassas cihaz onayları ve baskı parolası.")}
      />

      <section aria-labelledby="yoneticiler-baslik" className="flex flex-col gap-2">
        <div className="flex flex-col gap-1">
          <h2 id="yoneticiler-baslik" className="text-base font-semibold">
            {t("Yetkili yöneticiler")}
          </h2>
          <p className="text-sm text-muted-foreground text-pretty">
            {t("Her yetki en çok 90 gün geçerlidir ve yalnızca listelenen işlemlere izin verir. Kök rotasyonu, onay politikası ve roller her zaman kökündür.")}
          </p>
        </div>
        <QueryState error={admins.error} isLoading={admins.isLoading} onRetry={() => admins.mutate()}>
          {admins.data ? (
            admins.data.grants.length === 0 ? (
              <EmptyNote>{t("Henüz yetkili yönetici yok; ağı yalnızca kök anahtar değiştirebilir.")}</EmptyNote>
            ) : (
              <ListTable label={t("Yetkili yöneticiler")}>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className={headCell}>{t("Ad")}</TableHead>
                    <TableHead className={cn(headCell, "hidden md:table-cell")}>{t("İşlemler")}</TableHead>
                    <TableHead className={cn(headCell, "hidden lg:table-cell")}>{t("Jeton")}</TableHead>
                    <TableHead className={headCell}>{t("Bitiş")}</TableHead>
                    <TableHead className={headCell}>{t("Durum")}</TableHead>
                    <TableHead className={cn(headCell, "w-0")}>
                      <span className="sr-only">{t("İşlem")}</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {admins.data.grants.map((g) => {
                    const st = statusOf(g, admins.data as AdminList)
                    return (
                      <TableRow key={g.id}>
                        <TableCell className="min-w-36 whitespace-normal">
                          <span className="flex flex-col gap-1">
                            <span className="text-sm font-medium">{g.name}</span>
                            {g.tags && g.tags.length > 0 ? (
                              <span className="flex flex-wrap gap-1">
                                {g.tags.map((tag) => (
                                  <span key={tag} className="rounded-full bg-secondary px-1.5 font-mono text-xs text-muted-foreground">
                                    {tag}
                                  </span>
                                ))}
                              </span>
                            ) : null}
                          </span>
                        </TableCell>
                        <TableCell className="hidden min-w-40 whitespace-normal md:table-cell">
                          <span className="font-mono text-xs text-muted-foreground">{(g.operations ?? []).join(", ") || "—"}</span>
                        </TableCell>
                        <TableCell className="hidden text-sm lg:table-cell">{tokenText(g.token)}</TableCell>
                        <TableCell className="text-sm whitespace-nowrap tabular-nums">{formatDate(g.not_after)}</TableCell>
                        <TableCell>
                          <SettingBadge tone={statusBadge[st].tone}>{t(statusBadge[st].label)}</SettingBadge>
                        </TableCell>
                        <TableCell className="text-right">
                          {st !== "revoked" ? (
                            <Writable>
                              <Button
                                size="sm"
                                variant="destructive"
                                className={destructiveText}
                                onClick={() => setRevoking(g)}
                                aria-label={t("{name} yetkisini geri al", { name: g.name })}
                              >
                                <UserX data-icon="inline-start" />
                                {t("revoke|Geri al")}
                              </Button>
                            </Writable>
                          ) : null}
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </ListTable>
            )
          ) : null}
        </QueryState>
        <p className="text-sm text-muted-foreground text-pretty">
          {t("Yeni yönetici için: yöneticinin bilgisayarında {keygen}, ardından kök cihazda {grant}.")
            .split(/\{(keygen|grant)\}/)
            .map((part, i) =>
              i % 2 === 1 ? (
                <code key={part} className="font-mono text-xs">
                  openscale admin {part}
                </code>
              ) : (
                part
              )
            )}
        </p>
      </section>

      <SensitiveSection />
      <DuressSection />

      {revoking ? (
        <SignChangeDialog
          open
          onOpenChange={(open) => {
            if (!open) setRevoking(null)
          }}
          title={t("{name} yetkisini geri al", { name: revoking.name })}
          description={t("Bu yönetici artık belge imzalayamaz. Bu sürümü görmeyen cihazlar yetkiyi süresi bitene kadar kabul edebilir.")}
          endpoint="/api/g1/admins/revoke"
          payload={{ id: revoking.id }}
          confirmLabel={t("Geri al ve imzala")}
          destructive
          onSigned={() => void admins.mutate()}
        />
      ) : null}
    </SettingsColumn>
  )
}

/** Sensitive devices: the two-person rule's state (ADR-0174). */
function SensitiveSection() {
  const { t } = useI18n()
  const { data, error, isLoading, mutate } = useSWR<{ sensitive: SensitiveState }>("/api/g1/sensitive", fetcher)
  const s = data?.sensitive
  const devices = s?.devices ?? []
  const approved = s?.approved ?? []
  return (
    <SettingsSection
      id="hassas"
      title={t("Hassas cihazlar")}
      description={t("Bu cihazlara erişimi değiştiren her sürüm, kökün yanında belirlenen onaycıların imzasını da ister.")}
    >
      <QueryState error={error} isLoading={isLoading} onRetry={() => mutate()}>
        {s ? (
          devices.length === 0 && s.needed === 0 ? (
            <EmptyNote framed={false}>{t("Çift onay kuralı tanımlı değil. Tanımlamak için: {command}", { command: "openscale admin sensitive add" })}</EmptyNote>
          ) : (
            <>
              {!s.complete ? (
                <div role="alert" className="mt-5 rounded-lg bg-destructive/10 px-3 py-2.5 text-sm text-destructive">
                  {t("Cihazlar onaylar eklenene kadar bu sürümü reddeder. Onay için:")} <code className="font-mono text-xs">openscale admin sensitive approve</code>
                </div>
              ) : null}
              <SettingRow title={t("Hassas cihazlar")} description={devices.length > 0 ? devices.join(", ") : "—"} />
              <SettingRow
                title={t("Onaylar")}
                description={approved.length > 0 ? approved.join(", ") : t("Henüz onay yok.")}
                action={
                  <SettingBadge tone={s.complete ? "success" : "danger"}>
                    {approved.length}/{s.needed}
                  </SettingBadge>
                }
              />
              <SettingRow
                title={t("Erişim özeti")}
                description={t("Onaycıların imzaladığı özet; kendi cihazlarındaki çıktıyla karşılaştırın.")}
                action={s.fingerprint ? <ValueBox value={s.fingerprint}>{`${s.fingerprint.slice(0, 16)}…`}</ValueBox> : null}
              />
            </>
          )
        ) : null}
      </QueryState>
    </SettingsSection>
  )
}

/** Duress passphrase: state only, deliberately small (ADR-0176). */
function DuressSection() {
  const { t } = useI18n()
  const { data } = useSWR<{ configured: boolean }>("/api/g1/duress", fetcher, { revalidateOnFocus: false })
  if (!data) return null
  return (
    <div className="flex flex-col gap-1 text-xs text-muted-foreground">
      <span>{t("Baskı parolası: {state}.", { state: data.configured ? t("ayarlı") : t("yok") })}</span>
      <CodeLine value="openscale admin duress set" className="max-w-sm" />
    </div>
  )
}
