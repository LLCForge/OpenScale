"use client"

import useSWR from "swr"

import { SettingRow } from "@/components/settings/settings-layout"
import { Spinner } from "@/components/ui/spinner"
import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"

/** The root key's short authentication string (ADR-0062) as a settings row. */
export function RootSASRow() {
  const { t } = useI18n()
  const { data } = useSWR<{ sas: string }>("/api/network/sas", fetcher)
  return (
    <SettingRow
      title={t("Ağın doğrulama kodu")}
      description={t("Katılan cihazın gösterdiği kök anahtar kodu bununla aynı olmalı; farklıysa başka bir ağa bağlanıyordur.")}
      action={data ? <span className="rounded-md border bg-muted/40 px-3 py-1 font-mono text-sm tracking-widest">{data.sas}</span> : <Spinner />}
    />
  )
}
