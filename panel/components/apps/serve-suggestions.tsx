"use client"

import useSWR from "swr"

import { CodeLine } from "@/components/copy-field"
import { DetailSection } from "@/components/devices/detail-card"
import { EmptyNote, SettingBadge } from "@/components/settings/settings-layout"
import { ApiError, fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { ServeSuggestion, ServeSuggestions } from "@/lib/p07-types"

// Container serve suggestions (#441): containers labelled openscale.serve
// on this computer's Docker or Podman, read with one read-only request.
// Publishing stays a deliberate step: the command below adds the service
// to serve.json, and the serve rule is still signed in the rule editor.

function publishCommand(s: ServeSuggestion): string | null {
  if (!s.target) return null
  const flag = s.type === "http" ? "--http" : "--tcp"
  return `openscale serve add ${s.name} ${flag} ${s.target}`
}

export function ServeSuggestionsSection() {
  const { t, ts } = useI18n()
  const { data, error } = useSWR<ServeSuggestions>("/api/app/serve/suggestions", fetcher, {
    revalidateOnFocus: false,
    shouldRetryOnError: (err: unknown) => !(err instanceof ApiError && err.status === 404),
  })
  if (error instanceof ApiError && error.status === 404) return null
  if (!data) return null
  // No container engine on this computer (Windows, or none installed): nothing to suggest.
  if (!data.available && !data.socket) return null

  const list = data.suggestions ?? []
  return (
    <DetailSection
      id="konteyner-onerileri"
      title={t("Konteynerlerden öneriler")}
      description={t("Yalnızca openscale.serve etiketli konteynerler listelenir. OpenScale konteynerlere dokunmaz; yalnızca listeyi okur.")}
      framed={false}
    >
      {!data.available ? (
        <EmptyNote>{data.error ? ts(data.error) : t("Docker veya Podman API soketine ulaşılamadı.")}</EmptyNote>
      ) : list.length === 0 ? (
        <EmptyNote>{t("openscale.serve etiketli konteyner yok.")}</EmptyNote>
      ) : (
        <ul className="flex flex-col divide-y rounded-lg border">
          {list.map((s) => {
            const cmd = publishCommand(s)
            return (
              <li key={`${s.container}-${s.name}`} className="flex flex-col gap-2 px-4 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium">{s.name}</span>
                  <SettingBadge>{s.type.toLocaleUpperCase("en")}</SettingBadge>
                  {s.published ? <SettingBadge tone="success">{t("Zaten yayında")}</SettingBadge> : null}
                </div>
                <span className="text-sm text-muted-foreground">
                  <span className="font-mono text-[0.8125rem]">{s.container}</span>
                  {s.image ? <> · {s.image}</> : null}
                  {s.target ? (
                    <>
                      {" "}
                      → <span className="font-mono text-[0.8125rem]">{s.target}</span>
                    </>
                  ) : null}
                </span>
                {s.problem ? (
                  <span className="text-sm text-muted-foreground text-pretty">{t("Yayınlanamaz: {problem}", { problem: ts(s.problem) })}</span>
                ) : !s.published && cmd ? (
                  <CodeLine value={cmd} label={t("Yayın komutunu kopyala")} />
                ) : null}
              </li>
            )
          })}
        </ul>
      )}
    </DetailSection>
  )
}
