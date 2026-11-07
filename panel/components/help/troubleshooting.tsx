"use client"

import { useDeferredValue, useId, useState } from "react"
import useSWR from "swr"
import { ChevronRight, Search } from "lucide-react"

import { CodeLine } from "@/components/copy-field"
import { EntryDetails } from "@/components/error-code"
import { QueryState } from "@/components/query-state"
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group"
import { fetcher } from "@/lib/api"
import { msg, useI18n } from "@/lib/i18n/i18n"
import { errorAreaLabels, type ErrorCatalog, type ErrorCodeEntry } from "@/lib/p12-types"

// Help > Sorun giderme (#550, #583, ADR-0165): the stable error codes with
// cause, steps and commands, a short symptom table that works without the
// network, and the command line tools that need no panel.

/** Symptom to first look, a short copy of docs/sorun-giderme.md. */
const symptoms: { symptom: string; look: string; codes: string }[] = [
  { symptom: msg("Hiçbir cihaza bağlanamıyorum, durum \"eşitleme hatası\""), look: "openscale netcheck", codes: "OS-3001, OS-1003" },
  { symptom: msg("Bağlanıyor ama yavaş, yol \"relay\" görünüyor"), look: "openscale paths", codes: "OS-3002" },
  { symptom: msg("Otelde veya şirkette hiç bağlanmıyor"), look: "openscale netcheck", codes: "OS-3004, OS-5003" },
  { symptom: msg("Küçük sayfalar açılıyor, büyük dosyalar takılıyor"), look: "openscale set mtu=1280", codes: "OS-3006" },
  { symptom: msg("nas.ag.internal gibi adlar çözülmüyor"), look: "openscale dns status", codes: "OS-4004, OS-4001" },
  { symptom: msg("Linux'ta DNS bir süre sonra eski hâline dönüyor"), look: "openscale dns status", codes: "OS-4001, OS-4002" },
  { symptom: msg("OpenScale kapalı ama internet yok"), look: "openscale killswitch status", codes: "OS-5006" },
  { symptom: msg("Otel giriş sayfası açılmıyor"), look: "openscale killswitch captive --sure 5m", codes: "OS-5003" },
  { symptom: msg("Windows bilgisayarımdaki paylaşıma diğer cihazlardan ulaşılmıyor"), look: "openscale denied", codes: "OS-5004" },
  { symptom: msg("\"Yetki yok\" veya \"erişim reddedildi\""), look: msg("Yönetici terminali veya sudo"), codes: "OS-6001" },
  { symptom: msg("\"Port kullanımda\""), look: "openscale configtest", codes: "OS-6002" },
  { symptom: msg("Komut \"çalışan bir tünel bulunamadı\" diyor"), look: "openscale service status", codes: "OS-7001" },
  { symptom: msg("Panel \"salt okunur\" diyor"), look: "openscale panel readonly status", codes: "OS-7002" },
]

const tools: { command: string; text: string }[] = [
  { command: "openscale explain OS-3001", text: msg("Bir hata kodunun açıklaması, internetsiz.") },
  { command: "openscale tui", text: msg("Panel olmadan, SSH oturumunda durum, eşler ve çıkış düğümü seçimi.") },
  { command: "openscale mqtt init --broker 192.168.1.10", text: msg("Durumu ve olayları kendi MQTT aracına (ör. Home Assistant) yayımlar.") },
  { command: "openscale status --format '{{.version}}'", text: msg("Komut çıktısını şablonla biçimlendirir (betikler için).") },
  { command: "openscale debug bundle-key", text: msg("Yardım edecek kişi bir anahtar üretir ve açık anahtarını sana verir.") },
  { command: "openscale debug bundle --to osbk1:…", text: msg("Teşhis paketini yalnızca o kişinin açabileceği biçimde şifreler.") },
]

export function Troubleshooting() {
  const { t } = useI18n()
  const searchId = useId()
  const [query, setQuery] = useState("")
  const q = useDeferredValue(query.trim().slice(0, 200))
  const key = q ? `/api/errors?q=${encodeURIComponent(q)}` : "/api/errors"
  const { data, error, isLoading, mutate } = useSWR<ErrorCatalog>(key, fetcher, { revalidateOnFocus: false, keepPreviousData: true })

  const byArea = (data?.codes ?? []).reduce<Map<string, ErrorCodeEntry[]>>((m, e) => {
    m.set(e.area, [...(m.get(e.area) ?? []), e])
    return m
  }, new Map())

  return (
    <div className="flex flex-col gap-10">
      <section aria-labelledby="belirti-baslik" className="flex flex-col gap-3">
        <div className="flex flex-col gap-1">
          <h2 id="belirti-baslik" className="text-base font-semibold">
            {t("Belirtiden koda")}
          </h2>
          <p className="text-sm text-muted-foreground text-pretty">
            {t("Ne gördüğünden başla; satırdaki komut ilk bakılacak yeri, kodlar aşağıdaki ayrıntıyı gösterir.")}
          </p>
        </div>
        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left text-xs font-medium tracking-wide text-muted-foreground uppercase">
                <th scope="col" className="px-4 py-2.5 font-medium">
                  {t("Belirti")}
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  {t("Önce bak")}
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  {t("Kodlar")}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {symptoms.map((s) => (
                <tr key={s.symptom}>
                  <td className="px-4 py-2.5 text-pretty">{t(s.symptom)}</td>
                  <td className={s.look.startsWith("openscale") ? "px-4 py-2.5 font-mono text-[0.8125rem]" : "px-4 py-2.5 text-pretty"}>
                    {s.look.startsWith("openscale") ? s.look : t(s.look)}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-[0.8125rem] whitespace-nowrap">{s.codes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="kodlar-baslik" className="flex flex-col gap-3">
        <div className="flex flex-col gap-1">
          <h2 id="kodlar-baslik" className="text-base font-semibold">
            {t("Hata kodları")}
          </h2>
          <p className="text-sm text-muted-foreground text-pretty">
            {t("Hata iletilerinin altındaki OS-NNNN kodu kalıcıdır; yardım isterken bu kodu söyle. Komut satırında")}{" "}
            <code className="font-mono text-[0.8125rem] text-foreground">openscale explain</code> {t("aynı açıklamayı verir.")}
          </p>
        </div>
        <label htmlFor={searchId} className="sr-only">
          {t("Hata kodlarında ara")}
        </label>
        <InputGroup className="sm:max-w-sm">
          <InputGroupAddon>
            <Search aria-hidden="true" />
          </InputGroupAddon>
          <InputGroupInput
            id={searchId}
            type="search"
            placeholder={t("Kod veya kelime, ör. 3001, dns")}
            value={query}
            maxLength={200}
            onChange={(e) => setQuery(e.target.value)}
          />
        </InputGroup>
        <QueryState error={error} isLoading={isLoading && !data} onRetry={() => mutate()}>
          {data && data.codes.length === 0 ? (
            <p className="rounded-lg border px-4 py-8 text-center text-sm text-muted-foreground">{t("Bu kelimeyle eşleşen hata kodu yok.")}</p>
          ) : (
            <div className="flex flex-col gap-6" aria-live="polite">
              {[...byArea.entries()].map(([area, list]) => (
                <div key={area} className="flex flex-col gap-2">
                  <h3 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">{t(errorAreaLabels[area] ?? area)}</h3>
                  <ul className="flex flex-col divide-y rounded-lg border">
                    {list.map((e) => (
                      <CodeRow key={e.code} entry={e} />
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          )}
        </QueryState>
      </section>

      <section aria-labelledby="araclar-baslik" className="flex flex-col gap-3">
        <div className="flex flex-col gap-1">
          <h2 id="araclar-baslik" className="text-base font-semibold">
            {t("Panelsiz araçlar")}
          </h2>
          <p className="text-sm text-muted-foreground text-pretty">
            {t("Panel açılamadığında veya bir sunucuda SSH ile çalışırken işe yarayan komutlar.")}
          </p>
        </div>
        <ul className="flex flex-col gap-4">
          {tools.map((tool) => (
            <li key={tool.command} className="flex flex-col gap-1.5">
              <span className="text-sm text-pretty">{t(tool.text)}</span>
              <CodeLine value={tool.command} label={t("Komutu kopyala")} />
            </li>
          ))}
        </ul>
        <p className="text-sm text-muted-foreground text-pretty">
          {t(
            "Şifreli teşhis paketinde anahtarın parmak izini yardım edecek kişiyle sesli karşılaştır; paket yalnızca onun özel anahtarıyla açılır.",
          )}
        </p>
      </section>
    </div>
  )
}

function CodeRow({ entry: e }: { entry: ErrorCodeEntry }) {
  const { t, ts } = useI18n()
  return (
    <li>
      <details className="group">
        <summary className="flex cursor-pointer list-none items-center gap-3 px-4 py-3 outline-none hover:bg-muted/40 focus-visible:ring-3 focus-visible:ring-ring/50 [&::-webkit-details-marker]:hidden">
          <ChevronRight className="size-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-90" aria-hidden="true" />
          <span className="w-20 shrink-0 font-mono text-[0.8125rem]">{e.code}</span>
          <span className="min-w-0 text-sm text-pretty">{ts(e.title)}</span>
          {e.deprecated ? <span className="ml-auto shrink-0 text-sm text-muted-foreground">{t("Artık oluşmuyor")}</span> : null}
        </summary>
        <div className="flex flex-col gap-4 px-4 pt-1 pb-4 sm:pl-11">
          <EntryDetails entry={e} />
        </div>
      </details>
    </li>
  )
}
