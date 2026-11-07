"use client"

import { Terminal } from "lucide-react"

import { CodeLine } from "@/components/copy-field"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { tx, useI18n } from "@/lib/i18n/i18n"

interface Step {
  title: string
  command?: string
  note?: string
}

/** Called during render of InstallCommands (it calls useI18n), so tx() follows the language. */
function stepsFor(os: "windows" | "linux", rootFingerprint: string): Step[] {
  const stateDir = os === "windows" ? "" : " --state-dir /var/lib/openscale"
  const elevated = os === "windows" ? tx("Yönetici olarak açılmış PowerShell'de:") : tx("root olarak (sudo ile):")
  return [
    {
      title: tx("OpenScale'i yükle"),
      note:
        os === "windows"
          ? tx("openscale.exe dosyasını bu bilgisayara kopyala ve PATH'e ekle (ör. C:\\Program Files\\OpenScale).")
          : tx("openscale ikilisini /usr/local/bin/openscale konumuna kopyala ve çalıştırılabilir yap."),
    },
    { title: tx("Cihaz anahtarlarını üret"), command: `openscale keygen${stateDir}` },
    {
      title: tx("Kayıt isteğini panele ekle"),
      note: tx("Çıkan osreq1... satırını Cihazlar > Cihaz ekle'ye yapıştır ve ekrandaki parmak izini panelde yaz."),
    },
    { title: tx("Ağa katıl"), command: `openscale join${stateDir} --bundle @openscale-bundle.txt --root-fingerprint ${rootFingerprint}` },
    { title: tx("Tüneli aç ({elevated})", { elevated }), command: `openscale up${stateDir}` },
  ]
}

/** OS-specific join instructions, like an installer page. */
export function InstallCommands({ rootFingerprint }: { rootFingerprint: string }) {
  const { t } = useI18n()
  return (
    <Tabs defaultValue="windows" className="flex flex-col gap-4">
      <TabsList>
        <TabsTrigger value="windows">Windows</TabsTrigger>
        <TabsTrigger value="linux">Linux</TabsTrigger>
        <TabsTrigger value="mobile" disabled>
          {t("Android / iOS (yakında)")}
        </TabsTrigger>
      </TabsList>
      {(["windows", "linux"] as const).map((os) => (
        <TabsContent key={os} value={os}>
          <div className="mb-3 flex items-center gap-2 text-sm font-medium">
            <Terminal className="size-4" />
            {t("Komut satırıyla kurulum")}
          </div>
          <ol className="flex flex-col">
            {stepsFor(os, rootFingerprint).map((step, i, all) => (
              <li key={step.title} className="relative flex gap-4 pb-5 last:pb-0">
                {i < all.length - 1 ? <span aria-hidden="true" className="absolute top-8 left-3.5 h-[calc(100%-2rem)] w-px bg-border" /> : null}
                <span className="flex size-7 shrink-0 items-center justify-center rounded-full border bg-card text-xs text-muted-foreground">
                  {i + 1}
                </span>
                <div className="flex min-w-0 flex-1 flex-col gap-2 pt-0.5">
                  <span className="text-sm">{step.title}</span>
                  {step.command ? <CodeLine value={step.command} nowrap /> : null}
                  {step.note ? <p className="text-sm leading-relaxed text-muted-foreground">{step.note}</p> : null}
                </div>
              </li>
            ))}
          </ol>
        </TabsContent>
      ))}
    </Tabs>
  )
}
