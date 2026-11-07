"use client"

import { Fragment, useState } from "react"
import { X } from "lucide-react"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { errorMessage, post } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"
import type { JoiningStatus } from "@/lib/types"

/** Fills the {name} slots of a translated sentence with elements. */
function fill(text: string, parts: Record<string, React.ReactNode>): React.ReactNode[] {
  return text.split(/(\{\w+\})/).map((piece, i) => {
    const m = /^\{(\w+)\}$/.exec(piece)
    return m && m[1] in parts ? <Fragment key={i}>{parts[m[1]]}</Fragment> : piece
  })
}

/** Shows the 4-digit code the owner must see next to the pending request. */
export function JoiningCard({ joining, onCancelled }: { joining: JoiningStatus; onCancelled: () => void }) {
  const { t } = useI18n()
  const [cancelling, setCancelling] = useState(false)

  async function cancel() {
    setCancelling(true)
    try {
      await post("/api/app/join/cancel", {})
      onCancelled()
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setCancelling(false)
    }
  }

  return (
    <section
      aria-labelledby="joining-title"
      aria-live="polite"
      className="flex w-full max-w-md flex-col items-center gap-6 rounded-2xl border bg-card p-8 text-center shadow-xl shadow-black/20 sm:p-10"
    >
      {joining.shortCode ? (
        <>
          <div className="flex flex-col gap-2">
            <h1 id="joining-title" className="text-xl font-semibold tracking-tight">
              {t("Yönetici onayı bekleniyor")}
            </h1>
            <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
              {fill(t("Yönetici bilgisayarda OpenScale'i aç ve {page} sayfasındaki onay bekleyen {name} isteğinde bu kodu gör."), {
                page: <span className="font-medium text-foreground">{t("Cihazlar")}</span>,
                name: <span className="font-medium text-foreground">{joining.name}</span>,
              })}
            </p>
          </div>
          <div aria-label={t("Doğrulama kodu {code}", { code: joining.shortCode.split("").join(" ") })} className="flex gap-2">
            {joining.shortCode.split("").map((digit, i) => (
              <span
                key={`${i}-${digit}`}
                className="flex h-16 w-12 items-center justify-center rounded-xl border bg-muted font-mono text-3xl font-semibold"
              >
                {digit}
              </span>
            ))}
          </div>
          <p className="text-xs leading-relaxed text-muted-foreground text-pretty">
            {t("Kodlar aynıysa orada Onayla'ya bas. Farklıysa onaylama: istek başka bir cihazdan gelmiş demektir.")}
          </p>
        </>
      ) : (
        <div className="flex flex-col gap-2">
          <h1 id="joining-title" className="text-xl font-semibold tracking-tight">
            {t("Ağa bağlanılıyor")}
          </h1>
          <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
            {t(
              "Koordinatöre ulaşılıyor. Bu bir dakikadan uzun sürerse yönetici bilgisayarın açık olduğundan ve aynı ağda veya internetten erişilebilir olduğundan emin ol.",
            )}
          </p>
        </div>
      )}
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Spinner />
        {joining.shortCode ? t("Onay bekleniyor") : t("Bağlanılıyor")}
      </div>
      <Button variant="outline" onClick={cancel} disabled={cancelling}>
        <X data-icon="inline-start" />
        {t("Vazgeç")}
      </Button>
    </section>
  )
}
