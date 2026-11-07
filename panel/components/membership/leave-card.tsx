"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { LogOut } from "lucide-react"
import { toast } from "sonner"

import { Writable } from "@/components/app/read-only"
import { CodeLine } from "@/components/copy-field"
import { SettingRow } from "@/components/settings/settings-layout"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Spinner } from "@/components/ui/spinner"
import { errorMessage, post } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"

/** Lifts red button text toward the foreground on the dark theme's red fill (contrast 4.5:1). */
const destructiveText = "dark:text-[color-mix(in_oklch,var(--destructive),var(--foreground)_45%)]"

/**
 * Leaving the network from a member computer (F-106): the computer signs a
 * leave request, hands it to the coordinator and deletes its own key. The
 * owner then removes it with one signature.
 */
export function LeaveRow() {
  const { t } = useI18n()
  const router = useRouter()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [request, setRequest] = useState<string | null>(null)

  async function leave() {
    setBusy(true)
    try {
      const res = await post<{ request: string }>("/api/app/leave", {})
      setRequest(res.request)
      toast.success(t("Ayrılma isteği gönderildi; bu bilgisayarın anahtarı silindi."))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <SettingRow
      title={t("Ağdan ayrıl")}
      description={t(
        "Bu bilgisayar imzalı bir ayrılma isteği gönderir ve kendi anahtarını hemen siler; yönetici onaylayınca belgeden çıkar. Geri dönmek istersen yöneticiden yeni bir davet kodu alman gerekir.",
      )}
      action={
        <Writable>
          <Button variant="destructive" className={destructiveText} onClick={() => setOpen(true)}>
            <LogOut data-icon="inline-start" />
            {t("Ağdan ayrıl…")}
          </Button>
        </Writable>
      }
    >
      <Dialog
        open={open}
        onOpenChange={(v) => {
          setOpen(v)
          if (!v && request) {
            router.replace("/welcome")
          }
        }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{request ? t("Ağdan ayrıldın") : t("Ağdan ayrılmak istiyor musun?")}</DialogTitle>
            <DialogDescription className="text-pretty">
              {request
                ? t(
                    "İstek koordinatöre iletildi. Koordinatöre ulaşılamadıysa bu satırı yöneticiye ver; panelde veya 'openscale device leave-apply' ile uygular.",
                  )
                : t(
                    "Bu bilgisayarın cihaz anahtarı silinir ve aynı kimlikle geri dönülemez. Yeniden katılmak için yöneticiden yeni bir davet kodu iste; bu bilgisayar o davetle yeni bir cihaz olarak katılır.",
                  )}
            </DialogDescription>
          </DialogHeader>
          {request ? <CodeLine value={request} label={t("Ayrılma isteğini kopyala")} nowrap /> : null}
          <DialogFooter>
            {request ? (
              <Button onClick={() => router.replace("/welcome")}>{t("Tamam")}</Button>
            ) : (
              <>
                <Button variant="outline" onClick={() => setOpen(false)}>
                  {t("Vazgeç")}
                </Button>
                <Button variant="destructive" className={destructiveText} onClick={leave} disabled={busy}>
                  {busy ? <Spinner data-icon="inline-start" /> : <LogOut data-icon="inline-start" />}
                  {t("Ayrıl ve anahtarı sil")}
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </SettingRow>
  )
}
