"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { RotateCcw, ShieldX } from "lucide-react"
import { toast } from "sonner"

import { Writable } from "@/components/app/read-only"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Spinner } from "@/components/ui/spinner"
import { errorMessage, post } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"

/** Shown when this computer was removed from the network. */
export function RemovedCard({ onReset }: { onReset: () => void }) {
  const { t } = useI18n()
  const router = useRouter()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)

  async function reset() {
    setBusy(true)
    try {
      await post("/api/app/reset", {})
      onReset()
      router.replace("/welcome")
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Alert variant="destructive">
        <ShieldX />
        <AlertTitle>{t("Bu bilgisayar ağdan çıkarılmış")}</AlertTitle>
        <AlertDescription className="flex flex-col gap-3">
          <span className="text-pretty">
            {t(
              "Yönetici bu bilgisayarın anahtarlarını iptal etmiş. Aynı anahtarlarla geri dönülemez. Bilgisayarı sıfırlayıp yeni anahtarla, yeni bir davet koduyla katılabilirsin.",
            )}
          </span>
          <Writable>
            <Button variant="outline" className="self-start" onClick={() => setOpen(true)}>
              <RotateCcw data-icon="inline-start" />
              {t("Sıfırla ve yeniden katıl")}
            </Button>
          </Writable>
        </AlertDescription>
      </Alert>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t("Bu bilgisayarı sıfırla")}</DialogTitle>
            <DialogDescription className="text-pretty">
              {t(
                "Eski cihaz anahtarı ve ağ kaydı bu bilgisayardan silinir. Sonra karşılama ekranından yeni bir davet koduyla katılırsın. Yönetici bilgisayarda yeni bir davet oluşturman gerekecek.",
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
              {t("Vazgeç")}
            </Button>
            <Button onClick={reset} disabled={busy}>
              {busy ? <Spinner data-icon="inline-start" /> : <RotateCcw data-icon="inline-start" />}
              {t("Sıfırla")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
