"use client";

import { useState } from "react";
import { toast } from "sonner";

import { useReadOnly } from "@/components/app/read-only";
import { useAppStatus } from "@/components/app/use-app-status";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { errorMessage, post } from "@/lib/api";
import { useI18n } from "@/lib/i18n/i18n";
import type { AppStatus } from "@/lib/types";

/** Shields: refuse every connection other devices open to this computer. */
export function ShieldsRow() {
  const { t } = useI18n();
  const { status, mutate } = useAppStatus();
  const [busy, setBusy] = useState(false);
  const readOnly = useReadOnly();
  const device = status?.device;
  if (!device || !device.name) return null;

  async function toggle(on: boolean) {
    setBusy(true);
    try {
      const res = await post<AppStatus>("/api/app/shields", { shields: on });
      await mutate(res, { revalidate: false });
      toast.success(
        on
          ? t("Kalkanlar açık: diğer cihazlar bu bilgisayara bağlanamaz.")
          : t("Kalkanlar kapalı: erişim kuralları yeniden geçerli."),
      );
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex items-center justify-between gap-4 px-4 py-3">
      <div className="flex items-start gap-3">
        <span className="flex flex-col gap-0.5">
          <label htmlFor="shields" className="text-sm font-medium">
            {t("Bu cihaza gelen bütün bağlantıları reddet")}
          </label>
          <span className="text-sm leading-relaxed text-muted-foreground text-pretty">
            {device.shields
              ? t("Kalkanlar açık. Kurallar izin verse de ağdaki cihazlar bu bilgisayara bağlanamaz; bu bilgisayarın açtığı bağlantılar çalışır.")
              : t("Kalkanlar kapalı. Ağdaki cihazlar erişim kurallarının izin verdiği ölçüde bağlanabilir. Açınca mevcut gelen bağlantılar da kesilir.")}
          </span>
        </span>
      </div>
      <div className="flex items-center gap-2">
        {busy ? <Spinner /> : null}
        <Switch
          id="shields"
          checked={device.shields}
          disabled={busy || readOnly}
          onCheckedChange={(on) => toggle(on)}
        />
      </div>
    </div>
  );
}
