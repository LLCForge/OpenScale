"use client";

import { useState } from "react";
import useSWR from "swr";
import {
  ChevronDown,
  MonitorSmartphone,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import { toast } from "sonner";

import { useReadOnly } from "@/components/app/read-only";
import { NetworkDnsRow } from "@/components/security/network-dns-row";
import { ShieldsRow } from "@/components/security/shields-row";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ApiError, errorMessage, fetcher, post } from "@/lib/api";
import { formatAgo } from "@/lib/format";
import { msg, useI18n } from "@/lib/i18n/i18n";
import type { LocalSecurity, ServiceAccess } from "@/lib/types";
import { cn } from "@/lib/utils";

const exposureLabel: Record<string, string> = {
  all: msg("Tüm ağlar"),
  lan: msg("Yerel ağ"),
  openscale: msg("Yalnızca OpenScale"),
};

/** RDP/SSH scope and listening ports of the computer running this panel. */
export function LocalSecurityCard() {
  const { t, ts } = useI18n();
  const { data, error, isLoading, mutate } = useSWR<LocalSecurity>(
    "/api/app/security",
    fetcher,
    {
      revalidateOnFocus: false,
      shouldRetryOnError: false,
    },
  );
  const [busy, setBusy] = useState<string | null>(null);
  const [showPorts, setShowPorts] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  if (error instanceof ApiError && error.status === 404) return null;
  if (data && !data.supported) return null;

  async function toggle(service: "rdp" | "ssh", overlayOnly: boolean) {
    setBusy(service);
    try {
      const res = await post<LocalSecurity>("/api/app/security", {
        service,
        overlayOnly,
      });
      await mutate(res, { revalidate: false });
      toast.success(
        overlayOnly
          ? t("Artık yalnızca OpenScale ağından erişilebilir.")
          : t("Windows varsayılanına döndü."),
      );
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(null);
    }
  }

  async function refresh() {
    setRefreshing(true);
    try {
      await mutate(
        await fetcher<LocalSecurity>("/api/app/security?refresh=1"),
        { revalidate: false },
      );
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setRefreshing(false);
    }
  }

  return (
    <Card className="lg:col-span-3">
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex flex-col gap-1.5">
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldCheck className="size-4 text-muted-foreground" />
            {t("Gelen bağlantılar")}
          </CardTitle>
          <CardDescription className="text-pretty">
            {t("Kalkanlar, ağ DNS'i, uzak masaüstü ve SSH'nin kapsamı ile bağlantı bekleyen portlar.")}
          </CardDescription>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={refresh}
          disabled={refreshing || isLoading}
          className="shrink-0"
        >
          <RefreshCw
            data-icon="inline-start"
            className={cn(refreshing && "animate-spin")}
          />
          {t("Yeniden kontrol et")}
        </Button>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {isLoading || !data ? (
          <div className="flex flex-col gap-3">
            <Skeleton className="h-14 w-full" />
            <Skeleton className="h-14 w-full" />
            <p className="text-sm text-muted-foreground">
              {t("Windows güvenlik duvarı okunuyor; birkaç saniye sürebilir.")}
            </p>
          </div>
        ) : (
          <>
            {data.error ? (
              <Alert variant="destructive">
                <ShieldAlert />
                <AlertDescription>{ts(data.error)}</AlertDescription>
              </Alert>
            ) : null}
            <div className="flex flex-col divide-y rounded-lg border">
            <ShieldsRow />
            <NetworkDnsRow />
            <AccessRow
              icon={MonitorSmartphone}
              title={t("Uzak Masaüstü (RDP)")}
              access={data.rdp}
              missing={t("Bu bilgisayarda uzak masaüstü kapalı.")}
              busy={busy === "rdp"}
              onChange={(on) => toggle("rdp", on)}
            />
            <AccessRow
              icon={Terminal}
              title={t("SSH sunucusu")}
              access={data.ssh}
              missing={t("Bu bilgisayarda OpenSSH sunucusu kurulu değil.")}
              busy={busy === "ssh"}
              onChange={(on) => toggle("ssh", on)}
            />
            <div className="flex flex-col gap-2 px-4 py-3">
              <button
                type="button"
                onClick={() => setShowPorts((v) => !v)}
                className="flex items-center justify-between gap-3 text-left"
                aria-expanded={showPorts}
              >
                <span className="flex flex-col gap-0.5">
                  <span className="text-sm font-medium">
                    {t("Bağlantı bekleyen portlar")}
                  </span>
                  <span className="text-sm text-muted-foreground">
                    {t(
                      "{all} tüm ağlarda, {lan} yalnızca yerel ağda, {openscale} yalnızca OpenScale'de. Kontrol: {checked}",
                      {
                        all: data.summary.all,
                        lan: data.summary.lan,
                        openscale: data.summary.openscale,
                        checked: formatAgo(data.checkedAt),
                      },
                    )}
                  </span>
                </span>
                <ChevronDown
                  className={cn(
                    "size-4 shrink-0 text-muted-foreground transition-transform",
                    showPorts && "rotate-180",
                  )}
                />
              </button>
              {showPorts ? (
                <>
                  <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
                    {t(
                      "\"Tüm ağlar\" bir programın her ağ arayüzünde dinlediği anlamına gelir; Windows güvenlik duvarı bunların çoğunu yine engeller. Tanımadığın bir program varsa onu kapat veya güvenlik duvarında engelle.",
                    )}
                  </p>
                  <div className="max-h-80 overflow-auto rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>{t("Port")}</TableHead>
                          <TableHead>{t("Program")}</TableHead>
                          <TableHead>{t("Adres")}</TableHead>
                          <TableHead>{t("Erişim")}</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {data.listeners.map((l) => (
                          <TableRow key={`${l.proto}-${l.address}-${l.port}`}>
                            <TableCell className="font-mono text-[0.8125rem]">
                              {l.proto.toUpperCase()} {l.port}
                            </TableCell>
                            <TableCell className="text-sm">
                              {l.process || "-"}
                            </TableCell>
                            <TableCell className="font-mono text-[0.8125rem] text-muted-foreground">
                              {l.address}
                            </TableCell>
                            <TableCell>
                              <span
                                className={cn(
                                  "rounded-md px-2 py-0.5 text-xs font-medium",
                                  l.exposure === "all"
                                    ? "bg-warning/15 text-warning-foreground dark:text-warning"
                                    : "border",
                                )}
                              >
                                {exposureLabel[l.exposure]
                                  ? t(exposureLabel[l.exposure])
                                  : l.exposure}
                              </span>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </>
              ) : null}
            </div>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function AccessRow({
  icon: Icon,
  title,
  access,
  missing,
  busy,
  onChange,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  access: ServiceAccess;
  missing: string;
  busy: boolean;
  onChange: (on: boolean) => void;
}) {
  const { t } = useI18n();
  const readOnly = useReadOnly();
  const id = `scope-${title.replace(/\W+/g, "-").toLowerCase()}`;
  const state = !access.available
    ? missing
    : access.overlayOnly
      ? t("Yalnızca OpenScale ağından erişilebilir.")
      : t("Tüm ağlardan erişilebilir (Windows varsayılanı).");
  return (
    <div className="flex items-center justify-between gap-4 px-4 py-3">
      <div className="flex items-start gap-3">
        <Icon
          aria-hidden="true"
          className={cn(
            "mt-0.5 size-4 shrink-0",
            access.available && !access.overlayOnly ? "text-warning-foreground dark:text-warning" : "text-muted-foreground",
          )}
        />
        <span className="flex flex-col gap-0.5">
          <label htmlFor={id} className="text-sm font-medium">
            {title}{" "}
            <span className="font-mono text-[0.8125rem] text-muted-foreground">
              {t("port {port}", { port: access.port })}
            </span>
          </label>
          <span className="text-sm text-muted-foreground">{state}</span>
        </span>
      </div>
      <div className="flex items-center gap-2">
        {busy ? <Spinner /> : null}
        <span className="hidden text-sm text-muted-foreground sm:inline">
          {t("Yalnızca OpenScale")}
        </span>
        <Switch
          id={id}
          checked={access.overlayOnly}
          disabled={busy || !access.available || readOnly}
          onCheckedChange={(on) => onChange(on)}
        />
      </div>
    </div>
  );
}
