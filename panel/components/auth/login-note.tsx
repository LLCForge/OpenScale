"use client"

import useSWR from "swr"

import { fetcher } from "@/lib/api"
import { useI18n } from "@/lib/i18n/i18n"

interface LoginInfo {
  remote: boolean
}

/**
 * The privacy line under the login form. From another device (ADR-0107)
 * the panel runs on the admin computer and is reached over the tunnel, so
 * the local wording would be wrong there.
 */
export function LoginNote() {
  const { t } = useI18n()
  const { data } = useSWR<LoginInfo>("/api/login-info", fetcher, { revalidateOnFocus: false })
  if (!data) return <p aria-hidden="true" className="min-h-10 max-w-sm" />
  return (
    <p className="max-w-sm text-center text-sm leading-relaxed text-muted-foreground text-pretty">
      {data.remote
        ? t("Bu panel yönetici bilgisayarda çalışıyor ve yalnızca tünel üzerinden, salt okunur açılır. Uzak erişim parolası kök anahtarı açmaz; ağda hiçbir şeyi değiştiremez.")
        : t("Panel yalnızca bu bilgisayarda çalışır, hiçbir dış adrese bağlanmaz. Parolan imzalama dışında hiçbir yerde saklanmaz.")}
    </p>
  )
}
