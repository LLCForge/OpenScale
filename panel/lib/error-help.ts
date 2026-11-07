// What to do after an error (#230). The server's message says what
// happened and why; this adds the next step for the cases the owner can
// fix. It never shows internals: only the status code and the server's
// own (already sanitized) message are looked at.

import { ApiError } from "@/lib/api"
import { tx } from "@/lib/i18n/i18n"

/** Returns the next step for err in the current language, or "" when there is none. */
export function errorAction(err: unknown): string {
  if (err instanceof TypeError) {
    return tx("Panel sunucusuna ulaşılamadı. 'openscale panel' veya OpenScale uygulaması hâlâ çalışıyor mu? Çalışıyorsa sayfayı yenile.")
  }
  if (!(err instanceof ApiError)) return ""
  // The server's Turkish message is matched below, so the advice does not
  // depend on the panel language.
  const msg = err.message.toLowerCase()
  switch (err.status) {
    case 401:
      return msg.includes("parola") ? tx("Parolayı yeniden yaz. Büyük/küçük harf ve klavye dilini denetle.") : tx("Yeniden giriş yap.")
    case 403:
      if (msg.includes("salt okunur")) return tx("Değişiklik için bu bilgisayarda yönetici olarak 'openscale panel readonly off' çalıştır.")
      return tx("Sayfayı yenile; panel yeniden başlatıldıysa güvenlik belirteci değişmiştir.")
    case 404:
      return msg.includes("masaüstü") || msg.includes("servis") // i18n-ignore: sunucu iletisiyle eşleşme
        ? tx("Bu bölüm yalnızca OpenScale masaüstü uygulamasında çalışır; 'openscale app' ile açılan panelde dene.")
        : ""
    case 409:
      return msg.includes("yönetici") // i18n-ignore: sunucu iletisiyle eşleşme
        ? tx("Bu işlemi kök anahtarın bulunduğu yönetici bilgisayardaki panelden yap.")
        : tx("Sayfayı yenileyip işlemi tekrar dene; belge başka bir yerden değişmiş olabilir.")
    case 413:
      return tx("Daha küçük bir dosya seç.")
    case 429:
      return tx("Güvenlik için 5 dakika bekle, sonra tekrar dene.")
    case 500:
      return tx(
        "Beklenmeyen bir hata oldu. Ayrıntı için 'openscale health' ve 'openscale configtest' çalıştır; panel günlüğü terminalde veya servis günlüğündedir.",
      )
    case 503:
      return tx("Hizmet şu an yanıt vermiyor; birkaç saniye sonra tekrar dene.")
  }
  return ""
}
