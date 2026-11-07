import { msg } from "@/lib/i18n/i18n"
import type { ScoreCheck } from "@/lib/p16-types"

// Texts of the security score checks (#238), keyed by the stable check IDs
// of internal/panel/score.go. Written in Turkish and translated with t().

export interface CheckText {
  title: string
  /** Shown when the check passes. */
  ok: string
  /** Shown on a warning or failure: what is wrong and what to do. */
  advice: string
  /** Shown when the check does not apply. */
  skip?: string
  /** Page that fixes it. */
  href?: string
  action?: string
}

export const checkTexts: Record<string, CheckText> = {
  backup: {
    title: msg("Kök anahtar yedeği"),
    ok: msg("{count} yedek alınmış."),
    advice: msg("Kök anahtarın hiç yedeği yok: bu bilgisayar bozulursa ağ kaybolur. Ayrı parolalı bir yedek alıp USB bellekte sakla."),
    href: "/settings",
    action: msg("Yedek al"),
  },
  backup_age: {
    title: msg("Yedeğin tazeliği"),
    ok: msg("Son yedek {days} gün önce alınmış."),
    advice: msg("Son yedek {days} gün önce alınmış. Parolası unutulmuş veya sakladığın ortam bozulmuş olabilir; yeni bir yedek al ve eskisini doğrula."),
    href: "/settings",
    action: msg("Yeni yedek al"),
  },
  document_expiry: {
    title: msg("Ağ belgesinin süresi"),
    ok: msg("Belgenin bitmesine {days} gün var."),
    advice: msg("Belgenin süresi dolmak üzere veya dolmuş ({days} gün kaldı). Süresi dolan belgeyle cihazlar yeni bağlantı kurmaz; belgeyi yenile."),
    href: "/settings",
    action: msg("Belgeyi yenile"),
  },
  wide_rule: {
    title: msg("Herkesten herkese kural"),
    ok: msg("Bütün cihazları bütün portlarda birbirine açan bir kural yok."),
    advice: msg("{count} kural her cihazı her cihaza her portta açıyor; bu, erişim kurallarının korumasını kaldırır. Yerine yalnızca gereken cihaz ve portları açan kurallar yaz."),
    href: "/rules",
    action: msg("Kuralları düzenle"),
  },
  unused_tags: {
    title: msg("Boşa düşen etiketler"),
    ok: msg("Kurallardaki her etiket en az bir cihazda var."),
    advice: msg("Kurallarda geçen ama hiçbir cihazda olmayan etiketler var: {names}. Bu kurallar hiçbir şeyle eşleşmez; yazım hatası olabilir."),
    href: "/rules",
    action: msg("Kuralları incele"),
  },
  exit_users: {
    title: msg("Çıkış düğümünü kimler kullanabilir"),
    ok: msg("Çıkış düğümünü kullanabilecek cihazlar sınırlanmış."),
    advice: msg("Ağdaki her cihaz çıkış düğümünü kullanabiliyor. İnternet trafiğini çıkış düğümünden geçirmesi gereken cihazları sınırla."),
    skip: msg("Ağda çıkış düğümü yok."),
    href: "/network",
    action: msg("Çıkış kullanıcılarını seç"),
  },
  outdated_devices: {
    title: msg("Güncel olmayan cihazlar"),
    ok: msg("Sürüm bildiren her cihaz bu panelle aynı veya daha yeni sürümde."),
    advice: msg("Şu cihazlar eski bir OpenScale sürümü çalıştırıyor: {names}. Güvenlik düzeltmelerini almaları için güncelle."),
    href: "/devices",
    action: msg("Cihazlara git"),
  },
  expiring_members: {
    title: msg("Süresi dolan üyelikler"),
    ok: msg("14 gün içinde üyeliği bitecek cihaz yok."),
    advice: msg("Şu cihazların üyeliği 14 gün içinde bitiyor veya bitti: {names}. Kullanılmayanları ağdan çıkar, kullanılanları uzat."),
    href: "/devices",
    action: msg("Cihazlara git"),
  },
  kill_switch: {
    title: msg("Kill switch"),
    ok: msg("Çıkış düğümü kullanılırken kill switch açık: tünel düşerse trafik açıkta akmaz."),
    advice: msg("Bu bilgisayar çıkış düğümü kullanıyor ama kill switch kapalı veya kurulamadı. Tünel düşerse trafik doğrudan internete çıkar; kill switch'i aç."),
    skip: msg("Bu bilgisayar çıkış düğümü kullanmıyor."),
    href: "/settings",
    action: msg("Çıkış ayarlarına git"),
  },
  post_quantum: {
    title: msg("Kuantum sonrası koruma"),
    ok: msg("Tüneller kuantum sonrası ön paylaşımlı anahtarla korunuyor."),
    advice: msg("Kuantum sonrası koruma kapalı. Bugün kaydedilen trafiğin gelecekte çözülmesine karşı gelişmiş ayarlardan açabilirsin."),
    skip: msg("Yalnızca masaüstü uygulamasında denetlenir."),
    href: "/settings",
    action: msg("Gelişmiş ayarlar"),
  },
  remote_desktop: {
    title: msg("Uzak masaüstü (RDP)"),
    ok: msg("Uzak masaüstü kapalı veya yalnızca OpenScale üzerinden erişilebilir."),
    advice: msg("Uzak masaüstü yerel ağdan veya internetten erişilebilir. Yalnızca OpenScale üzerinden erişilebilir yap."),
    skip: msg("Yalnızca masaüstü uygulamasında denetlenir."),
    href: "/settings",
    action: msg("Yerel güvenliğe git"),
  },
  ssh: {
    title: msg("SSH"),
    ok: msg("SSH kapalı veya yalnızca OpenScale üzerinden erişilebilir."),
    advice: msg("SSH yerel ağdan veya internetten erişilebilir. Yalnızca OpenScale üzerinden erişilebilir yap."),
    skip: msg("Yalnızca masaüstü uygulamasında denetlenir."),
    href: "/settings",
    action: msg("Yerel güvenliğe git"),
  },
  open_ports: {
    title: msg("Herkese açık portlar"),
    ok: msg("Bu bilgisayarda her ağ arayüzünde dinleyen port yok."),
    advice: msg("Bu bilgisayarda {count} port her ağ arayüzünde dinliyor. Gerekmeyen servisleri kapat veya yalnızca OpenScale'e bağla."),
    skip: msg("Yalnızca masaüstü uygulamasında denetlenir."),
    href: "/settings",
    action: msg("Dinleyen portlar"),
  },
}

export function checkVars(c: ScoreCheck): Record<string, string | number> {
  return { count: c.count ?? 0, days: c.days ?? 0, names: (c.names ?? []).join(", ") }
}
