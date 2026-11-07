// Texts of the troubleshooter's results, by the stable key the service
// returns (internal/troubleshoot). The service also sends Turkish texts
// for the command line; the panel uses these so both languages come from
// the dictionary. An unknown key falls back to the service's own text.

import { msg } from "@/lib/i18n/i18n"

export interface StepText {
  detail: string
  fix?: string
}

export const layerTitles: Record<string, string> = {
  interface: msg("Tünel arayüzü"),
  gateway: msg("Yerel ağ geçidi"),
  dns: msg("DNS"),
  coordinator: msg("Koordinatör"),
  relay: msg("Aktarıcı"),
  peer: msg("Eşler"),
}

export const stepTexts: Record<string, StepText> = {
  "skipped.lower_failed": { detail: msg("{layer} adımı başarısız olduğu için denenmedi; önce o adımı düzeltin.") },
  "interface.ok": { detail: msg("Tünel çalışıyor.") },
  "interface.disconnected": {
    detail: msg("Tünel kapalı (bağlantı elle kesildi)."),
    fix: msg("Tepsi simgesinden veya Kontrol Merkezi'nden bağlantıyı açın."),
  },
  "interface.not_running": {
    detail: msg("Tünel çalışmıyor."),
    fix: msg("Servisi yeniden başlatın; sürüyorsa servis günlüğüne bakın."),
  },
  "interface.down": {
    detail: msg("{name} arayüzü işletim sisteminde kapalı görünüyor."),
    fix: msg("Bağlantıyı yeniden kurun; olmazsa servisi yeniden başlatın."),
  },
  "gateway.ok": { detail: msg("Varsayılan ağ geçidi var.") },
  "gateway.missing": {
    detail: msg("Varsayılan ağ geçidi bulunamadı; bu bilgisayar yerel ağa veya internete bağlı değil."),
    fix: msg("Wi-Fi veya kablo bağlantısını denetleyin; modemi yeniden başlatın."),
  },
  "dns.no_network": { detail: msg("Bu bilgisayar henüz bir ağa katılmamış; koordinatör adı yok.") },
  "dns.coordinator_is_ip": { detail: msg("Koordinatör IP adresiyle tanımlı; ad çözmeye gerek yok.") },
  "dns.ok": { detail: msg("Koordinatörün adı çözüldü.") },
  "dns.resolve_failed": {
    detail: msg("Sistem DNS'i koordinatörün adını çözemedi."),
    fix: msg("Ağın DNS sunucusunu denetleyin; koordinatörün DNS kaydının doğru olduğundan emin olun."),
  },
  "dns.magicdns": {
    detail: msg("MagicDNS çözücüsü çalışmıyor; cihaz adları çözülmeyebilir."),
    fix: msg("Başka bir DNS programı 53. portu tutuyor olabilir; ayrıntı için bu sayfadaki ağ denetimine bakın."),
  },
  "coordinator.no_network": { detail: msg("Bu bilgisayar henüz bir ağa katılmamış.") },
  "coordinator.ok": { detail: msg("Koordinatör yanıt verdi ({ms} ms).") },
  "coordinator.captive": {
    detail: msg("Ağ bir giriş sayfası (captive portal) istiyor; koordinatöre ulaşılamıyor."),
    fix: msg("Tarayıcıda ağın giriş sayfasını açıp oturum açın."),
  },
  "coordinator.unreachable": {
    detail: msg("Koordinatör yanıt vermedi."),
    fix: msg("Koordinatörün çalıştığını ve güvenlik duvarında UDP portunun açık olduğunu denetleyin; UDP engelliyse TCP yedeğini açın."),
  },
  "coordinator.over_tcp": {
    detail: msg("Koordinatöre yalnızca TCP üzerinden ulaşılıyor ({ms} ms); UDP engelli."),
    fix: msg("Ağ UDP'yi engelliyor; doğrudan bağlantılar kurulamayabilir. Başka bir ağ deneyin."),
  },
  "relay.no_peer": { detail: msg("Aktarıcıyı denemek için çevrimiçi bir eş yok.") },
  "relay.ok": { detail: msg("Aktarıcı üzerinden {peer}: {ms} ms.") },
  "relay.failed": {
    detail: msg("Koordinatörün aktarıcısı üzerinden {peer} cihazına ulaşılamadı."),
    fix: msg("Doğrudan bağlantı kurulamayan eşlere ulaşılamaz; koordinatörün aktarıcı sınırlarını ve sürümünü denetleyin."),
  },
  "peer.none": { detail: msg("Bu cihazın tünel kurabileceği bir eş yok.") },
  "peer.more": { detail: msg("{count} eş daha denetlenmedi.") },
  "peer.offline": {
    detail: msg("{peer} ile son birkaç dakikada el sıkışma olmadı."),
    fix: msg("Cihazın açık ve OpenScale'in çalıştığını denetleyin; uzun süredir çevrimdışıysa kendi bağlantısını denetleyin."),
  },
  "peer.relayed": {
    detail: msg("{peer} aktarıcı üzerinden bağlı; doğrudan yol kurulamadı."),
    fix: msg("Bağlantı çalışır ama daha yavaştır; iki taraftan birinde UDP port yönlendirmesi doğrudan yolu açar."),
  },
  "peer.direct": { detail: msg("{peer} doğrudan bağlı.") },
}
