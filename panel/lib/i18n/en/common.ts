// English texts (#224), keyed by the Turkish source text. See lib/i18n/i18n.tsx.
//
// Shared words and the terminology every area file follows. Look a text up
// here (and in messages-en.ts) before adding it to an area file; a key must
// have one English text in the whole dictionary.
//
// Style: short, plain, sentence case ("Take a backup"); main menu items keep
// title case like the Turkish ("Access Control"). Turkish "sen" imperatives
// become plain imperatives. Keep product and protocol names as they are
// (OpenScale, WireGuard, MagicDNS, SSH, RDP, DNS, NAT, STUN, TOTP, WebAuthn).
//
// Terminology (Turkish -> English):
//   koordinatör -> coordinator          çıkış düğümü -> exit node
//   ağ belgesi -> network document      kök anahtar -> root key
//   kurtarma anahtarı -> recovery key   kill switch -> kill switch
//   davet / davet kodu -> invite / invite code
//   katılım paketi -> join bundle       katıl -> join
//   onayla / onay -> approve / approval reddet -> reject (a request), deny (traffic)
//   iptal et (cihaz, davet) -> revoke   İptal / Vazgeç (button) -> Cancel
//   üye / üyelik -> member / membership ağ sahibi -> network owner
//   yönetici -> admin                   yönetici bilgisayar -> admin computer
//   cihaz -> device                     bu bilgisayar -> this computer
//   kural / erişim kuralı -> rule / access rule; servis kuralı -> service rule
//   etiket -> tag   grup -> group      rota -> route; alt ağ yönlendirici -> subnet router
//   aktarıcı -> relay   doğrudan -> direct   el sıkışma -> handshake
//   tünel -> tunnel   uç nokta -> endpoint   parmak izi -> fingerprint
//   parola (kök anahtar, yedek, mühür) -> passphrase
//   parola (panel girişi, hesap, uzak erişim) -> password
//   imza / imzala -> signature / sign   imzalı -> signed
//   yayımla -> publish   taslak -> draft   sürüm -> version
//   yedek / yedekle / geri yükle -> backup / back up / restore
//   ad sunucusu -> nameserver   alan adı -> domain   alana göre DNS -> split DNS
//   eşitleme -> sync   gelen kutusu -> inbox   karantina -> quarantine
//   uzak masaüstü -> remote desktop   uzak erişim -> remote access
//   konuk -> guest   erişim isteği -> access request
//   anahtar yenileme -> key rotation   kanarya -> canary
//   acil durum kilidi -> emergency lockdown   salt okunur -> read-only
//   denetim kaydı -> audit log   tanı -> diagnostics   olay -> event
//   çevrimiçi / çevrimdışı -> online / offline   son görülme -> last seen
//   kuantum sonrası -> post-quantum   güvenlik anahtarı -> security key
//   oturum -> session   giriş yap / çıkış yap -> sign in / sign out
//   masaüstü uygulaması -> desktop app   servis -> service
//   yerel ağ -> local network   gizlilik -> privacy   sızıntı -> leak
//   kalkan -> shield   engelleme -> blocking   izleme -> monitoring

export const enCommon: Record<string, string> = {
  // Buttons and actions
  İptal: "Cancel",
  Vazgeç: "Cancel",
  Kaydet: "Save",
  Kaydediliyor: "Saving",
  "Kaydediliyor…": "Saving…",
  Sil: "Delete",
  Ekle: "Add",
  Düzenle: "Edit",
  Kopyala: "Copy",
  Kopyalandı: "Copied",
  "Kopyalandı.": "Copied.",
  "Panoya kopyalanamadı.": "Could not copy to the clipboard.",
  Yenile: "Refresh",
  Geri: "Back",
  İleri: "Next",
  Devam: "Continue",
  "Devam et": "Continue",
  Evet: "Yes",
  Hayır: "No",
  Seç: "Choose",
  Seçin: "Choose",
  Göster: "Show",
  Gizle: "Hide",
  İndir: "Download",
  Gönder: "Send",
  Onayla: "Approve",
  Reddet: "Reject",
  "İzin ver": "Allow",
  Uygula: "Apply",
  Kaldır: "Remove",
  Aç: "Open",
  Bitti: "Done",
  "İmzala ve kaydet": "Sign and save",
  "İmzala ve ekle": "Sign and add",
  "İmzala ve uygula": "Sign and apply",
  "İmzala ve kaldır": "Sign and remove",
  "İmzala ve sil": "Sign and delete",
  "İmzala ve onayla": "Sign and approve",
  "İmzala ve kapat": "Sign and turn off",
  "İmzala ve aç": "Sign and turn on",
  "Değişikliği göster": "Show the change",
  İşlemler: "Actions",
  İşlem: "Action",

  // States
  Açık: "On",
  Kapalı: "Off",
  Etkin: "Enabled",
  "Devre dışı": "Disabled",
  Bağlı: "Connected",
  "Bağlı değil": "Not connected",
  Çevrimiçi: "Online",
  Çevrimdışı: "Offline",
  Bilinmiyor: "Unknown",
  Bekleniyor: "Waiting",
  "Bekleniyor…": "Waiting…",
  "Yükleniyor…": "Loading…",
  Çalışıyor: "Running",
  Çalışmıyor: "Not running",
  Başarısız: "Failed",
  Güncel: "Up to date",
  Uyarı: "Warning",
  Hata: "Error",
  Bilgi: "Info",
  Tümü: "All",
  "Süresi doldu": "Expired",
  "Tehlikeli bölge": "Danger zone",
  "Son görülme": "Last seen",
  "Varsayılan kapalı": "Off by default",

  // Common nouns
  Bağlantı: "Connection",
  Tür: "Type",
  Ad: "Name",
  Adres: "Address",
  Süre: "Duration",
  Bitiş: "Ends",
  Tarih: "Date",
  Saat: "Time",
  Ayrıntılar: "Details",
  Açıklama: "Description",
  Tünel: "Tunnel",
  "Uç nokta": "Endpoint",
  "Cihaz adı": "Device name",
  "Adsız cihaz": "Unnamed device",
  "Kök anahtar parolası": "Root key passphrase",
  "Kök anahtar parolası gerekli": "The root key passphrase is required",
  "İşletim sistemi": "Operating system",
  "Uzak masaüstü": "Remote desktop",

  // Form validation
  "Çok uzun": "Too long",
  "Parola çok uzun": "Passphrase is too long",
  "Parolalar eşleşmiyor": "The passphrases do not match",
  "Adres çok uzun": "Address is too long",
  "Tam sayı gir": "Enter a whole number",
  "Sayı gir": "Enter a number",
  "En az 1 gün": "At least 1 day",
  "Beklenmeyen bir hata oluştu.": "An unexpected error occurred.",

  // lib/format.ts
  "süresi doldu": "expired",
  "{count} gün kaldı": "{count} day left|{count} days left",
  "{d} gün {h} sa": "{d} d {h} h",
  "{h} sa {m} dk": "{h} h {m} min",
  "{m} dk": "{m} min",

  // Context keys ("context|Text"): one Turkish text, two English texts
  "recording|Kaydediliyor": "Recording",
  "none|Yok": "None",
  "rule-action|Reddet": "Deny",
  "revoke|Geri al": "Revoke",
  "turn-off|Kapat": "Turn off",
  "passphrase|Parola": "Passphrase",

  // Language selector
  Görünüm: "Appearance",
  Dil: "Language",
  "Türkçe / English": "Türkçe / English",
  "Panelin dili. Seçim bu tarayıcıda saklanır.": "The panel's language. The choice is kept in this browser.",
}
