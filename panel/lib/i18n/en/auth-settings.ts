// English texts (#224), keyed by the Turkish source text. See lib/i18n/i18n.tsx.

export const enAuthSettings: Record<string, string> = {
  // auth/login-form.tsx
  "Parola gerekli": "Password required",
  "Giriş yapılamadı.": "Could not sign in.",
  "OpenScale'i uygulamadan aç": "Open OpenScale from the app",
  "Bu bilgisayarda parolayla girilecek bir ağ yok. Görev çubuğundaki OpenScale simgesine tıkla veya programa çift tıkla; panel kendiliğinden açılır.":
    "There is no network on this computer to sign in to with a password. Click the OpenScale icon in the taskbar or double-click the program; the panel opens by itself.",
  "Giriş yap": "Sign in",
  "Parolanı gir": "Enter your password",
  "5 yanlış denemeden sonra giriş 5 dakika kilitlenir.": "After 5 wrong attempts, sign-in is locked for 5 minutes.",
  "Uzak panele giriş": "Sign in to the remote panel",
  "Uzak erişim parolanı gir": "Enter your remote access password",
  "Uzak erişim parolası": "Remote access password",
  "Yönetici bilgisayarda 'openscale panel-remote password' ile belirlenen parola. Kök anahtar parolasını burada yazma. Uzak panel yalnızca okunur; 5 yanlış denemeden sonra giriş 5 dakika kilitlenir.":
    "The password set on the admin computer with 'openscale panel-remote password'. Do not type the root key passphrase here. The remote panel is read-only; after 5 wrong attempts, sign-in is locked for 5 minutes.",
  "Kök anahtar parolanı gir": "Enter your root key passphrase",
  "'openscale network init' sırasında belirlediğin parola. 5 yanlış denemeden sonra giriş 5 dakika kilitlenir.":
    "The passphrase you set during 'openscale network init'. After 5 wrong attempts, sign-in is locked for 5 minutes.",
  "Parolayı gizle": "Hide password",
  "Parolayı göster": "Show password",

  // auth/login-note.tsx
  "Bu panel yönetici bilgisayarda çalışıyor ve yalnızca tünel üzerinden, salt okunur açılır. Uzak erişim parolası kök anahtarı açmaz; ağda hiçbir şeyi değiştiremez.":
    "This panel runs on the admin computer and opens only through the tunnel, read-only. The remote access password does not unlock the root key; it cannot change anything in the network.",
  "Panel yalnızca bu bilgisayarda çalışır, hiçbir dış adrese bağlanmaz. Parolan imzalama dışında hiçbir yerde saklanmaz.":
    "The panel runs only on this computer and connects to no outside address. Your passphrase is not stored anywhere except for signing.",

  // auth/mfa-step.tsx
  "Altı haneli kodu girin.": "Enter the six-digit code.",
  "Kod doğrulanamadı.": "Could not verify the code.",
  "İkinci doğrulama": "Second verification",
  "YubiKey'inize dokunun": "Touch your YubiKey",
  "Kimlik doğrulama uygulamasındaki kodu girin": "Enter the code from your authenticator app",
  "Güvenlik anahtarı yalnızca ad ile açılan adreste çalışır. Paneli {host} adresiyle açıp yeniden giriş yapın.":
    "A security key works only on an address opened by name. Open the panel at {host} and sign in again.",
  "Girişe dön": "Back to sign-in",
  "Güvenlik anahtarını kullan": "Use the security key",
  "Anahtarım yanımda değil: kod kullan": "I don't have my key: use a code",
  "Kod 30 saniyede bir değişir. İki dakika içinde bitirmezseniz parola yeniden sorulur.":
    "The code changes every 30 seconds. If you do not finish within two minutes, you are asked for the password again.",
  Doğrula: "Verify",
  "Güvenlik anahtarı kullan": "Use a security key",

  // auth/strict-api.ts
  "Güvenlik anahtarı yanıt vermedi.": "The security key did not respond.",
  "Güvenlik anahtarı yanıtı okunamadı.": "Could not read the security key's response.",
  "İşlem iptal edildi veya süresi doldu. Yeniden deneyin.": "The operation was cancelled or timed out. Try again.",
  "Bu güvenlik anahtarı zaten kayıtlı.": "This security key is already registered.",
  "Tarayıcı bu adreste güvenlik anahtarını kullanmaya izin vermiyor.": "The browser does not allow using the security key on this address.",
  "Güvenlik anahtarı kullanılamadı.": "Could not use the security key.",

  // auth/reauth.tsx
  "Doğrulama yapılamadı.": "Could not verify.",
  "Yönetici kipini yeniden aç": "Turn admin mode back on",
  "Kimliğinizi yeniden doğrulayın": "Verify your identity again",
  "Yönetici kipi kapandı; panel salt okunur. Değişikliğe devam etmek için kimliğinizi doğrulayın.":
    "Admin mode is off; the panel is read-only. Verify your identity to continue the change.",
  "Bu işlem için kimliğinizi yeniden doğrulayın. Doğrulama iki dakika geçerlidir ve tek işlem içindir.":
    "Verify your identity again for this action. The verification is valid for two minutes and for one action only.",
  "Kimlik doğrulama uygulaması açıksa kodu da girin.": "If the authenticator app is on, also enter the code.",
  "Güvenlik anahtarıyla": "With a security key",

  // auth/privacy-guard.tsx
  "Panel kilitlendi": "Panel locked",
  "Devam etmek için bilgisayar parolanızı girin veya YubiKey'inize dokunun.": "Enter your computer password or touch your YubiKey to continue.",
  "Devam etmek için ağ parolasını girin.": "Enter the network passphrase to continue.",
  "Kilidi aç": "Unlock",
  "Şimdi kilitle": "Lock now",
  "Ekranınız paylaşılıyor veya kaydediliyor olabilir ({apps}). Sırlar gizlendi.": "Your screen may be shared or recorded ({apps}). Secrets are hidden.",
  "Ekranı paylaşabilecek bir uygulama açık ({apps}). Sırlar gizlendi.": "An app that can share the screen is open ({apps}). Secrets are hidden.",
  "10 sn göster": "Show for 10 s",
  "Yönetici kipi: {minutes} dk": "Admin mode: {minutes} min",
  "Yönetici kipi kapandı; panel salt okunur.": "Admin mode is off; the panel is read-only.",
  "Yeniden doğrula": "Verify again",
  "Bu bilgisayar uzaktan yönetiliyor: {peers}. Hemen kesmek için Ctrl+Alt+Shift+K.": "This computer is being controlled remotely: {peers}. Press Ctrl+Alt+Shift+K to cut it off at once.",
  "Bu bilgisayarın ekranı izleniyor: {peers}. Hemen kesmek için Ctrl+Alt+Shift+K.": "This computer's screen is being watched: {peers}. Press Ctrl+Alt+Shift+K to cut it off at once.",
  "Oturumu gör": "View session",

  // auth/panel-auth-settings.tsx
  "Panel girişi ve gizlilik": "Panel sign-in and privacy",
  "Panele kimlerin, hangi ikinci doğrulamayla girebileceği ve ekran başında olmadığınızda panelin nasıl korunacağı. Bu ayarlar ağ belgesini değiştirmez.":
    "Who can sign in to the panel, with which second verification, and how the panel is protected when you are away from the screen. These settings do not change the network document.",
  "Bu ayarlar yalnızca yönetici bilgisayarın kendi panelinde değiştirilebilir.": "These settings can only be changed in the admin computer's own panel.",
  "Güvenlik anahtarı eklendi.": "Security key added.",
  "Güvenlik anahtarı kaldırıldı.": "Security key removed.",
  "Anahtar kaldırılamadı.": "Could not remove the key.",
  "Güvenlik anahtarları": "Security keys",
  "YubiKey gibi bir anahtar, parolanın yanında ikinci doğrulama olur. Tarayıcılar anahtarı yalnızca ad ile açılan adreste (localhost) kullanır.":
    "A key such as a YubiKey adds a second verification next to the password. Browsers use the key only on an address opened by name (localhost).",
  "Son kullanım": "Last used",
  Hiç: "Never",
  "Anahtarın adı": "Key name",
  "Güvenlik anahtarı": "Security key",
  "Anahtar ekle": "Add key",
  "Bu adreste güvenlik anahtarı eklenemez. Paneli {host} adresiyle açın.": "A security key cannot be added on this address. Open the panel at {host}.",
  "Kök anahtar parolası gerekli.": "Root key passphrase required.",
  "Kimlik doğrulama uygulaması eklendi.": "Authenticator app added.",
  "Kimlik doğrulama uygulaması kaldırıldı.": "Authenticator app removed.",
  "Kaldırılamadı.": "Could not remove.",
  "Kimlik doğrulama uygulaması (yedek)": "Authenticator app (backup)",
  "Güvenlik anahtarı yanınızda değilken 6 haneli kodla giriş. Kodun tohumu parolanızla mühürlü saklanır.":
    "Sign in with a 6-digit code when your security key is not with you. The code's seed is stored sealed with your passphrase.",
  "Kayıtlı. Uzak panelde de kullanılabilir.": "Registered. Can also be used in the remote panel.",
  "Kayıtlı. Yalnızca bu bilgisayarın panelinde kullanılır.": "Registered. Used only in this computer's panel.",
  "Kimlik doğrulama uygulaması ekle": "Add authenticator app",
  "Uzak erişim parolası (isteğe bağlı)": "Remote access password (optional)",
  "Girerseniz kod uzak panelde de kullanılır.": "If you enter it, the code also works in the remote panel.",
  "Bu kodu kimseyle paylaşmayın. Sayfayı kapatınca bir daha gösterilmez.": "Do not share this code with anyone. It is not shown again after you close the page.",
  "Uygulamaya elle girilecek anahtar": "Key to enter in the app by hand",
  "Anahtarı kopyala": "Copy key",
  "Bağlantıyı destekleyen uygulamalar için:": "For apps that support the link:",
  "Kayıt bağlantısını kopyala": "Copy enrollment link",
  "Uygulamadaki kod": "Code from the app",
  "Beş dakika içinde tamamlayın.": "Finish within five minutes.",
  "Kaydı bitir": "Finish enrollment",
  "Kritik işlemlerde yeniden doğrulama iste": "Ask for verification again for critical actions",
  "Önerilen: açık. Anahtar ekleme, kaldırma gibi işlemler taze bir doğrulama ister.": "Recommended: on. Actions such as adding or removing keys ask for a fresh verification.",
  "Yönetici kipi: değişiklikler 15 dakika sonra kapanır": "Admin mode: changes close after 15 minutes",
  "Doğrulamadan 15 dakika sonra panel salt okunur olur; yeniden doğrulayınca açılır.": "15 minutes after verification the panel becomes read-only; verifying again opens it.",
  "YubiKey çekilince yönetici kipini hemen kapat": "Turn off admin mode as soon as the YubiKey is removed",
  "Anahtarı geri takmak yetmez; yeni bir doğrulama gerekir.": "Plugging the key back in is not enough; a new verification is needed.",
  "Bu bilgisayarda da ikinci doğrulama iste": "Also ask for a second verification on this computer",
  "En az bir güvenlik anahtarı veya kimlik doğrulama uygulaması kayıtlı olmalı.": "At least one security key or authenticator app must be registered.",
  "Doğrulama kuralları": "Verification rules",
  "Bu bilgisayarda kilidi açacak bir yöntem yok.": "There is no way to unlock on this computer.",
  "Boşta kilit": "Idle lock",
  "Boşta kalınca paneli kilitle": "Lock the panel when idle",
  "Süre dolunca panel bulanıklaşır ve devam etmek için parola ister. Kilit sunucuda uygulanır; sayfa değiştirilse de veri gelmez.":
    "When the time runs out, the panel blurs and asks for the password to continue. The lock is enforced on the server; no data arrives even if the page is altered.",
  "{count} dakika": "{count} minute|{count} minutes",
  "Ekran paylaşımı": "Screen sharing",
  "Ekran paylaşılırken sırları otomatik gizle": "Hide secrets automatically while the screen is shared",
  "Zoom, Teams, OBS gibi bir uygulama açıkken anahtarlar, parmak izleri, adresler ve kodlar bulanıklaşır; üzerine gelince 10 saniye görünür. Tarayıcıdan yapılan paylaşımlar algılanamaz. Bu tercih yalnızca bu tarayıcıda saklanır.":
    "While an app such as Zoom, Teams or OBS is open, keys, fingerprints, addresses and codes are blurred; hovering shows them for 10 seconds. Sharing from the browser cannot be detected. This preference is stored only in this browser.",
  "Kayıt silindi.": "Entry deleted.",
  "SSH sunucu anahtarları": "SSH host keys",
  "Panel terminalinin ilk bağlantıda kaydettiği anahtarlar. Anahtar değişirse bağlantı kurulmaz.":
    "Keys the panel terminal saved on the first connection. If a key changes, the connection is not made.",
  "Kayıtlı sunucu anahtarı yok.": "No host keys saved.",
  "İlk görülme": "First seen",
  "Kaydı sil": "Delete entry",
  "Uzak panel adresi": "Remote panel address",
  "Bu ad yalnızca tünel içinde çözülür ve imzalı belgeden gelir; başka bir ad panelde kabul edilmez.":
    "This name resolves only inside the tunnel and comes from the signed document; the panel accepts no other name.",
  "Uzak panel adresi:": "Remote panel address:",
  "Sunan cihazlar: {hosts}": "Serving devices: {hosts}",

  // settings/settings-layout.tsx
  "Bu bölümdeki değişiklikler önce farkı gösterir, sonra kök anahtar parolasıyla imzalanır.":
    "Changes in this section show the diff first, then are signed with the root key passphrase.",
  "İmza gerekir": "Signature required",

  // settings/ddns-section.tsx
  "Güncel değil": "Out of date",
  Çözülemiyor: "Cannot resolve",
  Karşılaştırılamadı: "Could not compare",
  "Saniye olarak sayı yaz": "Enter a number of seconds",
  "Denetim bitti.": "Check finished.",
  "Güncelleme gönderildi.": "Update sent.",
  "Dinamik DNS": "Dynamic DNS",
  "Koordinatörün adı doğru adrese mi çıkıyor, ve ev adresin değişince kendi DNS sunucunun güncellenmesi.":
    "Whether the coordinator's name points to the right address, and updating your own DNS server when your home address changes.",
  "DDNS tutarlılığı": "DDNS consistency",
  "Son denetim {time}": "Last check {time}",
  "Henüz denetlenmedi.": "Not checked yet.",
  "Şimdi denetle": "Check now",
  "DNS sunucusunda gereken ayar": "Setting needed on the DNS server",
  "Anahtar yalnızca bu adı güncelleyebilmeli; ele geçirilirse başka adlar değişmesin.":
    "The key should only be able to update this name, so other names cannot change if it is stolen.",
  "Örneği göster": "Show example",
  "<anahtar>": "<key>",
  "<ad>": "<name>",
  "Örneği kopyala": "Copy example",
  "Açıkken bu alan gerekli": "This field is required when on",
  "Gizli değer silindi.": "Secret deleted.",
  "DDNS ayarları kaydedildi.": "DDNS settings saved.",
  "Kendi DNS sunucuma bildir": "Report to my own DNS server",
  "Ev adresin yalnızca bu sunucuya gönderilir. Özel veya CGNAT adresler hiç yayımlanmaz.":
    "Your home address is sent only to this server. Private or CGNAT addresses are never published.",
  "Son yayın {address} ({time}).": "Last published {address} ({time}).",
  "Son yayın {address}.": "Last published {address}.",
  "Şimdi güncelle": "Update now",
  "Güncelleyici açık": "Updater on",
  "TSIG ile imzalı RFC 2136 güncellemesi gönderilir.": "Sends an RFC 2136 update signed with TSIG.",
  "DNS sunucusu (IP:port)": "DNS server (IP:port)",
  "VPS adresi:53": "VPS address:53",
  Bölge: "Zone",
  "ornek.com": "example.com",
  "ev.ornek.com": "home.example.com",
  "TTL (saniye)": "TTL (seconds)",
  "Anahtar adı": "Key name",
  "ev-guncelle": "home-update",
  Algoritma: "Algorithm",
  "Gizli değer (base64)": "Secret (base64)",
  "Kayıtlı. Değiştirmek için yeni değeri yaz; boş bırakırsan kayıtlı değer korunur.":
    "Saved. Type a new value to change it; leave it empty to keep the saved value.",
  "Sunucudaki TSIG anahtarının gizli değeri.": "The secret of the TSIG key on the server.",
  "Gizli değeri sil": "Delete secret",

  // settings/desktop-section.tsx
  "Başlangıç ve görünüm": "Startup and appearance",
  "Masaüstü uygulamasının bu bilgisayardaki davranışı; imza gerekmez.": "How the desktop app behaves on this computer; no signature needed.",
  "Oturum açılınca başlat": "Start at sign-in",
  "Bütün kullanıcılar": "All users",
  "Bu bilgisayarda oturum açtığınızda OpenScale simgesi bildirim alanında başlar. Arka plan servisi her zaman açılışta çalışır.":
    "When you sign in to this computer, the OpenScale icon starts in the notification area. The background service always runs at startup.",
  "Bütün kullanıcılar için kayıt var; bu kullanıcı kapatırsa simge yine başlamaz.":
    "There is an entry for all users; if this user turns it off, the icon still does not start.",
  "Göze çarpmayan ad kipi açıldı.": "Discreet name mode turned on.",
  "Göze çarpmayan ad kipi kapatıldı.": "Discreet name mode turned off.",
  "Göze çarpmayan ad kipi": "Discreet name mode",
  "Bildirim alanı simgesi, pencere başlığı ve servis görünen adı nötr bir adla görünür. Korumalar ve servis adı değişmez.":
    "The notification area icon, the window title and the service display name show a neutral name. Protections and the service name do not change.",
  "Görünen ad": "Display name",
  "Ağ Yardımcısı": "Network Helper",

  // settings/net-places-row.tsx
  "Ağ konumları açıldı; paylaşımlar bir dakika içinde Gezgin'de görünür.": "Network locations turned on; shares appear in Explorer within a minute.",
  "Ağ konumları kapatıldı; OpenScale'in eklediği konumlar kaldırılıyor.": "Network locations turned off; the locations OpenScale added are being removed.",
  "Bu cihaz yönetici değil: diğer cihazların paylaşım listesi yalnızca yönetici cihazlara gelir.":
    "This device is not an admin: the share list of other devices goes only to admin devices.",
  "Tünel çalışmıyor; konumlar tünel açılınca güncellenir.": "The tunnel is not running; locations are updated when the tunnel is up.",
  "Ağdaki cihazlar henüz paylaşım bildirmedi.": "No device in the network has reported shares yet.",
  "{count} paylaşım bulundu.": "{count} share found.|{count} shares found.",
  "Paylaşımları Ağdaki konumlara ekle": "Add shares to Network locations",
  "Ağdaki cihazların SMB paylaşımları Dosya Gezgini'nde Bu bilgisayar > Ağdaki konumlar altında görünür ve tünel üzerinden açılır. Sürücü harfi kullanılmaz; parola istenirse Windows kendi penceresini açar. Elle eklediğiniz konumlara dokunulmaz.":
    "SMB shares of the network's devices appear in File Explorer under This PC > Network locations and open through the tunnel. No drive letters are used; if a password is needed, Windows opens its own window. Locations you added by hand are not touched.",
  "Bulunan paylaşımlar": "Shares found",

  // settings/platform-section.tsx
  "Sorun yok": "No problem",
  Onarıldı: "Repaired",
  "derleme {build}": "build {build}",
  "Denetim bitti: {fixed} sorun onarıldı, {warned} uyarı.": "Check finished: {fixed} problems repaired, {warned} warnings.",
  Platform: "Platform",
  "İşletim sistemi, güncelleme sonrası öz onarım ve OpenScale servisinin bellek sınırları.":
    "The operating system, self-repair after updates and the memory limits of the OpenScale service.",
  "İşletim sistemi güncellendi ({from} → {to}). OpenScale ayarları tünel açılınca denetlenip onarılacak.":
    "The operating system was updated ({from} → {to}). OpenScale settings will be checked and repaired when the tunnel is up.",
  "Server Core: tepsi yok": "Server Core: no tray",
  "Bu sunucuda masaüstü yok; yönetim komut satırıyla veya bu panelden yapılır.": "This server has no desktop; manage it from the command line or this panel.",
  "Öz onarım": "Self-repair",
  "Son onarım: {time} (güncelleme sonrası).": "Last repair: {time} (after an update).",
  "Son onarım: {time} (elle).": "Last repair: {time} (by hand).",
  "Henüz onarım yapılmadı. İşletim sistemi güncellendiğinde OpenScale kendi ayarlarını kendiliğinden denetler.":
    "No repair yet. When the operating system is updated, OpenScale checks its own settings by itself.",
  "Denetleniyor…": "Checking…",
  "Şimdi denetle ve onar": "Check and repair now",
  "Düşük bellek profili": "Low memory profile",
  "{used} / {total} kullanılıyor.": "{used} / {total} in use.",
  "{used} kullanılıyor.": "{used} in use.",
  "Servis bellek tavanı": "Service memory cap",
  Uygulanmadı: "Not applied",
  Sınırsız: "Unlimited",
  "Windows iş nesnesi": "Windows job object",
  ", işlemci en çok %{percent}": ", CPU at most {percent}%",
  "WSL2 ile kullanım": "Using with WSL2",
  "WSL {version}, {mode} kipi.": "WSL {version}, {mode} mode.",
  "WSL kurulu.": "WSL is installed.",
  "Önerileri göster": "Show suggestions",
  Notlar: "Notes",
  "Onarım sürüyor…": "Repair in progress…",
  "Bellek bütçesinin yüzde {percent} kadarı kullanılıyor": "{percent} percent of the memory budget in use",

  // app/exit-auto-card.tsx
  "En fazla 16 aday": "At most 16 candidates",
  "Cihaz adı en fazla 63 karakter": "Device name is at most 63 characters",
  "En fazla 32 ağ adı": "At most 32 network names",
  "Ağ adı en fazla 128 bayt": "A network name is at most 128 bytes",
  "En fazla 64 aralık": "At most 64 ranges",
  "IPv4 CIDR aralıkları yaz (ör. 203.0.113.0/24)": "Enter IPv4 CIDR ranges (e.g. 203.0.113.0/24)",
  "Güvenilir ağ listesi yalnızca 'güvenilmeyen ağda aç' ile kullanılır": "The trusted network list is used only with 'turn on in untrusted networks'",
  "Aday listesi yalnızca otomatik seçim açıkken kullanılır": "The candidate list is used only while automatic selection is on",
  "Otomatik çıkış ayarları kaydedildi.": "Automatic exit settings saved.",
  "Otomatik seçim açık; şu an çıkış düğümü kullanılmıyor ({reason}).": "Automatic selection is on; no exit node is in use right now ({reason}).",
  "Otomatik seçim açık; şu an çıkış düğümü kullanılmıyor.": "Automatic selection is on; no exit node is in use right now.",
  "Şu an {exit} kullanılıyor ({reason}), {since} itibarıyla.": "Using {exit} right now ({reason}), since {since}.",
  "Şu an {exit} kullanılıyor, {since} itibarıyla.": "Using {exit} right now, since {since}.",
  "Şu an {exit} kullanılıyor ({reason}).": "Using {exit} right now ({reason}).",
  "Şu an {exit} kullanılıyor.": "Using {exit} right now.",
  "Otomatik çıkış düğümü": "Automatic exit node",
  "Kapalı: çıkış düğümünü elle seçersin.": "Off: you choose the exit node by hand.",
  "Otomatik seç": "Choose automatically",
  "Çalışmayan çıkış düğümünden sıradaki adaya geçer. Hiçbiri çalışmazsa trafik tünelde kalır, yerel ağa sızmaz.":
    "Moves from an exit node that stops working to the next candidate. If none works, traffic stays in the tunnel and does not leak to the local network.",
  "En hızlıyı seç": "Choose the fastest",
  "Gecikmesi en az olan adayı kullanır; yalnızca en az %30 daha hızlı bir aday 2 dakika sağlıklı kalınca geçer.":
    "Uses the candidate with the lowest latency; switches only when a candidate at least 30% faster stays healthy for 2 minutes.",
  "Aday çıkış düğümleri": "Candidate exit nodes",
  "boş: kullanılabilen hepsi": "empty: all available",
  "Öncelik sırasıyla, virgülle ayır.": "In order of priority, separated by commas.",
  "Güvenilmeyen ağda otomatik aç": "Turn on automatically in untrusted networks",
  "Bağlı ağlardan biri aşağıdaki listede değilse, ağ okunamazsa veya hiç ağ yoksa çıkış düğümü açılır.":
    "The exit node turns on when a connected network is not in the list below, the network cannot be read, or there is no network at all.",
  "Güvenilir Wi-Fi adları": "Trusted Wi-Fi names",
  "Ev, Ofis": "Home, Office",
  "Büyük-küçük harf duyarlı SSID adları, virgülle ayır.": "Case-sensitive SSID names, separated by commas.",
  "Kablolu ağlara güven": "Trust wired networks",
  "Varsayılan kapalı: kablolu ağlar da güvenilmez sayılır.": "Off by default: wired networks are untrusted too.",
  "Çıkış istisnaları": "Exit exceptions",
  "Çıkış düğümü dışında tutulan IPv4 aralıkları. Sızıntı kilidi (kill switch) açıkken bu trafik engellenir.":
    "IPv4 ranges kept out of the exit node. While the kill switch is on, this traffic is blocked.",
  "Görülen ağlar: {networks}": "Networks seen: {networks}",

  // app/exit-node-card.tsx
  "Çıkış düğümü ayarları kaydedildi.": "Exit node settings saved.",
  "İnternete doğrudan bu bilgisayarın bağlantısından çıkılır.": "Goes to the internet directly through this computer's connection.",
  "{name} (son kullanılan)": "{name} (last used)",
  "{ip}, çevrimiçi": "{ip}, online",
  "{ip}, şu an yanıt vermiyor": "{ip}, not responding right now",
  "Ağda henüz çıkış düğümü yok. Bir sunucuyu Cihazlar sayfasından \"Çıkış düğümü yap\" ile işaretle.":
    "There is no exit node in the network yet. Mark a server on the Devices page with \"Make exit node\".",
  "Yollar kuruluyor...": "Setting up routes...",
  "Çıkış düğümü uyarıları": "Exit node alerts",
  "Sızıntı kilidi (kill switch)": "Kill switch",
  "Açık. Çıkış düğümü seçiliyken tünel düşse, servis çökse veya bilgisayar yeniden başlasa da internet trafiği doğrudan çıkmaz.":
    "On. While an exit node is chosen, internet traffic does not go out directly even if the tunnel drops, the service crashes or the computer restarts.",
  "Kapalı. Koruma yalnızca tünel yollarına dayanır; servis durursa trafik doğrudan bu bilgisayarın bağlantısından çıkabilir.":
    "Off. Protection relies only on the tunnel routes; if the service stops, traffic can go out directly through this computer's connection.",
  "Çıkış düğümü kullanırken yerel ağa erişim": "Local network access while using an exit node",
  "Sızıntı kilidi kapalıyken bu ayar uygulanmaz; yerel ağ her zaman erişilebilir.": "This setting does not apply while the kill switch is off; the local network is always reachable.",
  "Yazıcı, NAS gibi yerel ağ cihazlarına erişilebilir. DNS sorguları yine yalnızca tünelden gider.":
    "Local network devices such as printers and NAS are reachable. DNS queries still go only through the tunnel.",
  "Yerel ağ engelli (önerilen). Açık Wi-Fi'de aynı ağdaki cihazlar bu bilgisayara ulaşamaz.":
    "Local network blocked (recommended). On open Wi-Fi, devices on the same network cannot reach this computer.",
  "Sızıntı kilidi (kill switch) kapatılsın mı?": "Turn off the kill switch?",
  "Çıkış düğümüne ulaşılamazsa veya servis durursa internet trafiği doğrudan bu bilgisayarın bağlantısından çıkabilir. Açık Wi-Fi'de gerçek IP adresin görünür hale gelebilir.":
    "If the exit node cannot be reached or the service stops, internet traffic can go out directly through this computer's connection. On open Wi-Fi your real IP address can become visible.",
  "Sızıntı kilidini kapat": "Turn off kill switch",
  "Seçtiğin cihaz bu bilgisayarın bütün internet trafiğini ve DNS sorgularını kendi bağlantısından çıkarır. Yerel ağdaki cihazlara erişim değişmez. Çıkış düğümüne ulaşılamazsa trafik tünelde bekler; doğrudan internete sızmaz.":
    "The device you choose sends all of this computer's internet traffic and DNS queries out through its own connection. Access to local network devices does not change. If the exit node cannot be reached, traffic waits in the tunnel; it does not leak directly to the internet.",
  "Seçtiğin cihaz bu bilgisayarın bütün internet trafiğini ve DNS sorgularını kendi bağlantısından çıkarır. Yerel ağa erişim açık. Sızıntı kilidi (kill switch), OpenScale dışındaki her yolu kapatır; servis çökse bile trafik doğrudan çıkmaz.":
    "The device you choose sends all of this computer's internet traffic and DNS queries out through its own connection. Local network access is on. The kill switch closes every path outside OpenScale; traffic does not go out directly even if the service crashes.",
  "Seçtiğin cihaz bu bilgisayarın bütün internet trafiğini ve DNS sorgularını kendi bağlantısından çıkarır. Yerel ağa erişim kapalı. Sızıntı kilidi (kill switch), OpenScale dışındaki her yolu kapatır; servis çökse bile trafik doğrudan çıkmaz.":
    "The device you choose sends all of this computer's internet traffic and DNS queries out through its own connection. Local network access is off. The kill switch closes every path outside OpenScale; traffic does not go out directly even if the service crashes.",

  // app/exit-leak-tools.tsx
  Sızıntı: "Leak",
  "Sızıntı bulundu; ayrıntılar kartta.": "Leak found; details are in the card.",
  "Sızıntı bulunmadı.": "No leak found.",
  "Giriş sayfası izni kapatıldı.": "Sign-in page permission closed.",
  "Giriş sayfası için {count} dakikalık izin açıldı.": "Sign-in page allowed for {count} minute.|Sign-in page allowed for {count} minutes.",
  "Sızıntı denetimi": "Leak check",
  "Sızıntı testi": "Leak test",
  "Görünen IP adresini, DNS yolunu, IPv6'yı ve WebRTC'nin gösterebileceği adresleri denetler. Yalnızca kendi koordinatörüne ve çıkış düğümünün çözücüsüne sorar.":
    "Checks the visible IP address, the DNS path, IPv6 and the addresses WebRTC could reveal. It asks only your own coordinator and the exit node's resolver.",
  "Testi çalıştır": "Run test",
  "Giriş sayfası (otel, havaalanı Wi-Fi)": "Sign-in page (hotel, airport Wi-Fi)",
  "{addrs} adresine HTTP/HTTPS izni {time} saatine kadar açık. Tarayıcıda {url} adresini açın.":
    "HTTP/HTTPS to {addrs} is allowed until {time}. Open {url} in the browser.",
  "Sızıntı kilidi açıkken ağın giriş sayfası açılmaz. Yalnızca yerel ağ geçidine {count} dakikalık HTTP/HTTPS izni açar; DNS ve diğer trafik kapalı kalır, süre dolunca izin kendiliğinden kapanır.":
    "While the kill switch is on, the network's sign-in page does not open. This allows HTTP/HTTPS only to the local gateway for {count} minutes; DNS and other traffic stay blocked, and the permission closes by itself when the time is up.",
  "İzni kapat": "Close permission",
  "Giriş sayfasına izin ver": "Allow sign-in page",
}
