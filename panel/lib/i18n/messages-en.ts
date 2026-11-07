// English dictionary (#224), keyed by the Turkish source text. {name}
// placeholders must match. This is the core file (shell, menus, page
// headers, loading and error states, map, score, transfer, help); the other
// areas are in lib/i18n/en/*.ts and lib/i18n/dictionary.ts merges them.

export const en: Record<string, string> = {
  // Shell and menus
  "Kontrol Merkezi": "Control Center",
  Cihazlar: "Devices",
  "Erişim Kontrolü": "Access Control",
  "Ağ ve Koordinatör": "Network and Coordinator",
  Etkinlik: "Activity",
  Tanı: "Diagnostics",
  "Uzak Erişim": "Remote Access",
  "Gelen Dosyalar": "Received Files",
  "Ağ Haritası": "Network Map",
  Rotalar: "Routes",
  "Güvenlik Puanı": "Security Score",
  Hakkında: "About",
  "Bu bilgisayar": "This computer",
  "Kurulum Sihirbazı": "Setup Wizard",
  "Güvenlik ve Ayarlar": "Security and Settings",
  "Belge Aktarımı": "Document Transfer",
  Yardım: "Help",
  "İçeriğe geç": "Skip to content",
  "Ağ adı:": "Network name:",
  "Menüyü genişlet": "Expand menu",
  "Menüyü daralt": "Collapse menu",
  "Hesap menüsü": "Account menu",
  // Presentation mode (#532)
  "Sunum kipini aç": "Turn on presentation mode",
  "Sunum kipini kapat": "Turn off presentation mode",
  "Sunum kipi açık": "Presentation mode on",
  Sunum: "Present",
  "IP'leri, parmak izlerini, davet kodlarını ve uç noktaları bulanıklaştırır (Alt+Shift+P)":
    "Blurs IP addresses, fingerprints, invite codes and endpoints (Alt+Shift+P)",
  "Ağ sahibi": "Network owner",
  "Ağ üyesi": "Network member",
  "Açık tema": "Light theme",
  "Koyu tema": "Dark theme",
  "Kök anahtar ve yedekler": "Root key and backups",
  "Çıkış yap": "Sign out",

  // Navigation groups and tab strips
  Ağ: "Network",
  Günlükler: "Logs",
  Ayarlar: "Settings",
  Genel: "General",
  Koordinatörler: "Coordinators",
  Harita: "Map",
  "Uzak erişim": "Remote access",
  "Eşitleme ve yedek": "Sync and backup",
  "Güvenlik ve ayarlar": "Security and settings",
  "Kurulum sihirbazı": "Setup wizard",
  "Belge aktarımı": "Document transfer",
  "{area} sayfaları": "{area} pages",
  "Alt ağ yönlendiricileri, OpenScale kurulamayan cihazların ağını (yazıcı, NAS, kamera) özel ağa açar.":
    "Subnet routers open networks of devices that cannot run OpenScale (printers, NAS, cameras) to the private network.",
  "Klasörler özel ağ içinden çekilerek eşitlenir; yedekler bu bilgisayarda şifrelenir.":
    "Folders are synced by pulling inside the private network; backups are encrypted on this computer.",
  "Cihazların adları nasıl çözdüğü: MagicDNS, ad sunucuları ve alan adına göre yönlendirme.":
    "How devices resolve names: MagicDNS, nameservers and split DNS.",
  "Cihazların birbirini bulmasını sağlayan sunucular; belgeyi değiştiremez, trafiği göremez.":
    "Servers that let devices find each other; they cannot change the document or see traffic.",
  "Ana menü": "Main menu",
  "Ana menü (mobil)": "Main menu (mobile)",
  "Ana menüyü aç": "Open main menu",
  "Menüyü kapat": "Close menu",
  "Bulunduğun alan:": "Current area:",
  "Hesap menüsü: ağ sahibi": "Account menu: network owner",
  "Hesap menüsü: ağ üyesi": "Account menu: network member",
  "Ağ (imzalı)": "Network (signed)",
  // Command palette
  "Sayfa veya komut ara": "Search pages or commands",
  "Komut paleti": "Command palette",
  "Sayfa adı veya komut yaz; ok tuşlarıyla seç, Enter ile aç.":
    "Type a page name or command; choose with the arrow keys, open with Enter.",
  Sayfalar: "Pages",
  Komutlar: "Commands",
  Sonuçlar: "Results",
  "Eşleşen sayfa veya komut yok.": "No matching page or command.",
  "Açık temaya geç": "Switch to light theme",
  "Koyu temaya geç": "Switch to dark theme",
  "Adresleri ve anahtarları bulanıklaştırır": "Blurs addresses and keys",
  "Arayüz dili": "Interface language",
  Buradasın: "You are here",
  seç: "select",
  aç: "open",
  kapat: "close",
  Kapat: "Close",
  "Ağ belgesi": "Network document",

  // Loading and errors (#230)
  "Oturumun süresi doldu": "Your session has expired",
  "Güvenlik için oturumlar 15 dakika işlem yapılmazsa kapanır. Giriş sayfasına yönlendiriliyorsun.":
    "For security, sessions close after 15 minutes without activity. Redirecting you to the sign-in page.",
  "Veriler yüklenemedi": "Could not load the data",
  "Tekrar dene": "Try again",
  Yükleniyor: "Loading",
  "Panel sunucusuna ulaşılamadı. 'openscale panel' veya OpenScale uygulaması hâlâ çalışıyor mu? Çalışıyorsa sayfayı yenile.":
    "The panel server cannot be reached. Is 'openscale panel' or the OpenScale app still running? If so, reload the page.",
  "Parolayı yeniden yaz. Büyük/küçük harf ve klavye dilini denetle.":
    "Type the passphrase again. Check upper/lower case and the keyboard layout.",
  "Yeniden giriş yap.": "Sign in again.",
  "Değişiklik için bu bilgisayarda yönetici olarak 'openscale panel readonly off' çalıştır.":
    "To make changes, run 'openscale panel readonly off' as administrator on this computer.",
  "Sayfayı yenile; panel yeniden başlatıldıysa güvenlik belirteci değişmiştir.":
    "Reload the page; if the panel was restarted, its security token has changed.",
  "Bu bölüm yalnızca OpenScale masaüstü uygulamasında çalışır; 'openscale app' ile açılan panelde dene.":
    "This section only works in the OpenScale desktop app; try the panel opened with 'openscale app'.",
  "Bu işlemi kök anahtarın bulunduğu yönetici bilgisayardaki panelden yap.":
    "Do this from the panel on the admin computer that holds the root key.",
  "Sayfayı yenileyip işlemi tekrar dene; belge başka bir yerden değişmiş olabilir.":
    "Reload the page and try again; the document may have been changed elsewhere.",
  "Daha küçük bir dosya seç.": "Choose a smaller file.",
  "Güvenlik için 5 dakika bekle, sonra tekrar dene.": "For security, wait 5 minutes and try again.",
  "Beklenmeyen bir hata oldu. Ayrıntı için 'openscale health' ve 'openscale configtest' çalıştır; panel günlüğü terminalde veya servis günlüğündedir.":
    "An unexpected error occurred. Run 'openscale health' and 'openscale configtest' for details; the panel log is in the terminal or the service log.",
  "Hizmet şu an yanıt vermiyor; birkaç saniye sonra tekrar dene.": "The service is not answering right now; try again in a few seconds.",

  // Page headers
  "Ağına kayıtlı bilgisayarlar, telefonlar ve sunucular.":
    "Computers, phones and servers in your network.",
  "Bu bilgisayar ağa üye; cihazlar ve kurallar yönetici bilgisayardan değiştirilir.":
    "This computer is a network member; devices and rules are changed from the admin computer.",
  "Tünel içinden SSH, dosya gönderme, uyandırma ve hız testi; izinleri servis kuralları belirler.":
    "SSH, file sending, wake-up and speed tests through the tunnel; service rules decide what is allowed.",
  "Diğer cihazların bu bilgisayara gönderdiği dosyalar; OpenScale veri klasöründeki gelen kutusunda durur.":
    "Files other devices sent to this computer; they stay in the inbox in the OpenScale data folder.",
  "Ağının durumu, ilgilenmen gerekenler ve son değişiklikler.":
    "Your network's state, what needs your attention and the latest changes.",
  "Kişisel, bağımsız ve gizlilik öncelikli mesh VPN; ağın sahibi yalnızca sensin.":
    "A personal, independent, privacy-first mesh VPN; you alone own the network.",
  "Ağın kimliği, adres aralıkları ve yeni cihazların katılımı.":
    "The network's identity, address ranges and how new devices join.",
  "Kök anahtar, ağ belgesi ve bu bilgisayarın bağlantı ayarları.":
    "Root key, network document and this computer's connection settings.",
  "Cihazlar arası trafik varsayılan olarak reddedilir; kurallar neye izin verildiğini belirler.":
    "Traffic between devices is refused by default; rules decide what is allowed.",
  "İmzalı her belge sürümü; sayfa açılınca imzalar ve sıra yeniden doğrulanır.":
    "Every signed document version; signatures and order are verified again when the page opens.",
  "Bağlantı sorunlarını bulmak için ağ denetimi, eş yolları, olaylar ve güvenlik kayıtları.":
    "Network check, peer paths, events and security records to find connection problems.",
  "Belge geçmişi": "Document history",
  "Erişim kuralları": "Access rules",
  "Erişim kontrolü": "Access control",
  "Gelen dosyalar": "Received files",
  "OpenScale hakkında": "About OpenScale",
  "Uzak erişim ve tanı": "Remote access and diagnostics",

  // Network map (#229) and device types (#233)
  "Ağ haritası": "Network map",
  "Cihazlar, koordinatör ve imzalı kurallardan gelen bağlantılar.":
    "Devices, the coordinator and the links drawn from the signed rules.",
  "Haritada henüz cihaz yok": "No devices on the map yet",
  "Kurulum sihirbazı koordinatörü ve ilk iki cihazını adım adım ekletir.":
    "The setup wizard walks you through adding the coordinator and your first two devices.",
  "Kurulum sihirbazını aç": "Open the setup wizard",
  "{devices} cihaz ve {links} bağlantı. Cihazlar arasında ok tuşlarıyla gez, ayrıntı için Enter'a bas.":
    "{devices} devices and {links} links. Move between devices with the arrow keys and press Enter for details.",
  "{name}, koordinatör, {status}": "{name}, coordinator, {status}",
  "{name}, {kind}, {status}, {count} bağlantı": "{name}, {kind}, {status}, {count} links",
  Koordinatör: "Coordinator",
  "Telefon veya tablet": "Phone or tablet",
  Sunucu: "Server",
  "Dizüstü bilgisayar": "Laptop",
  "Masaüstü bilgisayar": "Desktop computer",
  Cihaz: "Device",
  "bu bilgisayar": "this computer",
  çevrimiçi: "online",
  çevrimdışı: "offline",
  "durum bilinmiyor": "status unknown",
  Doğrudan: "Direct",
  "Aktarıcı üzerinden": "Through the relay",
  "Şu an bağlantı yok": "No connection right now",
  "Kural (yol bilinmiyor)": "Rule (path unknown)",
  "Çıkış düğümü tüneli (kural yok)": "Exit node tunnel (no rule)",
  "Yönetim tüneli (kural yok)": "Admin tunnel (no rule)",
  "Yönetim veya çıkış tüneli": "Admin or exit tunnel",
  Yönetici: "Admin",
  "Çıkış düğümü": "Exit node",
  "Koordinatör cihazların birbirini bulmasını sağlar ve doğrudan yol yoksa trafiği şifreli olarak aktarır; trafiği okuyamaz.":
    "The coordinator lets devices find each other and relays encrypted traffic when there is no direct path; it cannot read the traffic.",
  "Bu cihazın hiçbir cihazla bağlantısı yok: onu içeren bir kural yok.": "This device has no links: no rule includes it.",
  Bağlantılar: "Links",
  "Bir cihaza tıkla veya Tab ile seçip Enter'a bas: bağlantıları burada listelenir.":
    "Click a device, or select it with Tab and press Enter: its links are listed here.",
  "Bu panel tünel çalıştırmıyor; yalnızca imzalı kurallardan çıkan bağlantılar gösterilir. Doğrudan veya aktarıcı yolu masaüstü uygulamasında görünür.":
    "This panel runs no tunnel, so only links from the signed rules are shown. Direct or relayed paths appear in the desktop app.",
  "Tabloyu gizle": "Hide table",
  "Bağlantıları tablo olarak göster": "Show links as a table",
  "Ağ haritasındaki bağlantılar": "Links in the network map",
  Kural: "Rule",
  Yol: "Path",
  Var: "Yes",
  Yok: "No",
  Gösterim: "Legend",

  // Connection history (#190)
  "Bağlantı geçmişi (son 24 saat)": "Connection history (last 24 hours)",
  "Bu bilgisayarın her cihaza nasıl ulaştığı ve ölçülen gecikme, dakikada bir. Veriler yalnızca bu bilgisayarın belleğinde tutulur ve hiçbir yere gönderilmez; servis yeniden başlayınca sıfırlanır.":
    "How this computer reached each device and the measured latency, once a minute. The data stays only in this computer's memory and is sent nowhere; it resets when the service restarts.",
  "Yalnızca masaüstü uygulamasında": "Desktop app only",
  "Komut satırından açılan panel tünel çalıştırmaz, bu yüzden bağlantı geçmişi yoktur. 'openscale app' ile açılan panelde görünür.":
    "The panel opened from the command line runs no tunnel, so there is no connection history. It appears in the panel opened with 'openscale app'.",
  "Henüz örnek yok; ilk ölçüm bir dakika içinde gelir.": "No samples yet; the first one arrives within a minute.",
  Aktarıcı: "Relay",
  "El sıkışma yok": "No handshake",
  "Yol değişimi": "Path change",
  Gecikme: "Latency",
  "Doğrudan %{direct}, aktarıcı %{relay}, el sıkışma yok %{none}; {changes} yol değişimi":
    "Direct {direct}%, relay {relay}%, no handshake {none}%; {changes} path changes",
  "son gecikme {ms} ms": "last latency {ms} ms",
  "en yüksek {ms} ms": "highest {ms} ms",
  "24 sa önce": "24 h ago",
  "12 sa önce": "12 h ago",
  şimdi: "now",

  // Security score (#238)
  "Güvenlik puanı": "Security score",
  "Ağının ayarlarından bu bilgisayarda hesaplanan puan ve öneriler; hiçbir veri dışarı çıkmaz.":
    "Score and advice computed on this computer from your network's settings; no data leaves it.",
  "Yeniden denetle": "Check again",
  "Toplam puan": "Total score",
  "Son denetim: {time}": "Last check: {time}",
  "{score} / 100, {grade}": "{score} / 100, {grade}",
  "Çok iyi": "Excellent",
  İyi: "Good",
  Orta: "Fair",
  Zayıf: "Weak",
  Düzeltilmeli: "Needs fixing",
  İyileştirilebilir: "Could be better",
  Tamam: "OK",
  Uygulanmıyor: "Not applicable",
  Durum: "Status",
  ağırlık: "weight",
  "Bu denetim burada uygulanmıyor.": "This check does not apply here.",
  "Bu panel komut satırından açıldı: kill switch, RDP/SSH ve açık port denetimleri yalnızca masaüstü uygulamasında yapılır ve puana katılmadı.":
    "This panel was opened from the command line: the kill switch, RDP/SSH and open port checks run only in the desktop app and were left out of the score.",
  "Kök anahtar yedeği": "Root key backup",
  "{count} yedek alınmış.": "{count} backups taken.",
  "Kök anahtarın hiç yedeği yok: bu bilgisayar bozulursa ağ kaybolur. Ayrı parolalı bir yedek alıp USB bellekte sakla.":
    "The root key has no backup: if this computer breaks, the network is lost. Take a backup with its own passphrase and keep it on a USB stick.",
  "Yedek al": "Take a backup",
  "Yedeğin tazeliği": "Backup age",
  "Son yedek {days} gün önce alınmış.": "The last backup was taken {days} days ago.",
  "Son yedek {days} gün önce alınmış. Parolası unutulmuş veya sakladığın ortam bozulmuş olabilir; yeni bir yedek al ve eskisini doğrula.":
    "The last backup was taken {days} days ago. Its passphrase may be forgotten or its medium broken; take a new backup and verify the old one.",
  "Yeni yedek al": "Take a new backup",
  "Ağ belgesinin süresi": "Network document validity",
  "Belgenin bitmesine {days} gün var.": "The document is valid for {days} more days.",
  "Belgenin süresi dolmak üzere veya dolmuş ({days} gün kaldı). Süresi dolan belgeyle cihazlar yeni bağlantı kurmaz; belgeyi yenile.":
    "The document is about to expire or has expired ({days} days left). With an expired document devices make no new connections; renew it.",
  "Belgeyi yenile": "Renew the document",
  "Herkesten herkese kural": "Everyone-to-everyone rule",
  "Bütün cihazları bütün portlarda birbirine açan bir kural yok.": "No rule opens every device to every device on every port.",
  "{count} kural her cihazı her cihaza her portta açıyor; bu, erişim kurallarının korumasını kaldırır. Yerine yalnızca gereken cihaz ve portları açan kurallar yaz.":
    "{count} rules open every device to every device on every port, which removes the protection of access rules. Write rules that open only the devices and ports you need.",
  "Kuralları düzenle": "Edit rules",
  "Boşa düşen etiketler": "Unused tags",
  "Kurallardaki her etiket en az bir cihazda var.": "Every tag in the rules is on at least one device.",
  "Kurallarda geçen ama hiçbir cihazda olmayan etiketler var: {names}. Bu kurallar hiçbir şeyle eşleşmez; yazım hatası olabilir.":
    "Some tags in the rules are on no device: {names}. Those rules match nothing; it may be a typo.",
  "Kuralları incele": "Review rules",
  "Çıkış düğümünü kimler kullanabilir": "Who may use the exit node",
  "Çıkış düğümünü kullanabilecek cihazlar sınırlanmış.": "The devices that may use the exit node are limited.",
  "Ağdaki her cihaz çıkış düğümünü kullanabiliyor. İnternet trafiğini çıkış düğümünden geçirmesi gereken cihazları sınırla.":
    "Every device may use the exit node. Limit it to the devices that need to send internet traffic through it.",
  "Ağda çıkış düğümü yok.": "The network has no exit node.",
  "Çıkış kullanıcılarını seç": "Choose exit users",
  "Güncel olmayan cihazlar": "Outdated devices",
  "Sürüm bildiren her cihaz bu panelle aynı veya daha yeni sürümde.": "Every device that reports its version runs the panel's version or newer.",
  "Şu cihazlar eski bir OpenScale sürümü çalıştırıyor: {names}. Güvenlik düzeltmelerini almaları için güncelle.":
    "These devices run an older OpenScale: {names}. Update them so they get security fixes.",
  "Cihazlara git": "Go to devices",
  "Süresi dolan üyelikler": "Expiring memberships",
  "14 gün içinde üyeliği bitecek cihaz yok.": "No membership ends within 14 days.",
  "Şu cihazların üyeliği 14 gün içinde bitiyor veya bitti: {names}. Kullanılmayanları ağdan çıkar, kullanılanları uzat.":
    "These memberships end within 14 days or have ended: {names}. Remove unused devices and extend the others.",
  "Kill switch": "Kill switch",
  "Çıkış düğümü kullanılırken kill switch açık: tünel düşerse trafik açıkta akmaz.":
    "The kill switch is on while an exit node is used: if the tunnel drops, traffic does not leak.",
  "Bu bilgisayar çıkış düğümü kullanıyor ama kill switch kapalı veya kurulamadı. Tünel düşerse trafik doğrudan internete çıkar; kill switch'i aç.":
    "This computer uses an exit node but the kill switch is off or could not be installed. If the tunnel drops, traffic goes straight to the internet; turn the kill switch on.",
  "Bu bilgisayar çıkış düğümü kullanmıyor.": "This computer does not use an exit node.",
  "Çıkış ayarlarına git": "Go to exit settings",
  "Kuantum sonrası koruma": "Post-quantum protection",
  "Tüneller kuantum sonrası ön paylaşımlı anahtarla korunuyor.": "Tunnels are protected with a post-quantum pre-shared key.",
  "Kuantum sonrası koruma kapalı. Bugün kaydedilen trafiğin gelecekte çözülmesine karşı gelişmiş ayarlardan açabilirsin.":
    "Post-quantum protection is off. To guard traffic recorded today against future decryption, turn it on in the advanced settings.",
  "Yalnızca masaüstü uygulamasında denetlenir.": "Checked only in the desktop app.",
  "Gelişmiş ayarlar": "Advanced settings",
  "Uzak masaüstü (RDP)": "Remote desktop (RDP)",
  "Uzak masaüstü kapalı veya yalnızca OpenScale üzerinden erişilebilir.": "Remote desktop is off or reachable only through OpenScale.",
  "Uzak masaüstü yerel ağdan veya internetten erişilebilir. Yalnızca OpenScale üzerinden erişilebilir yap.":
    "Remote desktop is reachable from the local network or the internet. Make it reachable only through OpenScale.",
  "Yerel güvenliğe git": "Go to local security",
  SSH: "SSH",
  "SSH kapalı veya yalnızca OpenScale üzerinden erişilebilir.": "SSH is off or reachable only through OpenScale.",
  "SSH yerel ağdan veya internetten erişilebilir. Yalnızca OpenScale üzerinden erişilebilir yap.":
    "SSH is reachable from the local network or the internet. Make it reachable only through OpenScale.",
  "Herkese açık portlar": "Ports open to everyone",
  "Bu bilgisayarda her ağ arayüzünde dinleyen port yok.": "No port on this computer listens on every network interface.",
  "Bu bilgisayarda {count} port her ağ arayüzünde dinliyor. Gerekmeyen servisleri kapat veya yalnızca OpenScale'e bağla.":
    "{count} ports on this computer listen on every network interface. Stop services you do not need or bind them to OpenScale only.",
  "Dinleyen portlar": "Listening ports",

  // Document transfer (#234)
  "Belge dışa ve içe aktarma": "Document export and import",
  "İmzalı ağ belgesi": "Signed network document",
  "İmzalı ağ belgesini dosya olarak al veya bir belge dosyasının imzasını doğrula.":
    "Save the signed network document as a file or verify a document file's signature.",
  "Dışa aktar": "Export",
  "Her cihazın zaten tuttuğu imzalı belgeyi indirir: cihaz listesi, kurallar ve ayarlar. Gizli anahtar içermez.":
    "Downloads the signed document every device already holds: device list, rules and settings. It contains no private key.",
  "Bu bir yedek değil": "This is not a backup",
  "Belge, kök anahtar olmadan ağı geri getiremez. Kök anahtarın yedeğini Güvenlik ve Ayarlar sayfasından ayrı parolayla al.":
    "The document cannot bring the network back without the root key. Back up the root key, with its own passphrase, on the Security and Settings page.",
  "İmzalı belgeyi indir": "Download the signed document",
  "İmzalı ağ belgesi indirildi.": "Signed network document downloaded.",
  "İçe aktar ve doğrula": "Import and verify",
  "Daha önce dışa aktarılmış bir belgeyi seç: imzası bu ağın kök anahtarıyla denetlenir ve şu anki sürümle farkı gösterilir.":
    "Choose a previously exported document: its signature is checked against this network's root key and its difference from the current version is shown.",
  "Eski bir sürüm geri yüklenmez: iptal edilmiş cihazları geri getirebilirdi. Kök anahtarın kendisini geri yüklemek için 'openscale network restore' kullanılır.":
    "An old version is never restored: it could bring back revoked devices. To restore the root key itself, use 'openscale network restore'.",
  "Belge dosyası": "Document file",
  "Belge dosyası seç": "Choose a document file",
  "Dosya bir ağ belgesi için çok büyük.": "The file is too large for a network document.",
  "Belge doğrulanamadı": "The document could not be verified",
  "Belge şu anki sürümün aynısı.": "The document is identical to the current version.",
  "Bu eski bir sürüm. O sürümden bu yana değişenler aşağıda.": "This is an older version. What changed since then is listed below.",
  "Belge bu bilgisayardakinden yeni. Ağ başka bir kopyadan yönetilmiş olabilir; 'openscale network verify' çalıştır.":
    "The document is newer than the one on this computer. The network may have been managed from another copy; run 'openscale network verify'.",
  "Sürüm numarası aynı ama içerik farklı. Bu beklenmez; belge geçmişini doğrula.":
    "Same version number but different content. This is unexpected; verify the document history.",
  "İmza geçerli: belge bu ağın kök anahtarıyla imzalanmış": "Signature valid: signed with this network's root key",
  Dikkat: "Warning",
  Sürüm: "Version",
  "{v} (şu anki: {c})": "{v} (current: {c})",
  İmzalandı: "Signed",
  "Geçerlilik sonu": "Valid until",
  "süresi dolmuş": "expired",
  "Cihaz / kural": "Devices / rules",
  "Ağ adı": "Network name",
  "Belgedeki cihazlar": "Devices in the document",
  Farklar: "Differences",
  "Hiçbir şey imzalanmadı veya yazılmadı.": "Nothing was signed or written.",

  // Help (#237)
  "Yardım ve belgeler": "Help and documentation",
  "Kullanım, kurulum ve güvenlik rehberi; internet gerekmez, terminalde 'openscale docs' ile de açılır.":
    "Usage, setup and security guides; no internet needed, also opened with 'openscale docs' in the terminal.",
  "Belgeler şimdilik yalnızca Türkçe.": "The documents are available in Turkish only for now.",
  "Belge bulunamadı": "No documents found",
  "Bu derlemeye belge gömülmemiş; 'pnpm --dir panel build' ile yeniden derle.":
    "No documents were embedded in this build; rebuild with 'pnpm --dir panel build'.",
  Belgeler: "Documents",
  "Belgelerde ara": "Search the documents",
  "Eşleşen belge yok.": "No matching document.",
  Başlarken: "Getting started",
  Güvenlik: "Security",
  Platformlar: "Platforms",
  Mimari: "Architecture",
  "Karar kayıtları (ADR)": "Decision records (ADR)",
  "Ağ ayarları": "Network settings",
  "Yardım bölümleri": "Help sections",
  "Sorun giderme": "Troubleshooting",
  "Tüm cihazlar": "All devices",
  Konuklar: "Guests",
  "Erişim istekleri": "Access requests",
}
