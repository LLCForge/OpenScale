// English texts (#224), keyed by the Turkish source text. See lib/i18n/i18n.tsx.

export const enSecurity: Record<string, string> = {
  // Network settings (security-view)
  "Kök anahtar ve bütün cihazların uyduğu imzalı ağ belgesi. Yalnızca bu bilgisayarı etkileyen ayarlar Bu bilgisayar sekmesinde.":
    "The root key and the signed network document every device follows. Settings that affect only this computer are on the This computer tab.",
  "Kök anahtar": "Root key",
  "Ağın sahipliği bu anahtardadır; yedeksiz kaybı ağın kaybıdır.":
    "This key owns the network; losing it without a backup means losing the network.",
  Yedekler: "Backups",
  "{count} yedek": "{count} backup|{count} backups",
  "Hiç yedek yok": "No backups",
  "Son yedek {date}. Her yedek ayrı bir parolayla şifrelenir.": "Last backup {date}. Each backup is encrypted with its own passphrase.",
  "Her yedek ayrı bir parolayla şifrelenir; birini çevrim dışı sakla.": "Each backup is encrypted with its own passphrase; keep one offline.",
  "Yedek indir": "Download backup",
  "Yeni cihazlar kök anahtarı bu parmak iziyle doğrular.": "New devices verify the root key with this fingerprint.",
  "Cihazların uyduğu, kök anahtarla imzalı belge. Her değişiklik önce farkı gösterir.":
    "The document devices follow, signed with the root key. Every change shows the difference first.",
  Geçerlilik: "Validity",
  "{date} tarihine kadar geçerli ({days}). Süresi dolan belgeyle yeni bağlantı kurulmaz.":
    "Valid until {date} ({days}). No new connections are made with an expired document.",
  "{date} tarihine kadar geçerli. Süresi dolan belgeyle yeni bağlantı kurulmaz.": "Valid until {date}. No new connections are made with an expired document.",
  "Yeni parolayı unutursan kök anahtara yalnızca yedeklerle ulaşabilirsin. Mevcut yedekler kendi parolalarıyla geçerli kalır.":
    "If you forget the new passphrase, you can reach the root key only through backups. Existing backups stay valid with their own passphrases.",
  "Yalnızca bu bilgisayarda geçerli. Ağ belgesini değiştirmez, imza gerekmez; diğer cihazlar etkilenmez.":
    "Applies only to this computer. It does not change the network document and needs no signature; other devices are not affected.",
  "Uzak panelde bu bilgisayarın ayarları gösterilmez. Bu ayarları ilgili bilgisayarda OpenScale uygulamasından açıp değiştir.":
    "The remote panel does not show this computer's settings. Open and change them in the OpenScale app on that computer.",
  "Bu ayarlar OpenScale masaüstü uygulamasının servisinden gelir; komut satırından açılan panelde görünmez. Ağın imzalı ayarları {link} sayfasında.":
    "These settings come from the OpenScale desktop app's service; they do not appear in a panel opened from the command line. The network's signed settings are on the {link} page.",
  "Paylaşım ve koruma": "Sharing and protection",
  "Bu bilgisayarın ağa açtığı hizmetler, uzak masaüstü izinleri ve DNS korumaları.":
    "Services this computer shares with the network, remote desktop permissions and DNS protections.",
  Gelişmiş: "Advanced",
  "Emin değilsen varsayılanları değiştirme.": "If you are not sure, keep the defaults.",
  "Bu bilgisayar henüz bir ağa katılmadı; ayarlar katıldıktan sonra burada görünür.":
    "This computer has not joined a network yet; the settings appear here after it joins.",

  // Approval policy and hardware keys (approval-card)
  "Onay politikası": "Approval policy",
  "Her yeni belge kök imzasına ek olarak {approvers} onaylayıcıdan {threshold} imza ister.":
    "Every new document needs {threshold} signatures from {approvers} approvers in addition to the root signature.",
  "Politika yok; belgeyi yalnızca kök anahtar imzalar. Değiştirmek için": "No policy; only the root key signs the document. To change it, run",
  "Donanım anahtarları": "Hardware keys",
  "TPM: {tpm}. Akıllı kart okuyucuları: {readers}.": "TPM: {tpm}. Smart card readers: {readers}.",
  yok: "none",

  // Admins (admins-view)
  Geçerli: "Valid",
  "Geri alındı": "Revoked",
  "Yok (yazılım anahtarı)": "None (software key)",
  "Donanım anahtarı": "Hardware key",
  "Kök anahtarın süreli ve kapsamlı yetki verdiği yöneticiler, hassas cihaz onayları ve baskı parolası.":
    "Admins the root key has given time-limited, scoped rights, sensitive device approvals and the duress passphrase.",
  "Yetkili yöneticiler": "Authorized admins",
  "Her yetki en çok 90 gün geçerlidir ve yalnızca listelenen işlemlere izin verir. Kök rotasyonu, onay politikası ve roller her zaman kökündür.":
    "Each grant is valid for at most 90 days and allows only the listed operations. Root rotation, the approval policy and roles always stay with the root.",
  "Henüz yetkili yönetici yok; ağı yalnızca kök anahtar değiştirebilir.": "No authorized admins yet; only the root key can change the network.",
  Jeton: "Token",
  "Geri al": "Undo",
  "{name} yetkisini geri al": "Revoke the grant of {name}",
  "Yeni yönetici için: yöneticinin bilgisayarında {keygen}, ardından kök cihazda {grant}.":
    "For a new admin: run {keygen} on the admin's computer, then {grant} on the root device.",
  "Bu yönetici artık belge imzalayamaz. Bu sürümü görmeyen cihazlar yetkiyi süresi bitene kadar kabul edebilir.":
    "This admin can no longer sign documents. Devices that have not seen this version may accept the grant until it expires.",
  "Geri al ve imzala": "Revoke and sign",
  "Hassas cihazlar": "Sensitive devices",
  "Bu cihazlara erişimi değiştiren her sürüm, kökün yanında belirlenen onaycıların imzasını da ister.":
    "Every version that changes access to these devices also needs the signatures of the chosen approvers besides the root.",
  "Çift onay kuralı tanımlı değil. Tanımlamak için: {command}": "No two-person rule is set. To set one: {command}",
  "Cihazlar onaylar eklenene kadar bu sürümü reddeder. Onay için:": "Devices reject this version until the approvals are added. To approve:",
  Onaylar: "Approvals",
  "Henüz onay yok.": "No approvals yet.",
  "Erişim özeti": "Access digest",
  "Onaycıların imzaladığı özet; kendi cihazlarındaki çıktıyla karşılaştırın.": "The digest the approvers sign; compare it with the output on their own devices.",
  "Baskı parolası: {state}.": "Duress passphrase: {state}.",
  ayarlı: "set",

  // Tunnel and relay (advanced-card)
  "Negatif olamaz": "Cannot be negative",
  "MTU gir; varsayılan için 0": "Enter an MTU; 0 for the default",
  "Hız gir; varsayılan için 0": "Enter a rate; 0 for the default",
  "Miktar gir; varsayılan için 0": "Enter an amount; 0 for the default",
  "0 (varsayılan {default}) veya {min}-{max} arası olmalı": "Must be 0 (default {default}) or between {min} and {max}",
  "Her zaman aktarıcı kullanılırken MTU en fazla {max} olabilir": "When always using the relay, the MTU can be at most {max}",
  "0 (varsayılan) veya 64 KiB/s ile 10 GiB/s arası olmalı": "Must be 0 (default) or between 64 KiB/s and 10 GiB/s",
  "0 (varsayılan) veya 64 KiB ile 1 GiB arası olmalı": "Must be 0 (default) or between 64 KiB and 1 GiB",
  "Değişiklik yok.": "No changes.",
  "Gelişmiş ayarlar kaydedildi. Tünel kısa süreliğine yeniden başlatılıyor.": "Advanced settings saved. The tunnel is restarting briefly.",
  "Tünel ve aktarıcı": "Tunnel and relay",
  "Kaydedince tünel ve koordinatör birkaç saniyeliğine yeniden başlar.": "Saving restarts the tunnel and the coordinator for a few seconds.",
  "Kaydedince tünel birkaç saniyeliğine yeniden başlar.": "Saving restarts the tunnel for a few seconds.",
  "Her zaman aktarıcı kullan": "Always use the relay",
  "Bu cihaz yalnızca koordinatörle UDP konuşur; diğer cihazlarla doğrudan bağlantı denenmez. Doğrudan UDP'yi engelleyen ağlarda işe yarar ama trafik koordinatör üzerinden geçtiği için daha yavaştır. Açıkken MTU en fazla {mtu} olmalı.":
    "This device talks UDP only with the coordinator; direct connections to other devices are not tried. Useful on networks that block direct UDP, but slower because traffic goes through the coordinator. While on, the MTU must be at most {mtu}.",
  "Tünel MTU": "Tunnel MTU",
  "0 = varsayılan ({default}). Aksi halde {min}-{max} arası. Emin değilsen değiştirme; yüksek MTU bazı ağlarda bağlantıyı bozar.":
    "0 = default ({default}). Otherwise between {min} and {max}. If you are not sure, leave it; a high MTU breaks connections on some networks.",
  "Bu bilgisayardaki koordinatörün aktarma sınırları": "Relay limits of the coordinator on this computer",
  "Doğrudan bağlanamayan cihazların trafiği koordinatör üzerinden aktarılır. Sınırlar cihaz başınadır; 0 = varsayılan (20 MiB/s hız, 4 MiB ani yük).":
    "Traffic of devices that cannot connect directly is relayed through the coordinator. Limits are per device; 0 = default (20 MiB/s rate, 4 MiB burst).",
  "Aktarma hızı": "Relay rate",
  "64 KiB/s ile 10 GiB/s arası.": "Between 64 KiB/s and 10 GiB/s.",
  "Ani yük (burst)": "Burst",
  "64 KiB ile 1 GiB arası.": "Between 64 KiB and 1 GiB.",
  "Kaydet ve yeniden başlat": "Save and restart",
  "{label} birimi": "{label} unit",

  // Root key backup and passphrase (backup-dialog, passphrase-dialog, passphrase-schema, file-base64)
  "En fazla 64 karakter": "At most 64 characters",
  "Yedek parolası mevcut paroladan farklı olmalı": "The backup passphrase must differ from the current passphrase",
  "Yedek indirildi. Dosyayı ve parolasını ayrı yerlerde sakla.": "Backup downloaded. Keep the file and its passphrase in separate places.",
  "Kök anahtar yedeği indir": "Download a root key backup",
  "Yedek, belirlediğin yeni parolayla şifrelenmiş bir dosyadır. Geri yüklemek için:":
    "The backup is a file encrypted with the new passphrase you choose. To restore it:",
  "Mevcut kök anahtar parolası": "Current root key passphrase",
  "Yedeğin parolası": "Backup passphrase",
  "Ana paroladan farklı ve en az 12 karakter olmalı.": "Must differ from the main passphrase and be at least 12 characters.",
  "Yedeğin parolası (tekrar)": "Backup passphrase (again)",
  "Not (isteğe bağlı)": "Note (optional)",
  "Yedeğin nerede olduğunu hatırlaman için; dosyaya değil, bu bilgisayardaki kayda yazılır.":
    "To help you remember where the backup is; it is written to the record on this computer, not to the file.",
  "Yedeği oluştur ve indir": "Create and download backup",
  "Yeni parola mevcut paroladan farklı olmalı": "The new passphrase must differ from the current passphrase",
  "Kök anahtar parolası değiştirildi.": "Root key passphrase changed.",
  "Kök anahtar parolasını değiştir": "Change the root key passphrase",
  "Yeni parolayı unutursan yalnızca yedeklerinle kurtarabilirsin.": "If you forget the new passphrase, only your backups can recover the key.",
  "Mevcut parola": "Current passphrase",
  "Mevcut parola gerekli": "Current passphrase is required",
  "Yeni parola": "New passphrase",
  "Yeni parola (tekrar)": "New passphrase (again)",
  "Parolayı değiştir": "Change passphrase",
  "En az 12 karakter olmalı": "Must be at least 12 characters",
  "Birkaç karakterin tekrarından oluşmamalı": "Must not be just a few repeated characters",
  "Dosya çok büyük (en çok 64 KiB).": "The file is too large (at most 64 KiB).",

  // Paper backup and encryption strength (key-hardening-card)
  "Kâğıt yedek": "Paper backup",
  "Şifreli kök anahtarı yazdırılabilir bir QR kod ve elle yazılabilir satırlar olarak verir.":
    "Gives the encrypted root key as a printable QR code and lines you can write down by hand.",
  "Şifreleme gücü": "Encryption strength",
  "Argon2id: {time} tur, {memory} MiB bellek, {threads} iş parçacığı": "Argon2id: {time} passes, {memory} MiB memory, {threads} threads",
  Güçlendir: "Strengthen",
  "Yazdırıp güvenli bir yerde sakla. Yedek parolasını kâğıtla aynı yerde tutma. Geri yükleme: {command}.":
    "Print it and keep it somewhere safe. Do not keep the backup passphrase with the paper. To restore: {command}.",
  "Kök anahtar kâğıt yedeğinin QR kodu": "QR code of the root key paper backup",
  Yazdır: "Print",
  "Yedek parolası": "Backup passphrase",
  "En az 12 karakter; kâğıttaki yedek bu parolayla açılır.": "At least 12 characters; the paper backup opens with this passphrase.",
  "Yedek parolası (tekrar)": "Backup passphrase (again)",
  "Etiket (isteğe bağlı)": "Label (optional)",
  Oluştur: "Create",
  "Kök anahtar yeniden şifrelendi: {memoryBefore} → {memoryAfter} MiB, {timeBefore} → {timeAfter} tur.":
    "Root key re-encrypted: {memoryBefore} → {memoryAfter} MiB, {timeBefore} → {timeAfter} passes.",
  "Kök anahtar zaten bu bilgisayar için güçlü ayarlarla şifreli.": "The root key is already encrypted with strong settings for this computer.",
  "Şifrelemeyi güçlendir": "Strengthen encryption",
  "Bu bilgisayar ölçülür ve kök anahtar, açılması yaklaşık bir saniye sürecek Argon2id ayarlarıyla yeniden şifrelenir. Parola değişmez; mevcut yedekler kendi ayarlarıyla kalır.":
    "This computer is measured and the root key is re-encrypted with Argon2id settings that take about a second to open. The passphrase does not change; existing backups keep their own settings.",

  // Canary (canary-view)
  "Süresi doluyor": "Expiring",
  Yenilenmedi: "Not renewed",
  Doğrulanamadı: "Could not verify",
  "Beyan metni gerekli": "Statement text is required",
  "Beyan metni en çok 2000 bayt olmalı": "The statement text must be at most 2000 bytes",
  "Gün sayısı gerekli": "Number of days is required",
  "En çok 90 gün": "At most 90 days",
  "Kanarya beyanı": "Canary statement",
  "Kanarya, kök anahtarınızla imzaladığınız tarihli bir beyandır. Süresinde yenilemezseniz cihazlar uyarı gösterir. Koordinatör beyanı değiştiremez, yalnızca saklar.":
    "The canary is a dated statement you sign with your root key. If you do not renew it in time, devices show a warning. The coordinator cannot change the statement, only store it.",
  "Kanarya beyanı imzalandı.": "Canary statement signed.",
  "Beyanı imzala": "Sign the statement",
  "İmza bu bilgisayarda atılır; koordinatöre yükleme cihaz servisi tarafından yapılır.":
    "The signature is made on this computer; the device service uploads it to the coordinator.",
  "Beyan metni (en çok 2000 bayt)": "Statement text (at most 2000 bytes)",
  "Geçerlilik (gün)": "Validity (days)",
  İmzala: "Sign",
  "Dosyayı indir": "Download file",
  "Sıra {seq}, {date} tarihine kadar geçerli.": "Sequence {seq}, valid until {date}.",
  "Sıra {seq}.": "Sequence {seq}.",
  "Beyanı doğrula": "Verify a statement",
  "İndirdiğiniz veya bir cihazdan aldığınız kanarya dosyasını denetler.": "Checks a canary file you downloaded or got from a device.",
  "Kanarya dosyası": "Canary file",
  "Dosyayı seçin; içerik yalnızca bu bilgisayarda denetlenir.": "Choose the file; its content is checked only on this computer.",
  "Dosya seç": "Choose file",

  // Emergency (emergency-view)
  "Her şeyi kilitle": "Lock everything",
  "Cihazı çıkar: {device}": "Remove device: {device}",
  "Eski: ağ sonradan değişti": "Stale: the network changed since",
  "Kök anahtarla önceden imzalanıp ayrı bir parolayla mühürlenen belgeler; kök anahtara erişemediğinizde ağı kilitler.":
    "Documents signed in advance with the root key and sealed with a separate passphrase; they lock the network when you cannot reach the root key.",
  "Hazır belgeler": "Prepared documents",
  "Aynı hazırlıktan yalnızca bir belge yayımlanabilir.": "Only one document can be published from the same preparation.",
  "Hazır acil durum belgesi yok.": "No emergency documents are prepared.",
  "Sürüm {version}, taban sürüm {base}, hazırlandı {date}": "Version {version}, base version {base}, prepared {date}",
  "Hassas cihaz onayları gerekir.": "Needs sensitive device approvals.",
  Yayımla: "Publish",
  "Hazırlamak için kök cihazda:": "To prepare one, on the root device:",
  Panik: "Panic",
  "Yalnızca ağın ele geçirildiğinden şüphelendiğinizde kullanın.": "Use only when you suspect the network has been taken over.",
  "Bütün cihazlarda kurallar askıya alınır, davetler geri çekilir. Kök anahtar gerekmez.":
    "Rules are suspended on every device and invites are withdrawn. The root key is not needed.",
  "Önce kilit belgesini hazırlayın; hazır belge olmadan düğme çalışmaz.": "Prepare the lockdown document first; the button does not work without one.",
  "Acil durum parolası gerekli": "Emergency passphrase is required",
  "Onaylamak için PANIK yazın": "Type PANIK to confirm",
  "Onaylamak için {word} yazın": "Type {word} to confirm",
  "Acil durum belgesi yayımlandı (sürüm {version}).": "Emergency document published (version {version}).",
  "{device} ağdan çıkarılır. Kök anahtar gerekmez.": "{device} is removed from the network. The root key is not needed.",
  "Bu hazırlıktan başka belge yayımlanamaz.": "No other document can be published from this preparation.",
  "Acil durum parolası": "Emergency passphrase",
  "Hazırlarken belirlediğiniz ayrı parola; kök anahtar parolası değil.": "The separate passphrase you set when preparing; not the root key passphrase.",

  // Incoming connections (local-security-card)
  "Tüm ağlar": "All networks",
  "Yerel ağ": "Local network",
  "Yalnızca OpenScale": "OpenScale only",
  "Artık yalnızca OpenScale ağından erişilebilir.": "Now reachable only from the OpenScale network.",
  "Windows varsayılanına döndü.": "Back to the Windows default.",
  "Gelen bağlantılar": "Incoming connections",
  "Kalkanlar, ağ DNS'i, uzak masaüstü ve SSH'nin kapsamı ile bağlantı bekleyen portlar.":
    "Shields, network DNS, the scope of remote desktop and SSH, and ports waiting for connections.",
  "Yeniden kontrol et": "Check again",
  "Windows güvenlik duvarı okunuyor; birkaç saniye sürebilir.": "Reading the Windows firewall; this can take a few seconds.",
  "Uzak Masaüstü (RDP)": "Remote Desktop (RDP)",
  "Bu bilgisayarda uzak masaüstü kapalı.": "Remote desktop is off on this computer.",
  "SSH sunucusu": "SSH server",
  "Bu bilgisayarda OpenSSH sunucusu kurulu değil.": "The OpenSSH server is not installed on this computer.",
  "Bağlantı bekleyen portlar": "Ports waiting for connections",
  "{all} tüm ağlarda, {lan} yalnızca yerel ağda, {openscale} yalnızca OpenScale'de. Kontrol: {checked}":
    "{all} on all networks, {lan} on the local network only, {openscale} on OpenScale only. Checked: {checked}",
  "\"Tüm ağlar\" bir programın her ağ arayüzünde dinlediği anlamına gelir; Windows güvenlik duvarı bunların çoğunu yine engeller. Tanımadığın bir program varsa onu kapat veya güvenlik duvarında engelle.":
    "\"All networks\" means a program listens on every network interface; the Windows firewall still blocks most of them. If you do not recognize a program, close it or block it in the firewall.",
  Port: "Port",
  Program: "Program",
  Erişim: "Access",
  "Yalnızca OpenScale ağından erişilebilir.": "Reachable only from the OpenScale network.",
  "Tüm ağlardan erişilebilir (Windows varsayılanı).": "Reachable from all networks (Windows default).",
  "port {port}": "port {port}",

  // Network DNS (network-dns-row)
  "Kapalı. Bu bilgisayar ağ belgesindeki DNS ayarlarını yok sayar ve kendi çözücülerini kullanır. MagicDNS adları çalışmaya devam eder.":
    "Off. This computer ignores the DNS settings in the network document and uses its own resolvers. MagicDNS names keep working.",
  "Açık ve uygulanıyor. Ağ belgesindeki çözücüler ve alan adı yönlendirmeleri bu bilgisayarda etkin.":
    "On and applied. The resolvers and domain routes in the network document are active on this computer.",
  "Açık. Ağ belgesinde şu an DNS ayarı yok; bir ayar imzalandığında bu bilgisayar onu kendiliğinden uygular.":
    "On. The network document has no DNS settings right now; when one is signed, this computer applies it on its own.",
  "Ağdan gelen DNS ayarları kullanılacak.": "DNS settings from the network will be used.",
  "Ağdan gelen DNS ayarları artık kullanılmayacak.": "DNS settings from the network will no longer be used.",
  "Ağdan gelen DNS ayarlarını kullan": "Use DNS settings from the network",
  "DNS ayarları uygulanamadı: {error}": "Could not apply the DNS settings: {error}",

  // Shields (shields-row)
  "Kalkanlar açık: diğer cihazlar bu bilgisayara bağlanamaz.": "Shields on: other devices cannot connect to this computer.",
  "Kalkanlar kapalı: erişim kuralları yeniden geçerli.": "Shields off: access rules apply again.",
  "Bu cihaza gelen bütün bağlantıları reddet": "Refuse all incoming connections to this device",
  "Kalkanlar açık. Kurallar izin verse de ağdaki cihazlar bu bilgisayara bağlanamaz; bu bilgisayarın açtığı bağlantılar çalışır.":
    "Shields are on. Even when rules allow it, devices on the network cannot connect to this computer; connections this computer opens still work.",
  "Kalkanlar kapalı. Ağdaki cihazlar erişim kurallarının izin verdiği ölçüde bağlanabilir. Açınca mevcut gelen bağlantılar da kesilir.":
    "Shields are off. Devices on the network can connect as far as the access rules allow. Turning them on also cuts existing incoming connections.",

  // Personal data (pii-section, risk-summary)
  "Adlarda kişisel veri": "Personal data in names",
  "Bu adlar her cihaza ve koordinatöre gider; nötr adlar (ör. laptop-1) önerilir.":
    "These names go to every device and the coordinator; neutral names (e.g. laptop-1) are recommended.",
  "Ağ adlarında kişisel veri kalıbı bulunmadı.": "No personal data patterns were found in the network's names.",
  "Adlarda kişisel veri olabilir": "Names may contain personal data",
  "Düşük risk": "Low risk",
  "Orta risk": "Medium risk",
  "Yüksek risk": "High risk",
  "Kritik risk": "Critical risk",
  "Değişikliğin risk özeti": "Risk summary of the change",
  "{count} puan": "{count} point|{count} points",
  "Erişimi genişletir": "Widens access",

  // Remote desktop (rdesk-card, rdesk-file-roots)
  "Uzak masaüstü ayarı kaydedildi; açık oturumlar sona erer.": "Remote desktop setting saved; open sessions end.",
  "Oturumları kaydet": "Record sessions",
  "Her oturum bu bilgisayarda şifreli kaydedilir; bağlanan kişiye ve ekrandaki göstergeye bildirilir. Tuşlar ve pano kaydedilmez.":
    "Each session is recorded encrypted on this computer; the person connecting and the on-screen indicator are told. Keystrokes and the clipboard are not recorded.",
  "Ekran karartma ve yerel giriş kilidi": "Screen blanking and local input lock",
  "Kontrol oturumu ekranı karartıp yerel klavye ve fareyi kilitleyebilir; Ctrl+Alt+Del her zaman çalışır.":
    "A control session can blank the screen and lock the local keyboard and mouse; Ctrl+Alt+Del always works.",
  "Uzaktan yeniden başlatma": "Remote restart",
  "Kontrol oturumu bu bilgisayarı 10 saniye sonra yeniden başlatabilir. Güvenli mod bu sürümde yok.":
    "A control session can restart this computer after 10 seconds. Safe mode is not available in this version.",
  "Kimin bağlanacağını rdesk kuralları belirler; bu anahtarlar yalnızca bu bilgisayarda geçerli ve varsayılan kapalı.":
    "rdesk rules decide who can connect; these switches apply only to this computer and are off by default.",
  "Bu bilgisayar uzak masaüstü sunucusu çalıştıramıyor (masaüstü oturumu yok veya desteklenmiyor).":
    "This computer cannot run the remote desktop server (no desktop session, or not supported).",
  Dinliyor: "Listening",
  Başlatılamadı: "Could not start",
  "Açık oturumlar": "Open sessions",
  "kod {code}": "code {code}",
  Gözetimsiz: "Unattended",
  "Oturumdan dosya gezgini klasörleri": "File browser folders for sessions",
  "Her satıra bir mutlak klasör yolu (en fazla {max}). Kontrol izni ve files kuralı olan bir oturum yalnızca bu klasörlere göz atıp dosya çekebilir. Boş bırakılırsa kapalıdır.":
    "One absolute folder path per line (at most {max}). A session with control permission and a files rule can browse and fetch files only in these folders. Leave empty to turn it off.",
  "Klasörleri kaydet": "Save folders",

  // Renew the network document (renew-dialog)
  "En fazla 400 gün": "At most 400 days",
  "Belgenin içeriği aynı kalır; yalnızca sürüm numarası ve geçerlilik süresi yenilenir.":
    "The document's content stays the same; only the version number and the validity period are renewed.",
  "Geçerlilik süresi (gün)": "Validity period (days)",
  "Kısa süre daha güvenlidir ama daha sık yenileme gerektirir. Önerilen: 90 gün.": "A short period is safer but needs renewing more often. Recommended: 90 days.",
  "İmzala ve yenile": "Sign and renew",

  // Sealed data (sealed-blob-check)
  "Doğrulanamadı.": "Could not verify.",
  "Mühürlü veri doğrulandı: {kind}, sıra {seq}, imzalayan {signer}, {size} bayt, {date}.":
    "Sealed data verified: {kind}, sequence {seq}, signed by {signer}, {size} bytes, {date}.",
  "Mühürlü veri doğrulandı: {kind}, sıra {seq}, imzalayan {signer}, {size} bayt.": "Sealed data verified: {kind}, sequence {seq}, signed by {signer}, {size} bytes.",
  "Mühürlü veri": "Sealed data",
  "Koordinatörde saklanan mühürlü yönetici verisinin imzasını denetler; içerik gösterilmez.":
    "Checks the signature of sealed admin data stored on the coordinator; the content is not shown.",
  "Dosyayı doğrula": "Verify a file",
  "Koordinatörden veya yedekten aldığınız mühürlü dosyayı seçin.": "Choose the sealed file you got from the coordinator or a backup.",

  // Traffic and privacy (traffic-card)
  "Trafik ayarları yükleniyor": "Loading traffic settings",
  "Trafik ayarları kaydedildi. Tünel kısa süreliğine yeniden başlatılıyor.": "Traffic settings saved. The tunnel is restarting briefly.",
  "Trafik ve gizlilik": "Traffic and privacy",
  "Varsayılan kapalı. Dolgu ve sahte trafik veri ve pil harcar; maliyet onaylanmadan açılmaz.":
    "Off by default. Padding and cover traffic use data and battery; they do not turn on until you accept the cost.",
  "Tüketimi gör": "See usage",
  "Yönlendiricide port aç (UPnP/NAT-PMP/PCP)": "Open a port on the router (UPnP/NAT-PMP/PCP)",
  "Doğrudan bağlantı olasılığını artırır; yönlendiriciye bu cihaz için bir port yönlendirmesi eklenir.":
    "Makes direct connections more likely; a port forward for this device is added to the router.",
  "Etkin: {protocol} {external}.": "Active: {protocol} {external}.",
  "Son hata: {error}": "Last error: {error}",
  "Paket dolgusu": "Packet padding",
  "Kovalar (128/256/512/1024 bayt)": "Buckets (128/256/512/1024 bytes)",
  "Her paket MTU boyunda": "Every packet at MTU size",
  "Paket boylarından ne yapıldığının anlaşılmasını zorlaştırır.": "Makes it harder to tell from packet sizes what is being done.",
  "Sahte trafik (B/sn, 0: kapalı)": "Cover traffic (B/s, 0: off)",
  "Koordinatöre rastgele aralıklarla anlamsız paketler gönderir.": "Sends meaningless packets to the coordinator at random intervals.",
  "0 veya {min}-{max} arası olmalı.": "Must be 0 or between {min} and {max}.",
  "Tahmini maliyet (MTU {mtu})": "Estimated cost (MTU {mtu})",
  "Dolgu: tipik trafikte yaklaşık %{percent} ek bant genişliği.": "Padding: about {percent}% extra bandwidth on typical traffic.",
  "Sahte trafik: saatte {packets} paket (telefonda radyo uyanması), günde {perDay}, 30 günde {per30Days} veri.":
    "Cover traffic: {packets} packets an hour (radio wake-ups on a phone), {perDay} a day, {per30Days} of data in 30 days.",
  "Maliyeti gördüm, açmak istiyorum": "I have seen the cost and want to turn it on",
  "Etkileşimli trafiğe öncelik": "Prioritize interactive traffic",
  "SSH, uzak masaüstü, DNS ve ping paketleri büyük aktarımların önüne geçer.": "SSH, remote desktop, DNS and ping packets go ahead of large transfers.",
  "Koordinatöre Tor üzerinden bağlan": "Connect to the coordinator through Tor",
  "Bu bilgisayarda çalışan Tor istemcisinin SOCKS adresi. Açıkken bütün eşlere aktarıcıdan ulaşılır, bağlantı yavaşlar; Tor kurulu değilse tünel koordinatöre ulaşamaz.":
    "SOCKS address of the Tor client running on this computer. While on, all peers are reached through the relay and connections get slower; if Tor is not installed, the tunnel cannot reach the coordinator.",
  "Şu anda Tor kullanılıyor.": "Tor is in use right now.",
  "Bu oturumda: {padded} paket dolduruldu ({paddedBytes}), {cover} sahte paket ({coverBytes}).":
    "This session: {padded} packets padded ({paddedBytes}), {cover} cover packets ({coverBytes}).",

  // Connection and encryption (transport-card)
  "Dakika gir; varsayılan için 0": "Enter minutes; 0 for the default",
  "Saniye gir; varsayılan için 0": "Enter seconds; 0 for the default",
  "0 (varsayılan 10) veya {min}-{max} dakika": "0 (default 10) or {min}-{max} minutes",
  "0 (varsayılan 25) veya {min}-{max} saniye": "0 (default 25) or {min}-{max} seconds",
  "ana-makine:port biçiminde yaz, ör. vpn.ornek.com:443": "Write it as host:port, e.g. vpn.example.com:443",
  ":443 veya IP:port biçiminde yaz": "Write it as :443 or IP:port",
  "En fazla {max}": "At most {max}",
  "Bağlantı ayarları kaydedildi. Tünel kısa süreliğine yeniden başlatılıyor.": "Connection settings saved. The tunnel is restarting briefly.",
  "Bağlantı ve şifreleme": "Connection and encryption",
  "Kuantum sonrası anahtar, TCP yedeği ve tembel eşler; kaydedince tünel birkaç saniyeliğine yeniden başlar.":
    "Post-quantum key, TCP fallback and lazy peers; saving restarts the tunnel for a few seconds.",
  "Kuantum sonrası anahtar (ML-KEM-768)": "Post-quantum key (ML-KEM-768)",
  "Destekleyen her eşle WireGuard'a ek bir ön paylaşımlı anahtar anlaşılır. Eski sürümlü eşlerle bağlantı klasik şifrelemeyle sürer.":
    "An extra preshared key for WireGuard is agreed with every peer that supports it. Connections to peers on older versions continue with classic encryption.",
  "Anahtar yenileme aralığı (dakika)": "Key rotation interval (minutes)",
  "0 = varsayılan (10 dakika). {min} ile {max} dakika arası.": "0 = default (10 minutes). Between {min} and {max} minutes.",
  "Koordinatöre TCP yedeğini kullanma": "Do not use the TCP fallback to the coordinator",
  "Varsayılan olarak UDP engellenince koordinatöre TCP (443) üzerinden bağlanılır. Kapatınca yalnızca UDP denenir.":
    "By default, when UDP is blocked the coordinator is reached over TCP (443). With this on, only UDP is tried.",
  "TCP yedek adresi": "TCP fallback address",
  "koordinatör:443": "coordinator:443",
  "Boş = koordinatörün adresi, port 443.": "Empty = the coordinator's address, port 443.",
  "Keepalive (saniye)": "Keepalive (seconds)",
  "0 = varsayılan (25 saniye). {min}-{max} saniye. NAT eşlemesini çabuk unutan ağlarda kısalt.":
    "0 = default (25 seconds). {min}-{max} seconds. Shorten it on networks that forget NAT mappings quickly.",
  "Uyarlanan keepalive": "Adaptive keepalive",
  "Bağlantı kopup geri gelince aralık kısalır, uzun süre sorunsuz kalınca yeniden uzar.":
    "The interval gets shorter when the connection drops and comes back, and longer again after a long trouble-free stretch.",
  "Tembel eşler": "Lazy peers",
  "Eşler yalnızca trafik olunca WireGuard'a eklenir, boşta kalınca çıkarılır. Çok cihazlı ağlarda bellek ve el sıkışma yükünü azaltır.":
    "Peers are added to WireGuard only when there is traffic and removed when idle. Reduces memory and handshake load on networks with many devices.",
  "Boşta kalma süresi (dakika)": "Idle time (minutes)",
  "0 = varsayılan (10 dakika).": "0 = default (10 minutes).",
  "Bu bilgisayardaki koordinatörün TCP dinleyicisi": "TCP listener of the coordinator on this computer",
  "UDP'si engelli cihazlar koordinatöre bu adresten TCP ile bağlanır. Boş = kapalı. Güvenlik duvarında bu TCP portunu aç.":
    "Devices with blocked UDP connect to the coordinator over TCP at this address. Empty = off. Open this TCP port in the firewall.",
  "Dinleme adresi": "Listen address",
  "En fazla bağlantı": "Maximum connections",
  "0 = varsayılan (256).": "0 = default (256).",
  "Şu an dinliyor: {address}": "Listening now: {address}",
  "Koordinatöre şu an TCP ile bağlı: bu ağ UDP'yi engelliyor.": "Connected to the coordinator over TCP right now: this network blocks UDP.",
}
