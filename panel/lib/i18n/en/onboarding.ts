// English texts (#224), keyed by the Turkish source text. See lib/i18n/i18n.tsx.

export const enOnboarding: Record<string, string> = {
  // app/read-only.tsx
  "Uzak panel, salt okunur.": "Remote panel, read-only.",
  "Değişiklikleri kök anahtarın bulunduğu yönetici bilgisayarda yap.":
    "Make changes on the admin computer that holds the root key.",
  "Panel salt okunur.": "The panel is read-only.",
  "Kapatmak için": "To turn it off, run",

  // app/pin-button.tsx
  "{name} sabitlemesini kaldır": "Unpin {name}",
  "{name} cihazını üste sabitle": "Pin {name} to the top",
  "Sabitlemeyi kaldır": "Unpin",
  "Üste sabitle": "Pin to the top",

  // app/removed-card.tsx
  "Bu bilgisayar ağdan çıkarılmış": "This computer was removed from the network",
  "Yönetici bu bilgisayarın anahtarlarını iptal etmiş. Aynı anahtarlarla geri dönülemez. Bilgisayarı sıfırlayıp yeni anahtarla, yeni bir davet koduyla katılabilirsin.":
    "An admin revoked this computer's keys. It cannot come back with the same keys. Reset the computer and join with a new key and a new invite code.",
  "Sıfırla ve yeniden katıl": "Reset and join again",
  "Bu bilgisayarı sıfırla": "Reset this computer",
  "Eski cihaz anahtarı ve ağ kaydı bu bilgisayardan silinir. Sonra karşılama ekranından yeni bir davet koduyla katılırsın. Yönetici bilgisayarda yeni bir davet oluşturman gerekecek.":
    "The old device key and network record are deleted from this computer. Then you join from the welcome screen with a new invite code. You will need to create a new invite on the admin computer.",
  Sıfırla: "Reset",

  // app/post-quantum-badge.tsx
  "Kuantum sonrası": "Post-quantum",
  "Bu eşle WireGuard ek olarak ML-KEM-768 ile anlaşılmış bir ön paylaşımlı anahtar kullanıyor.":
    "WireGuard with this peer also uses a preshared key agreed with ML-KEM-768.",
  Anlaşılıyor: "Negotiating",
  "Kuantum sonrası anahtar anlaşması sürüyor.": "Post-quantum key agreement is in progress.",
  Klasik: "Classical",
  "Bu eşle yalnızca klasik WireGuard şifrelemesi kullanılıyor.": "Only classical WireGuard encryption is used with this peer.",
  "Eş kuantum sonrası anahtara yanıt vermedi: eski sürüm veya ayarı kapalı. Bağlantı klasik WireGuard ile şifreli.":
    "The peer did not answer the post-quantum key: an old version, or the setting is off. The connection is encrypted with classical WireGuard.",
  "Klasik (kapalı)": "Classical (off)",
  "Kuantum sonrası anahtar bu bilgisayarda kapalı (Gelişmiş ayarlar).":
    "The post-quantum key is off on this computer (Advanced settings).",

  // app/connection-card.tsx
  "5 dakika": "5 minutes",
  "1 saat": "1 hour",
  "Yarın sabaha kadar": "Until tomorrow morning",
  "Bağlantı kesildi; 5 dakika sonra kendiliğinden açılır.": "Disconnected; it turns back on by itself in 5 minutes.",
  "Bağlantı kesildi; 1 saat sonra kendiliğinden açılır.": "Disconnected; it turns back on by itself in 1 hour.",
  "Bağlantı kesildi; sabah 08.00'de kendiliğinden açılır.": "Disconnected; it turns back on by itself at 08:00 in the morning.",
  "Bağlantı kesildi. Yeniden açana kadar kapalı kalır.": "Disconnected. It stays off until you turn it back on.",
  "Bağlantı açılıyor.": "Connecting.",
  "Süreli kes": "Disconnect for a while",
  "Süreli olarak kesik; {time} sonrasında kendiliğinden açılır. Hemen açmak için anahtarı kullan.":
    "Disconnected for a while; it turns back on by itself after {time}. Use the switch to turn it on now.",
  "Diğer cihazlara ulaşılamaz. Bağlantı sen açana kadar kapalı kalır; bilgisayar yeniden başlasa da kapalı kalır.":
    "Other devices cannot be reached. The connection stays off until you turn it on, even if the computer restarts.",
  "{name} · {ip}. Kapatınca diğer cihazlara ulaşılmaz ve seçili çıkış düğümü kullanılmaz; süreli kesersen süre dolunca kendiliğinden açılır.":
    "{name} · {ip}. When off, other devices cannot be reached and the chosen exit node is not used; a timed disconnect turns back on by itself when the time is up.",

  // app/health-alerts.tsx
  "Tünel çalışmıyor": "The tunnel is not running",
  "Bağlantı kapalı": "Connection is off",
  "Koordinatöre ulaşılamıyor": "Cannot reach the coordinator",
  "Koordinatör çalışmıyor": "The coordinator is not running",
  "MagicDNS ayarlanamadı": "MagicDNS could not be set up",
  "Ağ DNS ayarları uygulanamadı": "The network's DNS settings could not be applied",
  "DNS ayarları başka bir programca değiştirildi": "Another program changed the DNS settings",
  "Grup İlkesi DNS kuralları": "Group Policy DNS rules",
  "Ağın DNS çözücüsüne ulaşılamıyor": "Cannot reach the network's DNS resolver",
  "Çıkış düğümü kullanılamıyor": "The exit node cannot be used",
  "Sızıntı kilidi (kill switch) sorunu": "Kill switch problem",
  "Üyelik süresi": "Membership period",
  "Saat yanlış görünüyor": "The clock looks wrong",
  "Ağa katılım başarısız": "Joining the network failed",
  "Giriş sayfası (captive portal)": "Sign-in page (captive portal)",
  "Bu bilgisayarın durumu": "Status of this computer",

  // app/member-home.tsx
  "Bu bilgisayar ağa üye. Cihazları ve erişim kurallarını ağın yöneticisi değiştirir.":
    "This computer is a member of the network. The network's admin changes the devices and access rules.",
  "Ulaşabildiğin cihazlar": "Devices you can reach",
  "Erişim kuralları bu bilgisayarın hangi cihazlarla konuşabileceğini belirler.":
    "Access rules decide which devices this computer can talk to.",
  "Görünen cihaz yok. Yönetici bir erişim kuralı eklediğinde cihazlar burada listelenir.":
    "No devices to show. Devices are listed here when an admin adds an access rule.",
  "Başka bir cihaza erişim iste": "Request access to another device",
  "Bu bilgisayarda komutu çalıştır ve çıkan satırı ağ yöneticisine ilet. İstek bu bilgisayarın anahtarıyla imzalanır; yönetici onaylarsa erişim istediğin süre kadar açılır ve kendiliğinden kapanır.":
    "Run the command on this computer and pass the line it prints to the network admin. The request is signed with this computer's key; if the admin approves it, access opens for the time you asked for and closes by itself.",
  "Bu bilgisayarın internet trafiğinin nereden çıkacağı.": "Where this computer's internet traffic goes out.",
  "Bu bilgisayar ağın koordinatörünü de çalıştırıyor.": "This computer also runs the network's coordinator.",
  "Koordinatör bu bilgisayarda": "The coordinator is on this computer",
  "Koordinatör durdu.": "The coordinator stopped.",
  "TCP yedek taşıma: {addr}": "TCP fallback transport: {addr}",
  "Koordinatör adresini": "the coordinator address",
  "Bu bilgisayarın özel ağa bağlı olup olmadığı.": "Whether this computer is connected to the private network.",
  "Ağ bilgisi en son {time} tarihinde eşitlendi.": "Network information was last synced on {time}.",
  "Ağ bilgisi henüz eşitlenmedi.": "Network information has not been synced yet.",
  "Tünel kapalı": "Tunnel is down",
  "OpenScale servisi tüneli açamadı. Bilgisayarı yeniden başlatmayı dene; sürerse yöneticiye haber ver.":
    "The OpenScale service could not open the tunnel. Try restarting the computer; if it continues, tell the admin.",
  Eşitlenemiyor: "Cannot sync",
  "Mevcut cihazlarla bağlantı sürer; yeni cihazlar ve kural değişiklikleri koordinatöre ulaşınca gelir.":
    "Connections to existing devices continue; new devices and rule changes arrive once the coordinator can be reached.",
  "Bu bilgisayarın adresleri": "Addresses of this computer",
  "Özel IP": "Private IP",
  "Bu ağ UDP'yi engelliyor; denetim trafiği TCP yedek taşımasından geçiyor. Bağlantı çalışır, biraz daha yavaş olabilir.":
    "This network blocks UDP; control traffic goes over the TCP fallback transport. The connection works but may be a little slower.",
  Sabitle: "Pin",
  "{name} IP adresini kopyala": "Copy the IP address of {name}",
  "Gelen bağlantılar ve tünel ayarları. Yalnızca bu bilgisayarda geçerli; ağ belgesini değiştirmez.":
    "Incoming connections and tunnel settings. They apply only to this computer and do not change the network document.",

  // membership/leave-card.tsx
  "Ayrılma isteği gönderildi; bu bilgisayarın anahtarı silindi.": "Leave request sent; this computer's key was deleted.",
  "Ağdan ayrıl": "Leave the network",
  "Bu bilgisayar imzalı bir ayrılma isteği gönderir ve kendi anahtarını hemen siler; yönetici onaylayınca belgeden çıkar. Geri dönmek istersen yöneticiden yeni bir davet kodu alman gerekir.":
    "This computer sends a signed leave request and deletes its own key right away; it leaves the document once an admin approves. To come back, you need a new invite code from the admin.",
  "Ağdan ayrıl…": "Leave the network…",
  "Ağdan ayrıldın": "You left the network",
  "Ağdan ayrılmak istiyor musun?": "Leave the network?",
  "İstek koordinatöre iletildi. Koordinatöre ulaşılamadıysa bu satırı yöneticiye ver; panelde veya 'openscale device leave-apply' ile uygular.":
    "The request was passed to the coordinator. If the coordinator could not be reached, give this line to the admin; they apply it in the panel or with 'openscale device leave-apply'.",
  "Bu bilgisayarın cihaz anahtarı silinir ve aynı kimlikle geri dönülemez. Yeniden katılmak için yöneticiden yeni bir davet kodu iste; bu bilgisayar o davetle yeni bir cihaz olarak katılır.":
    "This computer's device key is deleted and it cannot come back with the same identity. To join again, ask the admin for a new invite code; this computer then joins as a new device.",
  "Ayrılma isteğini kopyala": "Copy the leave request",
  "Ayrıl ve anahtarı sil": "Leave and delete the key",

  // membership/membership-panel.tsx
  "Ayrılmak isteyen, kimliği kopyalanmış veya uzun süredir görülmeyen cihazlar; her çıkarma senin imzanla olur.":
    "Devices that want to leave, whose identity was copied, or that have not been seen for a long time; every removal needs your signature.",
  "Ön onaylı kayıt anahtarı": "Preauthorized enrollment key",
  "Aynı kimlik iki yerde kullanılıyor": "The same identity is used in two places",
  "{first} ile {last} arasında uç noktası {count} kez gidip geldi{endpoints}. Cihazın diski kopyalanmış olabilir: kopyayı kapatın, gerekirse cihazı iptal edip yeniden davet edin.":
    "Between {first} and {last} its endpoint switched back and forth {count} time{endpoints}. The device's disk may have been copied: shut the copy down, and if needed revoke the device and invite it again.|Between {first} and {last} its endpoint switched back and forth {count} times{endpoints}. The device's disk may have been copied: shut the copy down, and if needed revoke the device and invite it again.",
  "Ayrılmak isteyen cihazlar": "Devices that want to leave",
  "İmzalı istek: {time}": "Signed request: {time}",
  "{name} ağdan çıkarılsın mı?": "Remove {name} from the network?",
  "Cihaz kendi anahtarıyla ayrılmak istedi. Onaylarsan anahtarları iptal listesine girer.":
    "The device asked to leave with its own key. If you approve, its keys go on the revocation list.",
  Çıkar: "Remove",
  "Hareketsiz cihazlar": "Inactive devices",
  "Hareketsizlik süresi": "Inactivity period",
  "{count} gündür görülmeyen cihaz yok.": "No device has gone unseen for {count} day.|No device has gone unseen for {count} days.",
  "(yönetici cihaz)": "(admin device)",
  "(geçici)": "(temporary)",
  "Son görülme {time}": "Last seen {time}",
  "Hiç görülmedi; eklenme {date}": "Never seen; added {date}",
  "{count} cihaz ağdan çıkarılsın mı?": "Remove {count} device from the network?|Remove {count} devices from the network?",
  "{names} kalıcı olarak iptal edilir; tek imzayla tek sürüm oluşur.":
    "{names} will be revoked permanently; one signature makes one version.",
  "Seçilenleri çıkar": "Remove selected",
  "Son görülme bu bilgisayarın tünelinden ve koordinatörden öğrenilir ve yalnızca burada saklanır. Geçici cihazlar üyelikleri bitince bir sonraki imzalı sürümde kendiliğinden düşer.":
    "Last seen is learned from this computer's tunnel and the coordinator and is kept only here. Temporary devices drop out by themselves in the next signed version once their membership ends.",
  "Kurtarma anahtarı yok: kök anahtar ele geçirilirse ağ yeniden kurulmalı. Oluşturmak için yönetici bilgisayarda:":
    "No recovery key: if the root key is compromised, the network must be set up again. To create one, on the admin computer run:",
  "Sürüm 1.2.3 biçiminde olmalı": "The version must look like 1.2.3",
  "Asgari sürüm {version} olsun mu?": "Set the minimum version to {version}?",
  "Asgari sürüm kaldırılsın mı?": "Remove the minimum version?",
  "Bu sürümün altındaki istemcileri koordinatör açık bir hata iletisiyle reddeder. Yönetici cihazlar hiçbir zaman reddedilmez.":
    "The coordinator rejects clients below this version with a clear error message. Admin devices are never rejected.",
  "Asgari istemci sürümü": "Minimum client version",
  "Bilinen açığı olan eski sürümleri ağdan uzak tutar. Boş bırakmak sınırı kaldırır.":
    "Keeps old versions with known vulnerabilities off the network. Leave it empty to remove the limit.",
  "Ağ belgesi sürüm {version} olarak imzalandı.": "The network document was signed as version {version}.",
  "Küçük harf, rakam ve tire; tireyle başlayıp bitemez": "Lowercase letters, digits and hyphens; it cannot start or end with a hyphen",
  "Geçici cihazın üyeliği en fazla 720 saat (30 gün) olabilir": "A temporary device's membership can be at most 720 hours (30 days)",
  "Kayıt anahtarı hazır": "Enrollment key ready",
  "Bu anahtar cihazın özel anahtarlarını içerir ve yalnızca bir kez gösterilir. Parola gibi taşı, tek bir sunucuda kullan.":
    "This key contains the device's private keys and is shown only once. Handle it like a password and use it on a single server.",
  "Sunucu veya konteyner, onay beklemeden katılır: cihaz şimdi senin imzanla belgeye eklenir. Yönetici rolü verilemez.":
    "A server or container joins without waiting for approval: the device is added to the document now with your signature. It cannot be given the admin role.",
  "Kayıt anahtarını kopyala": "Copy the enrollment key",
  "{name} ({ip}) eklendi; üyelik sonu {time}. Sunucuda: {join} ardından {up}.":
    "{name} ({ip}) was added; membership ends {time}. On the server: {join} then {up}.",
  "openscale preauth-join --key @dosya": "openscale preauth-join --key @file",
  "Etiketler (isteğe bağlı)": "Tags (optional)",
  "ci, sunucu": "ci, server",
  "Kurallar cihaza tag:ad ile erişim verir. En fazla {max}.": "Rules give the device access with tag:name. At most {max}.",
  "Üyelik süresi (saat)": "Membership period (hours)",
  "Geçici cihaz (süre bitince kendiliğinden düşer)": "Temporary device (drops out by itself when the time ends)",
  "Çıkış düğümü olabilsin": "Can be an exit node",
  "Anahtar oluştur": "Create key",

  // invites/invites-panel.tsx
  "Onay bekleyen cihazlar ({count})": "Devices awaiting approval ({count})",
  "Kod yeni bilgisayarın ekranındakiyle aynıysa onayla.": "Approve if the code matches the one on the new computer's screen.",
  "İstek: {time}": "Request: {time}",
  "Açık davetler ({count})": "Open invites ({count})",
  "{time} tarihine kadar geçerli": "Valid until {time}",
  "{used}/{max} kullanıldı": "{used}/{max} used",
  "İstek reddedildi; davet geçerli kalıyor.": "Request rejected; the invite stays valid.",
  "Doğrulama kodu {code}": "Verification code {code}",
  "Tek kod": "Single code",
  "İki parçalı kod": "Two-part code",
  "Kurulum dosyası": "Setup file",
  "Sayı girin": "Enter a number",
  "En fazla 64": "At most 64",
  "En fazla 120 karakter": "At most 120 characters",
  "Cihaz davet et": "Invite a device",
  "Davet, kök anahtarınla imzalanıp ağ belgesine eklenir. Süresi dolunca kendiliğinden geçersiz olur.":
    "The invite is signed with your root key and added to the network document. It becomes invalid by itself when it expires.",
  "Nasıl verilecek": "How to hand it over",
  "Yeni cihazın sistemi": "The new device's system",
  "Geçerlilik süresi": "Validity",
  "Kurulum dosyasındaki davet en çok 1 gün geçerli olur.": "An invite in a setup file is valid for at most 1 day.",
  "Kısa süre daha güvenli; kodu hemen kullanacaksan 1 saat yeterli.": "Shorter is safer; if you will use the code right away, 1 hour is enough.",
  "Katılan cihaz bu etiketlerle eklenir; kurallar ona hemen tag:ad ile başvurabilir. Virgül veya boşlukla ayır, en fazla {max}.":
    "The joining device is added with these tags; rules can refer to it right away with tag:name. Separate with commas or spaces, at most {max}.",
  "Kaç cihaz katılabilir": "How many devices can join",
  "1'den fazlaysa kod birden çok cihazda kullanılabilir; her cihazı yine 4 haneli kodla ayrı ayrı onaylarsın.":
    "If more than 1, the code can be used on several devices; you still approve each device separately with its 4-digit code.",
  "Açıklama (isteğe bağlı)": "Description (optional)",
  "Ayşe'nin telefonu": "Alice's phone",
  "Yalnızca bu bilgisayarda tutulur; imzalı ağ belgesine girmez.": "Kept only on this computer; it does not go into the signed network document.",
  "Kurulum dosyasını indir": "Download setup file",
  "Davet oluştur": "Create invite",
  "Yeni cihaz kodu 'Ağa katıl' ekranına yapıştırır.": "The new device pastes the code into the 'Join a network' screen.",
  "Kod iki parçaya bölünür: birini mesajla, diğerini telefonda okuyarak ver. Tek parçayı ele geçiren katılım başlatamaz. Eski sürümdeki cihazlar bölünmüş kodu tanımaz.":
    "The code is split in two parts: send one by message and read the other out over the phone. Someone who gets only one part cannot start joining. Devices on an old version do not recognize a split code.",
  "Kodu taşıyan küçük bir dosya iner; internetten bir şey indirmez. Windows'ta kodu panoya koyup uygulamayı açar, Linux'ta katılımı doğrudan başlatır. Katılım yine senin onayını ister.":
    "A small file that carries the code is downloaded; it downloads nothing from the internet. On Windows it puts the code on the clipboard and opens the app; on Linux it starts joining directly. Joining still needs your approval.",
  "Davet kodu hazır": "Invite code ready",
  "İki parçalı davet hazır": "Two-part invite ready",
  "Kurulum dosyası indirildi": "Setup file downloaded",
  "Yeni bilgisayarda OpenScale'i aç, Davet koduyla katıl'ı seç ve bu kodu yapıştır. Kod seçtiğin sayıda cihaz için geçerlidir.":
    "Open OpenScale on the new computer, choose Join with an invite code and paste this code. The code is valid for the number of devices you chose.",
  "Yeni cihaz iki parçayı 'Ağa katıl' ekranına aynı alana, aralarında boşlukla yazar. İki parçayı aynı kanaldan gönderme.":
    "The new device types both parts into the same field of the 'Join a network' screen, separated by a space. Do not send both parts over the same channel.",
  "Dosyayı yeni cihaza kendin taşı. Windows'ta OpenScale kurulu değilse resmi kurulum dosyasını yanına koy.":
    "Carry the file to the new device yourself. On Windows, if OpenScale is not installed, put the official installer next to it.",
  "Geçerlilik: {time}. Kodu kendin taşı; içinde ağına bağlanma anahtarı var. Kodu ele geçiren biri de istek gönderebilir, bu yüzden onaylarken 4 haneli kodu mutlaka karşılaştır.":
    "Valid until: {time}. Carry the code yourself; it holds the key to connect to your network. Anyone who gets the code can also send a request, so always compare the 4-digit code when approving.",
  "A parçası: mesajla gönder": "Part A: send by message",
  "A parçasını kopyala": "Copy part A",
  "B parçası: telefonda oku": "Part B: read out over the phone",
  "B parçası {code}": "Part B {code}",
  "Geçerlilik: {time}.": "Valid until: {time}.",
  "Yeniden indir": "Download again",
  "Davet {time} tarihinde geçersiz olur. Dosya davet kodunu açık taşır; kimseyle paylaşma ve işin bitince sil.":
    "The invite becomes invalid on {time}. The file carries the invite code in the clear; do not share it with anyone and delete it when you are done.",
  "{name} ağa eklendi ({ip}).": "{name} was added to the network ({ip}).",
  "Cihazı onayla": "Approve device",
  "Yeni bilgisayarın ekranındaki kod aşağıdakiyle aynı olmalı. Farklıysa onaylama ve daveti iptal et.":
    "The code on the new computer's screen must match the one below. If it differs, do not approve, and revoke the invite.",
  "Parmak izi {fingerprint}": "Fingerprint {fingerprint}",
  "Geçici (konuk) cihaz: {count} saat sonra, konuk erişimiyle birlikte düşer":
    "Temporary (guest) device: drops out after {count} hour, together with the guest access|Temporary (guest) device: drops out after {count} hours, together with the guest access",
  "Geçici (misafir) cihaz: 24 saat sonra kendiliğinden düşer": "Temporary (guest) device: drops out by itself after 24 hours",
  "Davetteki etiketler hazır gelir. Değiştirirsen davetin etiketlerinin yerine geçer; boş bırakmak hepsini kaldırır.":
    "The invite's tags are filled in. If you change them, they replace the invite's tags; leaving it empty removes them all.",
  "Kodlar aynı, onayla": "Codes match, approve",
  "Davet iptal edildi.": "Invite revoked.",
  "Daveti iptal et": "Revoke invite",
  "Kod artık kullanılamaz. Bekleyen istek varsa düşer.": "The code can no longer be used. Any pending request is dropped.",

  // welcome/welcome-view.tsx
  "Yalnızca harf, rakam, boşluk ve tire": "Only letters, digits, spaces and hyphens",
  "Katılım tamamlanamadı": "Joining could not be completed",
  "OpenScale'e hoş geldin": "Welcome to OpenScale",
  "Bu bilgisayar ilk cihazınsa yeni bir ağ kur. Ağın zaten varsa yönetici bilgisayardan aldığın davet koduyla katıl.":
    "If this computer is your first device, set up a new network. If you already have a network, join with an invite code from the admin computer.",
  "Yeni ağ kur": "Set up a new network",
  "Bu bilgisayar ağın yöneticisi ve buluşma noktası olur. Diğer cihazları buradan davet edersin.":
    "This computer becomes the network's admin and meeting point. You invite the other devices from here.",
  "Davet koduyla katıl": "Join with an invite code",
  "Yönetici bilgisayarda oluşturduğun davet kodunu yapıştır, ekranda çıkan kodu orada onayla.":
    "Paste the invite code you created on the admin computer, then approve the code shown on screen over there.",
  "IP adresi veya alan adı girin (port olmadan)": "Enter an IP address or domain (without a port)",
  "En az 12 karakter": "At least 12 characters",
  "Parolalar aynı değil": "The passphrases do not match",
  "Ağ kuruldu. Tünel ve koordinatör başlatılıyor.": "Network set up. Starting the tunnel and coordinator.",
  "Kök anahtar bu bilgisayarda parolayla şifrelenmiş olarak saklanır. Cihaz eklemek ve kural değiştirmek her zaman bu parolayı ister.":
    "The root key is kept on this computer, encrypted with a passphrase. Adding devices and changing rules always asks for this passphrase.",
  "Bu bilgisayarın adı": "This computer's name",
  "Bu bilgisayarın adresi": "This computer's address",
  "Diğer cihazlar bu bilgisayara bu adresle ulaşır. Aynı evdeki cihazlar için yerel IP yeterli. Dışarıdan bağlanacaksan modemde port yönlendirmesi yap veya dinamik DNS alan adını yaz.":
    "Other devices reach this computer at this address. For devices in the same home, the local IP is enough. To connect from outside, set up port forwarding on the router or enter a dynamic DNS domain.",
  "En az 12 karakter. Kaybolursa ağ yönetilemez; güvenli bir yere not al.":
    "At least 12 characters. If it is lost, the network cannot be managed; write it down somewhere safe.",
  "Parola tekrar": "Repeat passphrase",
  "Bütün cihazlar birbirine her porttan erişebilsin": "Let all devices reach each other on every port",
  "Kapalıysa ağ kuralsız başlar ve her şey reddedilir; erişimi Erişim kuralları sayfasından tek tek açarsın. Açmak kolay başlangıç sağlar ama bir cihaz ele geçirilirse diğerlerinin tüm portlarına ulaşılabilir.":
    "If off, the network starts without rules and everything is denied; you open access one by one on the Access rules page. Turning it on makes starting easy, but if one device is compromised, every port of the others can be reached.",
  "Anahtarlar oluşturuluyor...": "Creating keys...",
  "Ağı kur": "Set up the network",
  "Davet kodu gerekli": "The invite code is required",
  "Davet kodu osinv1. ile başlar": "An invite code starts with osinv1.",
  "Yönetici bilgisayarda Cihazlar > Cihaz davet et ile bir kod oluştur ve buraya yapıştır. Kodu yalnızca kendin taşı; e-postayla veya başkasının eliyle gönderme.":
    "On the admin computer, create a code with Devices > Invite a device and paste it here. Carry the code only yourself; do not send it by email or through someone else.",
  "Davet kodu": "Invite code",
  "Yönetici onaylarken adı değiştirebilir.": "The admin can change the name when approving.",
  Katıl: "Join",

  // welcome/joining-card.tsx
  "Yönetici onayı bekleniyor": "Waiting for admin approval",
  "Yönetici bilgisayarda OpenScale'i aç ve {page} sayfasındaki onay bekleyen {name} isteğinde bu kodu gör.":
    "Open OpenScale on the admin computer and find this code on the pending {name} request on the {page} page.",
  "Kodlar aynıysa orada Onayla'ya bas. Farklıysa onaylama: istek başka bir cihazdan gelmiş demektir.":
    "If the codes match, press Approve there. If they differ, do not approve: the request came from another device.",
  "Ağa bağlanılıyor": "Connecting to the network",
  "Koordinatöre ulaşılıyor. Bu bir dakikadan uzun sürerse yönetici bilgisayarın açık olduğundan ve aynı ağda veya internetten erişilebilir olduğundan emin ol.":
    "Reaching the coordinator. If this takes more than a minute, make sure the admin computer is on and reachable on the same network or from the internet.",
  Bağlanılıyor: "Connecting",

  // setup/missing-steps.tsx, setup/device-preview.tsx
  "Eksik adımlar": "Missing steps",
  "Eksik adımlar ({count})": "Missing steps ({count})",
  "İlk cihazın bekleniyor": "Waiting for your first device",
  "Aralarında kural var": "There is a rule between them",
  "Henüz kural yok": "No rule yet",
  "İkinci cihazın bekleniyor": "Waiting for your second device",

  // setup/setup-wizard.tsx
  "İlk cihaz": "First device",
  "İkinci cihaz": "Second device",
  "Bağlantı testi kuralı": "Connection test rule",
  "OpenScale'i zaten biliyor musun?": "Already know OpenScale?",
  "Panele geç": "Go to the panel",
  "Adım {current} / {total}": "Step {current} of {total}",
  "Adım {n}": "Step {n}",
  "Çalışıyor, panele geç": "It works, go to the panel",
  "Tüneller açık, devam": "Tunnels are up, continue",
  "Sonra yap, devam": "Do it later, continue",
  "Kök anahtarını yedekle": "Back up your root key",
  "Kök anahtar ağının tek yetkilisidir ve yalnızca bu bilgisayarda durur. Yedek ayrı bir parolayla şifrelenir; bir USB belleğe veya başka bir diske kaydet. Bu bilgisayar bozulursa ağın yedekten geri gelir.":
    "The root key is the only authority over your network and lives only on this computer. The backup is encrypted with a separate passphrase; save it to a USB stick or another disk. If this computer breaks, your network comes back from the backup.",
  "Kök anahtarın yedeği alınmış.": "The root key has been backed up.",
  "Yedeği şimdi al": "Back up now",
  "Kurulumu yarıda bırakırsan sihirbaz bir dahaki açılışta bu adımdan devam eder.":
    "If you leave the setup halfway, the wizard continues from this step next time it opens.",
  "Koordinatörünü bağla": "Connect your coordinator",
  "Koordinatör, cihazlarının birbirini bulduğu buluşma noktasıdır. Kendi VPS'inde veya ev sunucunda çalışır; ağ belgesini değiştiremez ve trafiğini göremez. Sunucuda şu komutu çalıştırıp çıkan bilgileri aşağıya gir:":
    "The coordinator is the meeting point where your devices find each other. It runs on your own VPS or home server; it cannot change the network document or see your traffic. Run this command on the server and enter the details it prints below:",
  "Koordinatör tanımlı: {endpoint}": "Coordinator set: {endpoint}",
  "İlk cihazını ekle": "Add your first device",
  "Sıra ikinci cihazında": "Now your second device",
  "Ağdaki her cihaz kendi özel IP adresini ve adını alır. Eklemek istediğin bilgisayarda anahtarları üret; özel anahtarlar o cihazdan hiç çıkmaz.":
    "Every device on the network gets its own private IP address and name. Generate the keys on the computer you want to add; private keys never leave that device.",
  "Ağdaki her cihaz kendi özel IP adresini ve adını alır. Eklemek istediğin ikinci cihazda anahtarları üret; özel anahtarlar o cihazdan hiç çıkmaz.":
    "Every device on the network gets its own private IP address and name. Generate the keys on the second device you want to add; private keys never leave that device.",
  "{name} eklendi · {ip}": "{name} added · {ip}",
  "Kayıt isteğini yapıştır": "Paste the enrollment request",
  "Cihazın ekranındaki parmak izini panelde elle yazman istenecek.":
    "You will be asked to type the fingerprint shown on the device's screen into the panel.",
  "Bağlantı testi için kural oluştur": "Create a rule for the connection test",
  "OpenScale'de varsayılan olarak her şey kapalıdır. Test için {from} cihazının {to} cihazına ping atabilmesine izin veren bir kural imzalayalım. Diğer erişimleri daha sonra Erişim Kontrolü'nden eklersin.":
    "In OpenScale everything is closed by default. For the test, let's sign a rule that allows {from} to ping {to}. You add other access later in Access Control.",
  "{from} → {to} ICMP kuralı var": "{from} → {to} ICMP rule exists",
  "Bağlantı testi": "Connection test",
  "{from} → {to} ping kuralını oluştur": "Create the {from} → {to} ping rule",
  "Önce iki cihaz ekle.": "Add two devices first.",
  "Cihazlarını ağa kat ve tüneli aç": "Join your devices and bring the tunnel up",
  "Katılım paketini her cihaza kopyala. Paketin gerçekten senin ağından geldiğini, komuttaki kök parmak izi kanıtlar:":
    "Copy the join bundle to every device. The root fingerprint in the command proves the bundle really comes from your network:",
  "1. Her cihazda paketle ağa katıl": "1. Join the network with the bundle on each device",
  "2. Yönetici yetkisiyle tüneli aç (Windows: yönetici PowerShell, Linux: sudo)":
    "2. Bring the tunnel up with administrator rights (Windows: administrator PowerShell, Linux: sudo)",
  "Bu bilgisayar da bir cihazsa, panelde yaptığın değişiklikleri koordinatöre anında iletmesi için:":
    "If this computer is also a device, so it passes the changes you make in the panel to the coordinator right away:",
  "ağ klasörü": "network folder",
  "Bağlantıyı test edelim": "Let's test the connection",
  "Cihazların birbirini görebiliyor mu? Kısa bir ping yeterli.": "Can your devices see each other? A short ping is enough.",
  "{from} cihazından {to} cihazına ping at. Bağlantı çalışıyorsa yanıt gelir.":
    "Ping {to} from {from}. If the connection works, you get a reply.",
  "<ikinci cihazın IP'si>": "<second device's IP>",
  "Yanıt gelmiyorsa: iki cihazda da `openscale up` çalışıyor mu, koordinatör portu (51820/UDP) açık mı ve belge sürümleri aynı mı kontrol et. Ters yönde ping için ayrıca kural gerekir.":
    "If there is no reply, check that `openscale up` runs on both devices, the coordinator port (51820/UDP) is open and the document versions match. A ping in the other direction needs its own rule.",
}
