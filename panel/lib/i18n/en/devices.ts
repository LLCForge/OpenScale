// English texts (#224), keyed by the Turkish source text. See lib/i18n/i18n.tsx.

export const enDevices: Record<string, string> = {
  // Devices list (devices-view)
  "Çıkış düğümleri": "Exit nodes",
  "Süresi yaklaşan": "Expiring soon",
  "{count} cihaz": "{count} device|{count} devices",
  "Anahtar yenileme isteği": "Key rotation request",
  "Cihaz ekle": "Add device",
  "Davet kodu oluştur": "Create an invite code",
  "Yeni bilgisayarda kodu yapıştır, kısa kodu onayla": "Paste the code on the new computer, approve the short code",
  "Konuk ekle": "Add guest",
  "Tek cihaza, süreli erişimle davet": "Invite with time-limited access to one device",
  "Kayıt isteğiyle ekle": "Add with an enrollment request",
  "openscale keygen çıktısını yapıştır": "Paste the output of openscale keygen",
  "Adım adım kurulum ve bağlantı testi": "Step-by-step setup and connection test",
  "Ad, IP, DNS adı, sistem veya etiket": "Name, IP, DNS name, system or tag",
  "Cihaz ara": "Search devices",
  "Kısayol: eğik çizgi": "Shortcut: slash",
  Filtre: "Filter",
  "Listeyi yenile": "Refresh the list",
  "Henüz cihaz yok": "No devices yet",
  "Kurulum sihirbazı ilk cihazını eklemen için gereken komutları adım adım gösterir.":
    "The setup wizard shows, step by step, the commands you need to add your first device.",
  "İptal edilmiş cihazlar ({count})": "Revoked devices ({count})",
  "Üyelik bakımı": "Membership maintenance",
  "{name} cihazını ağdan çıkar": "Remove {name} from the network",
  "Bu işlem geri alınamaz: cihazın anahtarları kalıcı olarak iptal edilir. Yalnızca çıkış düğümü rolünü kaldırmak istiyorsan bunu kullanma. Cihaz geri gelmek isterse kendini sıfırlayıp yeni davetle katılması gerekir.":
    "This cannot be undone: the device's keys are revoked permanently. Do not use this if you only want to remove the exit node role. To come back, the device must reset itself and join with a new invite.",
  "İmzala ve çıkar": "Sign and remove",
  "{name} çıkış düğümü olmasın": "Stop using {name} as an exit node",
  "{name} çıkış düğümü olsun": "Make {name} an exit node",
  "Rol ağ belgesine imzalanır. Linux cihazlar (sunucular) iletim ve NAT'ı kendisi açar; Windows çıkış düğümü henüz desteklenmiyor.":
    "The role is signed into the network document. Linux devices (servers) turn on forwarding and NAT themselves; Windows exit nodes are not supported yet.",
  "{what} kopyalandı.": "{what} copied.",
  "Eşleşen cihaz yok": "No matching devices",
  "Aramayı veya filtreyi değiştir.": "Change the search or the filter.",
  Adresler: "Addresses",
  "{name} için işlemler": "Actions for {name}",
  "Çıkış düğümü olmasın": "Stop being an exit node",
  "Çıkış düğümü yap": "Make exit node",
  "Üyeliği uzat…": "Extend membership…",
  "IPv4 adresi": "IPv4 address",
  "IPv4 adresini kopyala": "Copy IPv4 address",
  "DNS adı": "DNS name",
  "DNS adını kopyala": "Copy DNS name",
  "Emekliye ayır…": "Retire…",
  "Önce bütün başvurularını gösterir": "Shows every reference to it first",
  "Ağdan çıkar…": "Remove from network…",
  "Kalıcı; anahtarlar iptal edilir": "Permanent; the keys are revoked",
  "Süresi doldu {date}": "Expired {date}",
  "Süresi doluyor {date}": "Expires {date}",
  "Bilgi yok": "No information",
  "Yönetici bilgisayardaki sürüm {version}; bu cihazı güncelleyin.": "The admin computer runs version {version}; update this device.",
  "Eski sürüm": "Outdated",
  "Kısa ad": "Short name",
  "Genel IP": "Public IP",
  "{name} adresleri: {ip}": "{name} addresses: {ip}",
  "Adlar yalnızca ağ içinde .{domain} altında çözülür": "Names resolve only inside the network, under .{domain}",

  // Add device (add-device-dialog)
  "Kayıt isteği gerekli": "Enrollment request is required",
  "Kayıt isteği çok uzun": "The enrollment request is too long",
  "Bu bir OpenScale kayıt isteği değil; 'osreq1.' ile başlamalı": "This is not an OpenScale enrollment request; it must start with 'osreq1.'",
  "Cihaz adı gerekli": "Device name is required",
  "En fazla 63 karakter": "At most 63 characters",
  "Küçük harf, rakam ve tire kullan; tire ile başlayıp bitemez": "Use lowercase letters, digits and hyphens; it cannot start or end with a hyphen",
  "En fazla 3650 gün": "At most 3650 days",
  "Kod çok uzun": "The code is too long",
  "1/3: Yeni cihazın kayıt isteğini yapıştır ya da yerel ağdaki istekler arasından seç.":
    "1/3: Paste the new device's enrollment request or pick one of the requests on the local network.",
  "2/3: Yeni cihazın ekranındaki kısa kodu kendin yaz. Panel bu kodu sana göstermez.":
    "2/3: Type the short code shown on the new device's screen yourself. The panel does not show you this code.",
  "2/3: Yeni cihazın ekranındaki parmak izini kendin yaz. Panel bu değeri sana göstermez.":
    "2/3: Type the fingerprint shown on the new device's screen yourself. The panel does not show you this value.",
  "3/3: Değişikliği kontrol et ve kök anahtarınla imzala.": "3/3: Check the change and sign it with your root key.",
  "İsteği yapıştır": "Paste the request",
  "Yakındaki istekler": "Nearby requests",
  "İsteğin geldiği yer": "Where the request comes from",
  "Kayıt isteği": "Enrollment request",
  "Yeni cihazda 'openscale keygen' çalıştır. İstek yalnızca açık anahtarları içerir ve 24 saat geçerlidir.":
    "Run 'openscale keygen' on the new device. The request holds only public keys and is valid for 24 hours.",
  "İsteği doğrula": "Verify request",
  "Kod 20 rakamdan oluşur; yeni cihazın ekranındakinin tamamını yaz": "The code has 20 digits; type all of it from the new device's screen",
  "Kodlar aynıysa onaylayın; farklıysa cihazı eklemeyin": "Confirm if the codes match; if they differ, do not add the device",
  "Parmak izi XXXX-XXXX-XXXX-XXXX biçiminde olmalı": "The fingerprint must look like XXXX-XXXX-XXXX-XXXX",
  "İstek doğrulandı. Cihaz kimliği": "Request verified. Device ID",
  "Ağda bu adla görünür, ör. laptop.openscale.internal": "Shown on the network under this name, e.g. laptop.openscale.internal",
  "Yeni cihazın ekranındaki kod": "Code on the new device's screen",
  "Yeni cihazda \"openscale key sas\" komutunun gösterdiği kodu yaz. Kod tutmazsa istek yolda değiştirilmiştir ve cihaz eklenmez.":
    "Type the code shown by \"openscale key sas\" on the new device. If the code does not match, the request was altered on the way and the device is not added.",
  "Parmak izi yerine kısa kodu karşılaştır": "Compare the short code instead of the fingerprint",
  "Yeni cihazda \"openscale key sas\" komutunun gösterdiği 20 haneli kodla karşılaştırılır.":
    "Compared with the 20-digit code shown by \"openscale key sas\" on the new device.",
  "Kısa doğrulama kodu": "Short verification code",
  "Yeni cihazın ekranındaki kod bununla birebir aynı": "The code on the new device's screen is exactly the same",
  "Bir hane bile farklıysa istek yolda değiştirilmiştir; cihazı eklemeyin.": "If even one digit differs, the request was altered on the way; do not add the device.",
  "Parmak izi": "Fingerprint",
  "Yeni cihazın ekranında yazanı gir. Eşleşmezse istek yolda değiştirilmiş olabilir ve cihaz eklenmez.":
    "Enter what the new device's screen shows. If it does not match, the request may have been altered on the way and the device is not added.",
  "Üyelik süresi (gün)": "Membership length (days)",
  "Çıkış düğümü olabilir": "Can be an exit node",
  "Diğer cihazlar internet trafiğini bu cihaz üzerinden çıkarabilir.": "Other devices can send their internet traffic out through this device.",

  // Guest wizard (guest-wizard)
  "Dosya gönderme": "File sending",
  "Tek port": "Single port",
  "2 saat": "2 hours",
  "8 saat": "8 hours",
  "1 gün": "1 day",
  "3 gün": "3 days",
  "7 gün": "7 days",
  "En fazla 60 karakter": "At most 60 characters",
  "Hedef cihazı seç": "Choose the target device",
  "En az 1 saat": "At least 1 hour",
  "En fazla 168 saat": "At most 168 hours",
  "Konuk daveti hazır": "Guest invite is ready",
  "Konuğun cihazı yalnızca seçtiğin cihazın seçtiğin hizmetine, seçtiğin süre boyunca erişebilir. Süre dolunca kural çalışmaz.":
    "The guest's device can reach only the service you choose on the device you choose, for the time you choose. When the time runs out, the rule stops working.",
  "Davet ve süreli kural aynı imzayla yayımlanır. Değişikliği kontrol et.": "The invite and the time-limited rule are published with one signature. Check the change.",
  "Kodu konuğa ver. Cihazını onaylarken 'geçici' seçili kalsın; cihaz da konuk süresi bitince düşer.":
    "Give the code to the guest. Keep 'temporary' selected when you approve their device; the device then drops off when the guest time ends.",
  "İmzala ve davet oluştur": "Sign and create invite",
  "Davet kodunu kopyala": "Copy invite code",
  "Davet {date} tarihine kadar kullanılabilir.": "The invite can be used until {date}.",
  "Konuk erişimi {date} tarihinde biter.": "Guest access ends on {date}.",
  "Davet, konuk süresinden uzun olamaz": "The invite cannot last longer than the guest access",
  "Port 1 ile 65535 arasında olmalı": "The port must be between 1 and 65535",
  "Konuğun girebileceği en az bir hesap yaz": "Enter at least one account the guest can sign in to",
  "Konuk (isteğe bağlı)": "Guest (optional)",
  "Teknik servis": "Technical support",
  "Kuralın açıklamasına yazılır; kimin için açıldığını hatırlatır.": "Written into the rule's description; reminds you who it was opened for.",
  "Erişeceği cihaz": "Device to reach",
  Hizmet: "Service",
  Hesaplar: "Accounts",
  destek: "support",
  "Konuğun SSH ile girebileceği hesaplar; virgülle ayır.": "Accounts the guest can sign in to over SSH; separate with commas.",
  Protokol: "Protocol",
  "Konuk erişimi süresi": "Guest access length",
  "Davet kodu kaç saat geçerli": "Hours the invite code stays valid",
  "Konuk kodu bu süre içinde kullanmalı; kısa süre daha güvenli.": "The guest must use the code within this time; shorter is safer.",

  // Access requests (access-requests-view)
  "openscale access request --to <cihaz> --service ssh --users <hesap> --hours 8":
    "openscale access request --to <device> --service ssh --users <account> --hours 8",
  Bekliyor: "Pending",
  Onaylandı: "Approved",
  Reddedildi: "Rejected",
  "{count} bekliyor": "{count} pending",
  "Cihazların kendi anahtarıyla imzaladığı süreli erişim istekleri. Onaylarsan süreli bir kural imzalanır; süre dolunca kendiliğinden geçersiz olur.":
    "Time-limited access requests that devices signed with their own key. If you approve, a time-limited rule is signed; it stops working by itself when the time runs out.",
  "İstek yok": "No requests",
  "Erişim istemek için kişi kendi cihazında şu komutu çalıştırır ve çıkan satırı sana iletir:":
    "To ask for access, the person runs this command on their own device and sends you the line it prints:",
  "Komutu kopyala": "Copy command",
  Bekleyenler: "Pending",
  Yanıtlananlar: "Answered",
  "Bu bir OpenScale erişim isteği değil; 'osreq1.' ile başlamalı.": "This is not an OpenScale access request; it must start with 'osreq1.'.",
  "Bu istek zaten listede.": "This request is already in the list.",
  "İstek doğrulandı ve listeye eklendi.": "Request verified and added to the list.",
  "İstek ekle": "Add request",
  "Erişim isteği satırı": "Access request line",
  "Kişinin cihazındaki {command} komutunun çıktısını yapıştır. İstek cihazın anahtarıyla doğrulanır; eklemek hiçbir şeyi onaylamaz.":
    "Paste the output of the {command} command from the person's device. The request is verified with the device's key; adding it approves nothing.",
  "İsteği doğrula ve ekle": "Verify and add request",
  "İstek reddedildi.": "Request rejected.",
  "{from}, {to} cihazına {count} saat {access} erişimi istiyor.":
    "{from} asks for {access} access to {to} for {count} hour.|{from} asks for {access} access to {to} for {count} hours.",
  "Gerekçe: {reason}": "Reason: {reason}",
  "Bu istek artık doğrulanamıyor: {error}": "This request can no longer be verified: {error}",
  "Bu istek artık doğrulanamıyor.": "This request can no longer be verified.",
  "Geldi: {date}": "Received: {date}",
  "Yanıt: {date}": "Answered: {date}",
  "Onayla…": "Approve…",
  "{name} için erişimi onayla": "Approve access for {name}",
  "{to} cihazına {access} erişimi için süreli bir kural imzalanır. Süre yalnızca kısaltılabilir.":
    "A time-limited rule for {access} access to {to} is signed. The duration can only be shortened.",
  "İstenen süre ({count} saat)": "Requested duration ({count} hour)|Requested duration ({count} hours)",
  "{count} saat": "{count} hour|{count} hours",

  // Lost device (lost-device-dialog)
  "Kayıp cihaz: {name}": "Lost device: {name}",
  "Cihazın ağda neye ulaşabildiğine bak, sonra onu ağdan çıkar. Değişiklik imzalanana kadar hiçbir şey değişmez.":
    "See what the device can reach on the network, then remove it. Nothing changes until the change is signed.",
  "Cihazın anahtarları kalıcı olarak iptal edilir ve adı geçtiği her yerden kaldırılır. Geri gelmesi için yeni davetle katılması gerekir.":
    "The device's keys are revoked permanently and its name is removed everywhere it appears. To come back, it must join with a new invite.",
  "Üyelik şimdi biter; cihaz yeni bağlantı kuramaz. Anahtarları iptal edilmez, üyelik sonradan uzatılabilir.":
    "The membership ends now; the device cannot open new connections. Its keys are not revoked, and the membership can be extended later.",
  "İmzala ve kalıcı olarak çıkar": "Sign and remove permanently",
  "İmzala ve üyeliği bitir": "Sign and end membership",
  "Cihazın erişimleri yükleniyor": "Loading the device's access",
  "Yönlendirdiği ağlar": "Routed networks",
  "Bu cihazın erişebildikleri": "What this device can reach",
  "Bu cihaz başka cihaza bağlantı başlatamıyor.": "This device cannot open connections to other devices.",
  "Bu cihaza erişebilenler": "What can reach this device",
  "Hiçbir cihaz bu cihaza bağlanamıyor.": "No device can connect to this device.",
  "Değiştirilmesi gereken parolalar": "Passwords to change",
  "Bu liste yalnızca bu sayfada tutulur; işaretlediklerin hiçbir yere kaydedilmez.": "This list lives only on this page; what you tick is not saved anywhere.",
  "Ne yapılsın": "What to do",
  "Kayıp cihaz için işlem": "Action for the lost device",
  "Kalıcı olarak çıkar (önerilen)": "Remove permanently (recommended)",
  "Anahtarlar iptal edilir, cihaz adının geçtiği kurallar ve gruplar temizlenir. Geri alınamaz.":
    "The keys are revoked, and rules and groups that name the device are cleaned up. This cannot be undone.",
  "Yalnızca üyeliği bitir": "Only end the membership",
  "Cihazın geri bulunma ihtimali varsa. Cihaz belgede kalır; üyelik uzatılınca yeniden bağlanır.":
    "If the device may be found again. The device stays in the document; it reconnects when the membership is extended.",
  "Yalnızca bu cihaz için kalan kuralları da sil": "Also delete rules left only for this device",
  "Başka cihazların da geçtiği kurallar olduğu gibi kalır.": "Rules that also name other devices stay as they are.",
  "Cihaz çıkınca bu kural boş kalır ve silinir.": "Once the device is removed this rule is empty and is deleted.",

  // Key rotation (key-rotation-dialog)
  "Anahtar yenileme isteği gerekli": "Key rotation request is required",
  "İstek çok uzun": "The request is too long",
  "Bu bir OpenScale anahtar yenileme isteği değil; 'osrot1.' ile başlamalı": "This is not an OpenScale key rotation request; it must start with 'osrot1.'",
  "1/3: Cihazın ürettiği anahtar yenileme isteğini yapıştır.": "1/3: Paste the key rotation request the device created.",
  "2/3: Cihazın ekranındaki yeni parmak izini kendin yaz. Panel bu değeri sana göstermez.":
    "2/3: Type the new fingerprint shown on the device's screen yourself. The panel does not show you this value.",
  "İmzala ve {name} anahtarlarını yenile": "Sign and rotate the keys of {name}",
  "Anahtar çalınmış olabilir mi?": "Could the key have been stolen?",
  "Yenileme, cihazın kendi isteğiyle anahtarlarını değiştirir. Cihazın veya anahtarının ele geçirilmiş olabileceğinden şüpheleniyorsan yenileme yapma: cihazı ağdan kalıcı olarak çıkar ve sıfırlayıp yeni bir davetle yeniden ekle.":
    "Rotation replaces the device's keys at its own request. If you suspect the device or its key may be compromised, do not rotate: remove the device from the network permanently, reset it and add it again with a new invite.",
  "Bu istek {name} cihazına ait, {expected} cihazına değil. Doğru isteği yapıştır.": "This request belongs to {name}, not to {expected}. Paste the right request.",
  "İstek yalnızca açık anahtarları içerir ve cihazın mevcut anahtarıyla imzalıdır.": "The request holds only public keys and is signed with the device's current key.",
  "Cihaz kimliği": "Device ID",
  "İstek zamanı": "Request time",
  "Yeni parmak izi": "New fingerprint",
  "Cihazın ekranında yazanı gir. Eşleşmezse istek yolda değiştirilmiş olabilir ve anahtarlar yenilenmez.":
    "Enter what the device's screen shows. If it does not match, the request may have been altered on the way and the keys are not rotated.",

  // Like another device (like-device-dialog)
  "{name} başka bir cihaz gibi olsun": "Make {name} like another device",
  "Şu cihaz gibi yap": "Make like a device",
  "Seçtiğin cihazın etiketlerini, gruplarını, kurallarını ve çıkış iznini öneri olarak getiriyoruz. İstemediklerinin işaretini kaldır; hiçbir şey sen imzalamadan değişmez.":
    "We bring the tags, groups, rules and exit permission of the device you pick as a suggestion. Untick what you do not want; nothing changes until you sign.",
  "Değişikliği kontrol et ve kök anahtarınla imzala.": "Check the change and sign it with your root key.",
  "Örnek alınacak cihaz": "Device to copy from",
  "Öneri hazırlanıyor": "Preparing the suggestion",
  "Etiketler geçersiz": "The tags are not valid",
  "{name} cihazında aktarılacak etiket, grup, kural veya çıkış izni yok.": "{name} has no tags, groups, rules or exit permission to copy.",
  Etiketler: "Tags",
  "Önerilen etiketler; ekleyip çıkarabilirsin. Virgülle ayır, en fazla {max}.": "Suggested tags; you can add or remove some. Separate with commas, at most {max}.",
  Gruplar: "Groups",
  Kurallar: "Rules",
  "Kaynak cihazın adı geçen kurallar; yeni cihaz da bu kurallara eklenir.": "Rules that name the source device; the new device is added to them too.",
  "Çıkış düğümü kullanabilsin": "Can use exit nodes",

  // Extend membership (extend-membership-dialog)
  "Gün sayısı gir": "Enter a number of days",
  "{name} üyeliğini uzat": "Extend membership of {name}",
  "Yeni bitiş tarihini kontrol et ve kök anahtarınla imzala.": "Check the new end date and sign it with your root key.",
  "Süresi dolan cihaz yeni bağlantı kuramaz. Yeni süre imzadan önce değişiklik listesinde tarih olarak görünür.":
    "An expired device cannot open new connections. Before you sign, the new length shows as a date in the change list.",
  "İmzala ve uzat": "Sign and extend",
  "{count} gün": "{count} day|{count} days",
  "1 ile 3650 gün arası.": "Between 1 and 3650 days.",

  // Guests (guests-view)
  "{count} etkin": "{count} active",
  "Süreli konuk erişimleri: bir davet ve yalnızca seçilen cihaza, seçilen süre boyunca izin veren bir kural.":
    "Time-limited guest access: an invite and a rule that allows only the chosen device, for the chosen time.",
  "Konuk yok": "No guests",
  "Bir misafire veya teknik servise tek cihazın tek hizmetine birkaç saatlik erişim vermek için Konuk ekle'yi kullan. Süre dolunca kural kendiliğinden çalışmaz.":
    "Use Add guest to give a visitor or a technician a few hours of access to one service on one device. When the time runs out, the rule stops working by itself.",
  "Konuk erişimi": "Guest access",
  Süresiz: "No end",
  "Davet {date} tarihine kadar bekliyor": "Invite waiting until {date}",
  Katılmadı: "Not joined",

  // Rename device (rename-device-dialog)
  "\"coordinator\" adı koordinatöre ayrılmıştır": "The name \"coordinator\" is reserved for the coordinator",
  "Yeni ad eskisiyle aynı": "The new name is the same as the old one",
  "{name} cihazını yeniden adlandır": "Rename {name}",
  "Cihazın kimliği, adresleri ve anahtarları değişmez; yalnızca adı değişir.": "The device's identity, addresses and keys stay the same; only its name changes.",
  "İmzala ve yeniden adlandır": "Sign and rename",
  "MagicDNS adı da değişir: {address} artık çözülmez. Eski adı kullanan kayıtlı bağlantılar (ör. Uzak Masaüstü kısayolları, SSH yapılandırmaları) bozulur; onları yeni adla güncelle.":
    "The MagicDNS name changes too: {address} no longer resolves. Saved connections that use the old name (e.g. Remote Desktop shortcuts, SSH configurations) break; update them with the new name.",
  "Yeni ad": "New name",
  "Küçük harf, rakam ve tire; en fazla 63 karakter.": "Lowercase letters, digits and hyphens; at most 63 characters.",

  // Device tags (device-tags-dialog)
  "{name} etiketleri": "Tags of {name}",
  "Erişim kuralları, gruplar ve çıkış düğümü kullanıcıları cihazlara tag:ad biçiminde etiketle başvurabilir.":
    "Access rules, groups and exit node users can refer to devices by tag, written as tag:name.",
  "Etiketler değişmedi": "The tags did not change",
  "sunucu, ofis": "server, office",
  "Virgül veya boşlukla ayır; \"tag:\" öneki isteğe bağlı. En fazla {max} etiket. Boş bırakırsan bütün etiketler kaldırılır.":
    "Separate with commas or spaces; the \"tag:\" prefix is optional. At most {max} tags. Leave it empty to remove all tags.",

  // Nearby requests (nearby-requests)
  "Yeni cihazda {command} çalıştır. Aynı ağdaki istekler burada görünür. Listede adı olan herkes istek gönderebilir; yalnızca yeni cihazın ekranındaki kodu yazarak onayla.":
    "Run {command} on the new device. Requests on the same network show up here. Anyone listed can send a request; approve only by typing the code shown on the new device's screen.",
  "Dinleniyor; {time} saatinde kendiliğinden kapanır": "Listening; stops by itself at {time}",
  Dinlemiyor: "Not listening",
  "Dinlemeyi durdur": "Stop listening",
  "Yerel ağı 5 dakika dinle": "Listen on the local network for 5 minutes",
  "Bu cihazı ekle": "Add this device",
  "Henüz istek yok. Yeni cihazda komutu çalıştırdıysan birkaç saniye bekle.": "No requests yet. If you ran the command on the new device, wait a few seconds.",
  "İlk kullanımda Windows güvenlik duvarı izin isteyebilir; yalnızca özel ağlarda izin ver.":
    "On first use Windows Firewall may ask for permission; allow it only on private networks.",

  // Retire device (retire-device-dialog)
  "{name} cihazını emekliye ayır": "Retire {name}",
  "Cihazın anahtarları kalıcı olarak iptal edilir ve aşağıdaki bütün başvurular aynı imzada temizlenir. Bu işlem geri alınamaz; cihaz geri gelmek isterse yeni davetle katılmalı.":
    "The device's keys are revoked permanently and every reference below is cleaned up in the same signature. This cannot be undone; to come back, the device must join with a new invite.",
  "İmzala ve emekliye ayır": "Sign and retire",
  "Emekliye ayırma önizlemesi": "Retirement preview",
  "Belgede bu cihaza başka başvuru yok.": "Nothing else in the document refers to this device.",
  "İmzayla temizlenir": "Cleaned up by the signature",
  "İmzayla birlikte temizlenecek girdi:": "Entries cleaned up with the signature:",
}
