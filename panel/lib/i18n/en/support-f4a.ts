// English texts of ADR-0232 (#233 device icons, #243 IoT and camera
// isolation templates, #852 remote support toolbox), keyed by the Turkish
// source text. See lib/i18n/i18n.tsx.

export const enSupportF4A: Record<string, string> = {
  // Device icons (devices/device-icon.tsx)
  "Cihaz türü": "Device type",
  Kamera: "Camera",
  NAS: "NAS",
  Tablet: "Tablet",
  Telefon: "Phone",
  Televizyon: "TV",
  Yazıcı: "Printer",
  "Simge…": "Icon…",
  "Simgeyi kaldır": "Remove icon",
  "{name} simgesi": "{name} icon",
  "Simge imzalı ağ belgesine yazılır; panel ve tepsi cihazı bu türle gösterir. İlk simge asgari istemci sürümünü 1.0.0-beta.2 yapar.":
    "The icon is written into the signed network document; the panel and the tray show the device with this type. The first icon raises the minimum client version to 1.0.0-beta.2.",

  // Firewall templates (rules/firewall-templates.tsx)
  "Güvenlik duvarı şablonları": "Firewall templates",
  "Hazır paketler sıradan imzalı kurallar üretir; önce önizlemede neyin değiştiğini görürsün.":
    "Ready-made packages produce ordinary signed rules; the preview shows what changes first.",
  Şablon: "Template",
  Konu: "Subject",
  "Konu gerekli": "A subject is required",
  "Konu çok uzun": "The subject is too long",
  "Hedef listesi çok uzun": "The destination list is too long",
  "Port listesi çok uzun": "The port list is too long",
  Hedefler: "Destinations",
  "tag:iot veya 192.168.1.16/28": "tag:iot or 192.168.1.16/28",
  "cihaz, tag:x veya group:x": "device, tag:x or group:x",
  "Cihaz adı, tag:x veya group:x.": "A device name, tag:x or group:x.",
  "Cihaz adı, tag:x, group:x ya da bir IP/CIDR aralığı veya host:ad. Alt ağ yönlendirici arkasındaki bir aralık OpenScale kurmamış cihazları (kamera gibi) kapsar.":
    "A device name, tag:x, group:x, or an IP/CIDR range or host:name. A range behind a subnet router covers devices that do not run OpenScale (such as cameras).",
  "ha, nas": "ha, nas",
  "Konunun bağlanabileceği cihazlar; virgülle ayır.": "The devices the subject may connect to; separate with commas.",
  "8123, 1883": "8123, 1883",
  "Kendi aralarında ve internete kapalı": "Closed to each other and to the internet",
  "Konudaki cihazlar birbirine bağlanamaz ve çıkış düğümünü kullanamaz.": "The subject's devices cannot connect to each other or use exit nodes.",
  "Şablon uygulanamaz": "The template cannot be applied",
  "Eklenecek kurallar": "Rules to add",
  "Kapatılacak dar kurallar: {list}": "Narrow rules to turn off: {list}",
  "Çıkış düğümü kullanıcıları da değişir.": "The exit node users change too.",
  "Erişim değişiklikleri": "Access changes",
  açılır: "opens",
  kapanır: "closes",
  "Liste kısaltıldı.": "The list was shortened.",
  "İmzalamaya geç": "Continue to signing",
  "Şablonu imzala": "Sign the template",
  "Önizlemedeki kurallar belgeye yazılır. Belge önizlemeden sonra değiştiyse imza reddedilir; yeniden önizle.":
    "The previewed rules are written into the document. If the document changed after the preview, signing is refused; preview again.",

  // Template titles, descriptions and warnings from the server (internal/fwtemplate)
  "Yalnızca internet": "Internet only",
  "Yalnızca NAS": "NAS only",
  Misafir: "Guest",
  "IoT yalıtımı": "IoT isolation",
  "Yönetici her yere": "Admin everywhere",
  Karantina: "Quarantine",
  "Cihaz yalnızca çıkış düğümü üzerinden internete çıkar; ağdaki hiçbir cihaza bağlanamaz.":
    "The device only reaches the internet through an exit node; it cannot connect to any device in the network.",
  "Cihaz yalnızca seçilen NAS'a, seçilen portlardan bağlanır; daha geniş izinler önizlemede gösterilir.":
    "The device only connects to the chosen NAS on the chosen ports; broader permissions are shown in the preview.",
  "Misafir cihaz internete ve seçilen paylaşımlı cihazlara (yazıcı gibi) erişir; ağdaki cihazlar misafire bağlanamaz. İsteğe bağlı bitiş zamanı.":
    "The guest device reaches the internet and the chosen shared devices (such as a printer); devices in the network cannot connect to the guest. Optional end time.",
  "Akıllı cihazlar ve kameralar (alt ağ yönlendirici arkasındaki bir aralık da olabilir) yalnızca denetleyiciye (ör. Home Assistant) seçilen portlardan bağlanır; denetleyici onlara her yoldan ulaşır.":
    "Smart devices and cameras (also a range behind a subnet router) only connect to the controller (e.g. Home Assistant) on the chosen ports; the controller reaches them every way.",
  "Seçilen yönetim cihazı ağdaki her cihaza bağlanabilir.": "The chosen management device can connect to every device in the network.",
  "Cihazın ağdaki bütün bağlantıları iki yönde de kesilir; saldırı algılandığında önerilir.":
    "All of the device's connections in the network are cut in both directions; recommended when an attack is detected.",
  "Yönlendirici arkasındaki cihazlar birbirine ve internete OpenScale üzerinden ulaşamaz; ancak aynı yerel ağdaki trafik ve yönlendiricinin kendi internet çıkışı OpenScale'den geçmez. Bunları yönlendiricide veya ayrı bir VLAN ile kapatın.":
    "Devices behind the router cannot reach each other or the internet through OpenScale; but traffic within the same local network and the router's own internet access do not pass through OpenScale. Close those on the router or with a separate VLAN.",
  "Çıkış düğümü kullanıcıları listesi yoktu; şablon bütün diğer cihazlarla bir liste oluşturur. Sonradan katılan cihazları bu listeye eklemeniz gerekir.":
    "There was no exit node user list; the template creates one with every other device. Devices that join later must be added to this list.",
  "aralık ağ öneklerinin veya onaylı bir alt ağ rotasının içinde olmalı": "the range must lie inside the network prefixes or an approved subnet route",

  // Support toolbox, helper side (support/support-tools.tsx)
  "Destek araçları": "Support tools",
  "Salt okunur görünümler tünel üzerinden gelir. {name} cihazındaki kişi her oturumu onaylar ve oturum boyunca orada \"uzaktan bağlı\" göstergesi görünür.":
    "Read-only views arrive through the tunnel. The person at {name} approves every session and sees the \"remotely connected\" notice for as long as it lasts.",
  "Destek kuralı yok": "No support rule",
  "{from} cihazının {to} cihazına destek vermesi için imzalı bir support kuralı gerekir. Kural yalnızca okumaya izin verir; süreç sonlandırma ayrı bir izindir.":
    "For {from} to support {to}, a signed support rule is needed. The rule only allows reading; ending processes is a separate permission.",
  "Destek izni ver…": "Allow support…",
  "{to} için destek izni": "Support permission for {to}",
  "Ağ belgesine bir support kuralı eklenir. İlk support kuralı asgari istemci sürümünü 1.0.0-beta.2 yapar; daha eski cihazlar yeni belgeyi reddeder.":
    "A support rule is added to the network document. The first support rule raises the minimum client version to 1.0.0-beta.2; older devices reject the new document.",
  "Süreç sonlandırmaya da izin ver (support.kill)": "Also allow ending processes (support.kill)",
  "Kritik sistem süreçleri hiçbir zaman sonlandırılamaz; her sonlandırma hedefte ayrıca onaylanır.":
    "Critical system processes can never be ended; every termination is approved separately on the target.",
  "Sistem olayları": "System events",
  Hizmetler: "Services",
  Diskler: "Disks",
  "Açılış programları": "Startup programs",
  "Toplandı: {date}": "Collected: {date}",
  "Bilgi yalnızca istediğinde, karşı taraf onaylarsa toplanır.": "Information is only collected when you ask and the other side approves.",
  Getir: "Fetch",
  "Karşı cihazdaki kişinin onayı bekleniyor; en fazla bir dakika sürer.": "Waiting for the person at the other device to approve; this takes at most a minute.",
  "Bilgi alınamadı": "Could not get the information",
  "Liste uzun olduğu için kısaltıldı.": "The list was shortened because it is long.",
  "Gösterilecek bir şey yok.": "Nothing to show.",
  PID: "PID",
  "Sonlandır…": "End…",
  Sonlandır: "End",
  "{name} sonlandırıldı.": "{name} was ended.",
  "{name} sonlandırılsın mı?": "End {name}?",
  "Süreç {device} cihazında kapatılır; kaydedilmemiş çalışma kaybolabilir. Cihazdaki kişi bunu ayrıca onaylar.":
    "The process is closed on {device}; unsaved work may be lost. The person at the device approves this separately.",
  "{free} boş / {total}": "{free} free / {total}",
  "{mount} doluluk": "{mount} usage",

  // Support toolbox, target side (support/support-local-banner.tsx)
  "{peer} bu cihaza uzaktan destek vermek istiyor": "{peer} wants to give remote support to this device",
  "{peer} bu cihazda bir süreci sonlandırmak istiyor": "{peer} wants to end a process on this device",
  "İzin verirsen {peer} seçtiği bir süreci kapatabilir; kritik sistem süreçleri korunur.":
    "If you allow it, {peer} can close a process it picks; critical system processes are protected.",
  "İzin verirsen {peer} çalışan işlemleri, hizmetleri, son sistem olaylarını, disk doluluğunu ve açılış programlarını salt okunur görür. Kişisel bilgiler maskelenir.":
    "If you allow it, {peer} sees the running processes, services, recent system events, disk usage and startup programs, read-only. Personal data is masked.",
  "Uzaktan destek bağlı: {peers}": "Remote support connected: {peers}",
  "{peer}: {time} saatinden beri, salt okunur": "{peer}: since {time}, read-only",
  "{peer}: {time} saatinden beri, süreç sonlandırma dahil": "{peer}: since {time}, including ending processes",
  "Desteği kes": "Disconnect support",
  "Uzaktan destek kesildi.": "Remote support was disconnected.",

  // Server texts of the support endpoints (internal/panel/f4a_api.go, internal/support)
  "Destek araçları bu sürümde yok.": "The support tools are not in this version.",
  "Cihaz veya tür geçersiz.": "The device or kind is invalid.",
  "Süreç geçersiz.": "The process is invalid.",
  "İstek bulunamadı veya süresi geçti.": "The request was not found or has expired.",
  "Cihaz zamanında yanıt vermedi; karşıdaki kişi isteği onaylamamış olabilir.": "The device did not answer in time; the person there may not have approved the request.",
  "Cihaz adı veya simge geçersiz.": "The device name or icon is invalid.",
  "Şablon isteği geçersiz.": "The template request is invalid.",
  "bu cihaza destek izni veren bir kural yok": "there is no rule that allows support on this device",
  "bu cihazda süreç sonlandırmaya izin veren bir destek kuralı (support.kill) yok": "there is no support rule that allows ending processes on this device (support.kill)",
  "Cihaz yanıtı: cihazdaki kişi isteği onaylamadı": "Device answer: the person at the device did not approve the request",
  "Cihaz yanıtı: imzalı kurallar buna izin vermiyor": "Device answer: the signed rules do not allow this",
  "Cihaz yanıtı: bu süreç sistem için kritik; sonlandırılamaz": "Device answer: this process is critical for the system and cannot be ended",
  "Cihaz yanıtı: süreç bulunamadı veya adı değişti": "Device answer: the process was not found or its name changed",
  "Cihaz yanıtı: cihazda uzaktan bağlı göstergesi açılamadı; oturum başlatılmadı":
    "Device answer: the remotely connected notice could not be shown on the device; the session did not start",
  "Cihaz yanıtı: çok fazla istek; biraz bekleyin": "Device answer: too many requests; wait a little",
  "Cihaz yanıtı: destek araçları bu sistemde desteklenmiyor": "Device answer: the support tools are not supported on this system",
  "Cihaz simgesi tanınmıyor; laptop, desktop, phone, tablet, server, nas, printer, camera, tv, router veya other olmalı.":
    "The device icon is unknown; it must be laptop, desktop, phone, tablet, server, nas, printer, camera, tv, router or other.",
  "Bu belge eski istemcilerin reddettiği alanlar kullanıyor; asgari istemci sürümü en az 1.0.0-beta.2 olmalı.":
    "This document uses fields older clients reject; the minimum client version must be at least 1.0.0-beta.2.",
}
