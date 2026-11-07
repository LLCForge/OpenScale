// English texts (#224), keyed by the Turkish source text. See lib/i18n/i18n.tsx.

export const enRules: Record<string, string> = {
  // Rule dialog (rules/add-rule-dialog.tsx)
  "0 ile 255 arası bir IANA protokol numarası gir": "Enter an IANA protocol number between 0 and 255",
  "0 ile 255 arası bir sayı gir": "Enter a number between 0 and 255",
  "0-255 arası, ör. 47 (GRE) veya 50 (ESP). 1, 6, 17 ve 58 için adları (ICMP, TCP, UDP) kullan.":
    "0-255, e.g. 47 (GRE) or 50 (ESP). For 1, 6, 17 and 58 use the names (ICMP, TCP, UDP).",
  "1 ile 43200 dakika (30 gün) arası bir sayı gir": "Enter a number between 1 and 43200 minutes (30 days)",
  "3389 veya 5900-5910, 22": "3389 or 5900-5910, 22",
  "Boş: süresiz": "Empty: no time limit",
  "Bu kural şu an {date} tarihinde kapanıyor. Boş bırakırsan bu bitiş korunur; doldurursan imzadan bu kadar dakika sonra kapanır.":
    "This rule currently closes on {date}. Leave it empty to keep that end; fill it in and the rule closes this many minutes after signing.",
  "Bu kuralın bütün cihazlardan bütün cihazlara erişim açtığını ve varsayılan reddet ilkesini fiilen kapattığını anlıyorum":
    "I understand that this rule opens access from every device to every device and effectively turns off the default deny policy",
  "Bu kuralın saat veya başlangıç sınırı var; burada değişmez. Değiştirmek için metin düzenleyiciyi kullan.":
    "This rule has a time-of-day or start limit; it does not change here. Use the text editor to change it.",
  "Doluysa kural imzadan bu kadar dakika sonra kendiliğinden kapanır (tek seferlik erişim penceresi). Her cihaz kendi saatine göre uygular.":
    "When filled in, the rule closes by itself this many minutes after signing (a one-time access window). Each device applies it by its own clock.",
  "Dosya paylaşımı (SMB)": "File sharing (SMB)",
  "En az bir hedef seç": "Choose at least one destination",
  "En az bir kaynak seç": "Choose at least one source",
  "En fazla 43200 dakika": "At most 43200 minutes",
  "En fazla {count} hedef": "At most {count} destination|At most {count} destinations",
  "En fazla {count} kaynak": "At most {count} source|At most {count} sources",
  Eylem: "Action",
  "Hangi cihazların nereye, hangi porttan bağlanabileceğini seç.": "Choose which devices may connect where, and on which port.",
  "Hazır seçimler": "Presets",
  "Hedef (bağlanılan)": "Destination (connected to)",
  "Herkesten herkese erişim açan kural açık onay ister": "A rule that opens access from everyone to everyone needs explicit confirmation",
  "IANA protokol numarası": "IANA protocol number",
  "Kaynak (bağlanan)": "Source (connecting)",
  "Kural yerinde değişir; sırası ve açık/kapalı durumu korunur. Tek imza yeter.":
    "The rule changes in place; its position and on/off state are kept. One signature is enough.",
  "Kural {number}: düzenle": "Rule {number}: edit",
  Numara: "Number",
  "Port yalnızca TCP ve UDP için": "Ports are for TCP and UDP only",
  "Port yalnızca TCP ve UDP için girilir": "Ports can only be entered for TCP and UDP",
  Portlar: "Ports",
  "Portlar 1-65535 arası olmalı, ör. 3389 veya 5900-5910": "Ports must be between 1 and 65535, e.g. 3389 or 5900-5910",
  "Reddet kuralı her zaman izinden önce gelir: bir izin kuralı aynı trafiği kapsasa da reddedilir. Varsayılan zaten her şeyi reddettiği için reddet kuralı yalnızca geniş bir izinden istisna açmak için gerekir.":
    "A deny rule always comes before allows: the traffic is denied even if an allow rule covers it. Since the default already denies everything, a deny rule is only needed to make an exception to a broad allow.",
  "Süre sınırını kaldır: kural süresiz geçerli olsun": "Remove the time limit: the rule stays in effect with no end",
  "Süreli erişim (dakika)": "Timed access (minutes)",
  "TCP ve UDP için en az bir port gir": "Enter at least one port for TCP and UDP",
  "Çift yönlü: hedef de kaynağa aynı protokol ve portla bağlanabilsin": "Both ways: the destination may also connect to the source on the same protocol and port",
  "{number} numarası yerine \"{name}\" seçeneğini kullan": "Use the \"{name}\" option instead of number {number}",

  // Service rule dialog (rules/add-service-rule-dialog.tsx)
  "Aracı (hedefle aynı yerel ağda, açık kalan cihaz)": "Relay device (on the destination's local network, kept on)",
  "Aracı olarak tüm cihazlar seçilemez": "All devices cannot be chosen as the relay device",
  "Bir kullanıcı iki kez yazılmış": "A user is listed twice",
  "En az bir klasör kimliği yaz veya yedek iznini aç": "Enter at least one folder ID or turn on the backup permission",
  "En az bir kullanıcı yaz veya root iznini aç": "Enter at least one user or turn on the root permission",
  "En fazla {count} aracı": "At most {count} relay device|At most {count} relay devices",
  "En fazla {count} kullanıcı": "At most {count} user|At most {count} users",
  "Gözetimsiz erişim, hedefte kimse onaylamadan oturum açar. Gösterge yine görünür ve oturum günlüğe yazılır; yalnızca kendi cihazların için kullan.":
    "Unattended access opens a session without anyone approving it on the destination. The indicator still shows and the session is logged; use it only for your own devices.",
  "Gözetimsiz: hedefteki kişinin onayını bekleme": "Unattended: do not wait for approval from the person at the destination",
  "Hedef (servisi sunan)": "Destination (offering the service)",
  "Hedef (uyandırılacak)": "Destination (to wake)",
  "Hedefin Eşitleme sayfasında paylaştığı klasörlerin kimlikleri; virgülle. Eşitleme yalnızca çekmedir, kaynak hedefe yazamaz.":
    "IDs of the folders the destination shares on its Sync page, separated by commas. Sync only pulls; the source cannot write to the destination.",
  "Hedefin yerel ağındaki en az bir aracı cihaz seç": "Choose at least one relay device on the destination's local network",
  "Hedefte kaynaktan şifreli yedek tutulsun": "Keep an encrypted backup of the source on the destination",
  "Kaynak (isteyen)": "Source (requesting)",
  "Kaynak cihazlar hedefe gömülü SSH sunucusuyla (tünel içi port 4022) girebilir. Yalnızca listedeki yerel kullanıcılar; root ayrıca izin ister. Windows hedeflerde servis sistem hesabıyla çalışır: kullanıcı olarak system yazılmadıkça giriş reddedilir.":
    "Source devices can sign in to the destination through the built-in SSH server (port 4022 inside the tunnel). Only the local users listed; root needs its own permission. On Windows destinations the service runs as the system account: sign-in is refused unless system is listed as a user.",
  "Kaynak cihazlar hedefi Wake-on-LAN ile uyandırabilir. İstek, hedefin yerel ağındaki bir aracı cihaza gider; aracı orada magic paketi yayınlar.":
    "Source devices can wake the destination with Wake-on-LAN. The request goes to a relay device on the destination's local network, which broadcasts the magic packet there.",
  "Kaynak cihazlar hedefin ekranını izleyebilir (tünel içi port 4047). Kontrol ve onaysız bağlanma ayrı izinlerdir; hedefte her oturumda gösterge çıkar.":
    "Source devices can view the destination's screen (port 4047 inside the tunnel). Control and connecting without approval are separate permissions; the destination shows an indicator in every session.",
  "Kaynak cihazlar hedefin gelen kutusuna dosya gönderebilir; hedefte kabul edilmesi gerekir.":
    "Source devices can send files to the destination's inbox; they must be accepted on the destination.",
  "Kaynak cihazlar hedefin paylaştığı klasörleri salt okunur çekebilir ve/veya hedefte şifreli yedek tutabilir (tünel içi port 4050). Hedef yedeklerin içeriğini göremez.":
    "Source devices can pull the folders the destination shares, read-only, and/or keep an encrypted backup on the destination (port 4050 inside the tunnel). The destination cannot see what the backups contain.",
  "Kaynak cihazlar hedefle tünel içi hız testi yapabilir.": "Source devices can run a speed test with the destination inside the tunnel.",
  "Kaynak eski yedeklerini silebilsin (varsayılan: yalnızca ekleme)": "Let the source delete its old backups (default: add only)",
  "Kimlikler küçük harf, rakam ve tire içerir (ör. belgeler, foto-2026)": "IDs use lowercase letters, digits and hyphens (e.g. documents, photos-2026)",
  "Kontrole izin ver (klavye, fare, pano)": "Allow control (keyboard, mouse, clipboard)",
  "Kota (GiB, 0: 50 GiB)": "Quota (GiB, 0: 50 GiB)",
  "Kullanıcı adları küçük harf, rakam, _ . - içerebilir (ör. ali, deploy, system)":
    "User names may contain lowercase letters, digits, _ . - (e.g. alice, deploy, system)",
  "Laptoptan sunucuya SSH": "SSH from the laptop to the server",
  "Okunabilecek klasör kimlikleri": "Folder IDs that can be read",
  "Reddet kuralı bu servisi, izin kuralları ne derse desin kapatır.": "A deny rule closes this service, whatever the allow rules say.",
  "SSH, dosya gönderme, uyandırma, hız testi, uzak masaüstü veya eşitleme izni. Servis yalnızca bir kural onu bir cihaza açtığında o cihazda dinler.":
    "Permission for SSH, file sending, wake-up, speed test, remote desktop or sync. A service only listens on a device when a rule opens it there.",
  "Sayı gir; varsayılan için 0": "Enter a number; 0 for the default",
  Servis: "Service",
  "Servis kuralı ekle": "Add service rule",
  "Servis: {name}": "Service: {name}",
  "Virgülle ayır. Joker yoktur; her hesap açıkça yazılır.": "Separate with commas. There are no wildcards; every account is written out.",
  "Yerel port yönlendirmeye (ssh -L) izin ver": "Allow local port forwarding (ssh -L)",
  "ali, deploy (Windows için: system)": "alice, deploy (on Windows: system)",
  "aracı: {via}": "relay: {via}",
  "belgeler, foto": "documents, photos",
  "gözetimsiz (onaysız)": "unattended (no approval)",
  "klasörler (salt okunur): {folders}": "folders (read-only): {folders}",
  "kullanıcılar: {users}": "users: {users}",
  "root (uid 0) olarak girişe izin ver": "Allow sign-in as root (uid 0)",
  "root ve system hesapları hedef cihazda tam yetki verir. Yalnızca gerçekten gereken kaynak cihazlara aç.":
    "The root and system accounts give full control of the destination device. Open them only to the source devices that really need it.",
  "root yazma; aşağıdaki root iznini aç": "Do not list root; turn on the root permission below",
  "Çok büyük": "Too large",
  "İzinli yerel kullanıcılar": "Allowed local users",
  "şifreli yedek (kota {quota} GiB); silebilir": "encrypted backup (quota {quota} GiB); may delete",
  "şifreli yedek (kota {quota} GiB); yalnızca ekleme": "encrypted backup (quota {quota} GiB); add only",
  "şifreli yedek; silebilir": "encrypted backup; may delete",
  "şifreli yedek; yalnızca ekleme": "encrypted backup; add only",

  // Group dialog and list (rules/group-dialog.tsx, rules/groups-section.tsx)
  "Bu adda bir grup var; değiştirmek için listeden düzenle": "A group with this name exists; edit it from the list to change it",
  "Cihazlar ve etiketler; grup içinde grup veya tüm cihazlar seçilemez.": "Devices and tags; a group cannot contain groups or all devices.",
  "En az bir üye seç": "Choose at least one member",
  "En fazla {count} üye": "At most {count} member|At most {count} members",
  "Grup adı": "Group name",
  "Grup adı değiştirilemez; farklı ad için yeni grup oluştur.": "A group name cannot be changed; create a new group for a different name.",
  "Grup ekle": "Add group",
  "Grup, cihazları ve etiketleri tek adla toplar. Kurallar ve çıkış düğümü kullanıcıları gruba group:ad ile başvurur.":
    "A group gathers devices and tags under one name. Rules and exit node users refer to it as group:name.",
  "Küçük harf, rakam ve tire. Kurallarda group:ad olarak görünür.": "Lowercase letters, digits and hyphens. Shows as group:name in rules.",
  "group:{name} grubunu düzenle": "Edit group:{name}",
  ofis: "office",
  Üyeler: "Members",
  "Bir grup cihazları ve etiketleri tek adla toplar; kurallarda ve çıkış düğümü kullanıcılarında group:ad olarak kullanılır.":
    "A group gathers devices and tags under one name; rules and exit node users use it as group:name.",
  "Düzenle…": "Edit…",
  Grup: "Group",
  "Grup belgeden kaldırılır. Üye cihazlar ve etiketler değişmez.": "The group is removed from the document. Its member devices and tags do not change.",
  "Henüz grup yok.": "No groups yet.",
  "Kullanımdaki grup silinemez; önce ona başvuran kuralları ve çıkış düğümü kullanıcılarını değiştir.":
    "A group in use cannot be deleted; first change the rules and exit node users that refer to it.",
  "Sil…": "Delete…",
  "group:{name} grubunu sil": "Delete group:{name}",
  "group:{name} için işlemler": "Actions for group:{name}",
  "group:{name} üyeleri": "Members of group:{name}",
  "{count} yerde kullanılıyor": "Used in {count} place|Used in {count} places",

  // Policy tests, simulator and text editor (rules/policy-tools.tsx)
  "22 veya rdp": "22 or rdp",
  "Belgede kural testi yok.": "The document has no rule tests.",
  "Belgedeki testler her imzadan önce çalışır; biri başarısızsa belge imzalanmaz. Testler metin düzenleyicide eklenir.":
    "The tests in the document run before every signature; if one fails, the document is not signed. Tests are added in the text editor.",
  "Bir bağlantının kurallarca nasıl karşılanacağını dene; reddet kuralı her zaman izinden önce gelir.":
    "Try how the rules answer a connection; a deny rule always comes before allows.",
  "Bir cihaz kendisiyle eşleşmez.": "A device does not match itself.",
  Dene: "Try",
  "Dosya 1 MiB'tan büyük olamaz": "The file cannot be larger than 1 MiB",
  "Dosya herkesten herkese erişim açan yeni bir kural eklerse bunu bilerek onaylıyorum":
    "If the file adds a new rule that opens access from everyone to everyone, I approve it knowingly",
  Geçti: "Passed",
  "Gruplar, adlandırılmış adresler, kurallar ve testler yorumlu JSON olarak. Kaydetmeden önce doğrulanır, testler çalışır ve fark gösterilir; imza yine ağ belgesinin kendisine atılır.":
    "Groups, named addresses, rules and tests as commented JSON. Before saving it is validated, the tests run and the diff is shown; the signature still goes on the network document itself.",
  "Hedef cihazı yaz": "Enter the destination device",
  "Hiçbir kural izin vermiyor; varsayılan olarak reddedilir.": "No rule allows it; denied by default.",
  Kaldı: "Failed",
  "Kaynak cihaz": "Source device",
  "Kaynak cihazı yaz": "Enter the source device",
  "Kural simülatörü": "Rule simulator",
  "Kural testleri": "Rule tests",
  "Kural {number} izin veriyor: {rule}": "Rule {number} allows it: {rule}",
  "Kural {number} reddediyor: {rule}": "Rule {number} denies it: {rule}",
  "Kural {number} reddediyor: {rule}. Kural {allow} izin verirdi; reddet kuralı her zaman önce gelir.":
    "Rule {number} denies it: {rule}. Rule {allow} would allow it; a deny rule always comes first.",
  "Politika boş olamaz": "The policy cannot be empty",
  "Politika dosyası": "Policy file",
  "Politika metni": "Policy text",
  "Port veya adını yaz (ör. 22, rdp)": "Enter a port or its name (e.g. 22, rdp)",
  Reddedilir: "Denied",
  Sonuç: "Result",
  "Sonuç: {result}": "Result: {result}",
  Test: "Test",
  "Yorumlar // veya # ile başlar. Port yerine ad yazılabilir (ör. rdp, ssh, https). CLI karşılığı: openscale policy export / import.":
    "Comments start with // or #. A name can be written instead of a port (e.g. rdp, ssh, https). CLI equivalent: openscale policy export / import.",
  "Zamana bağlı kuralları her zaman etkin say": "Treat time-based rules as always in effect",
  "{count} test geçti": "{count} test passed|{count} tests passed",
  "{count} test kaldı": "{count} test failed|{count} tests failed",
  "İzin verilir": "Allowed",

  // Reference picker (rules/reference-picker.tsx)
  "Birden fazla seçebilirsin.": "You can choose more than one.",
  "Cihaz yok": "No devices",
  "Henüz hiçbir cihazda olmayan bir etiket ekle": "Add a tag no device has yet",
  "Seçili: {count}/{max}.": "Selected: {count}/{max}.",
  "tag:sunucu": "tag:server",

  // Rules page (rules/rules-view.tsx)
  "Erişim Kontrolü bölümleri": "Access Control sections",
  "Kaynak → Hedef": "Source → Destination",
  "Kural numarası": "Rule number",
  "Kural simülatörü için önce cihaz ekle.": "Add a device first to use the rule simulator.",
  "Kural uyarıları": "Rule warnings",
  "Kural yok, her şey kapalı. Kural ekleyebilmek için önce cihaz ekle.": "No rules, everything is closed. Add a device first to be able to add rules.",
  "Kural yok, her şey kapalı. Örneğin laptoptan masaüstüne Uzak Masaüstü için TCP 3389'a izin veren bir kural ekleyebilirsin.":
    "No rules, everything is closed. For example, you can add a rule that allows TCP 3389 from the laptop to the desktop for Remote Desktop.",
  "Kural {number} için işlemler": "Actions for rule {number}",
  "Kural {number}: aç": "Rule {number}: turn on",
  "Kural {number}: kapat": "Rule {number}: turn off",
  "Kural {number}: sil": "Rule {number}: delete",
  "Kural {number}: {rule}": "Rule {number}: {rule}",
  "Kural {rules} kolay başlangıç içindir ve varsayılan reddet ilkesini fiilen kapatır. Cihazlarından biri ele geçirilirse diğerlerinin bütün portlarına ulaşabilir.":
    "Rule {rules}: meant for an easy start only; it effectively turns off the default deny policy. If one of your devices is compromised, it can reach every port of the others.",
  "Kuralı aç…": "Turn rule on…",
  "Kuralı kapat": "Turn rule off",
  "Kuralı kapat…": "Turn rule off…",
  "Kuralı sil": "Delete rule",
  "Metin düzenleyici": "Text editor",
  "Port / protokol": "Port / protocol",
  "Protokol {number}": "Protocol {number}",
  "Reddet kuralları her zaman izin kurallarından önce uygulanır; kapalı kurallar silinmeden devre dışı kalır.":
    "Deny rules are always applied before allow rules; rules turned off stay inactive without being deleted.",
  "Test ve simülatör": "Tests and simulator",
  "Tüm cihazlar birbirine her porttan erişebiliyor": "All devices can reach each other on every port",
  hedef: "to",
  "{rule} kuralı silinecek; bu trafik bundan sonra reddedilir. Sonraki kuralların numarası bir azalır.":
    "The rule {rule} will be deleted; this traffic is denied from now on. The rules after it move up by one.",
  "{rule} kuralı silinmeden devre dışı kalır; sonradan yeniden açabilirsin.": "The rule {rule} becomes inactive without being deleted; you can turn it back on later.",
  "{rule} kuralı yeniden uygulanır.": "The rule {rule} is applied again.",
  "{rule} reddet kuralı silinecek; izin kurallarının kapsadığı trafik bundan sonra geçer. Sonraki kuralların numarası bir azalır.":
    "The deny rule {rule} will be deleted; traffic covered by allow rules passes from now on. The rules after it move up by one.",
  "Önce ihtiyacın olan dar kuralları ekle (örneğin laptop → masaüstü, TCP 3389), sonra bu kuralı sil.":
    "First add the narrow rules you need (for example laptop → desktop, TCP 3389), then delete this rule.",

  // Unused tags (rules/unused-tags-alert.tsx)
  "Bir reddet kuralında kullanılıyor: yazım hatası olabilir ve engellemek istediğin trafik engellenmiyor olabilir.":
    "It is used in a deny rule: it may be a typo, and the traffic you want to block may not be blocked.",
  "Eşleşmeyen etiketler": "Tags that match nothing",
  "{tag} hiçbir cihazda yok; bu başvuru hiçbir şeyle eşleşmez.": "No device has {tag}; this reference matches nothing.",

  // Routes page (routes/routes-view.tsx)
  "Adres atama": "Address assignment",
  "Alt ağ": "Subnet",
  "Alt ağ rotaları": "Subnet routes",
  "Alt ağlar": "Subnets",
  "Ayrılmış aralıklar": "Reserved ranges",
  "Bir cihaz seçin.": "Choose a device.",
  "Boş liste cihazın bütün rotalarını kaldırır. Bir kuralın kullandığı rota kaldırılamaz; önce kuralı silin.":
    "An empty list removes all of the device's routes. A route used by a rule cannot be removed; delete the rule first.",
  "Bu aralıklardan otomatik adres verilmez.": "No addresses are assigned automatically from these ranges.",
  "Bu bilgisayarın ağlarıyla çakışma": "Conflict with this computer's networks",
  "Cihaza rota ekle": "Add route to device",
  "Değişikliği gözden geçir": "Review the change",
  "Düz WireGuard çıkış düğümleri": "Plain WireGuard exit nodes",
  "Erişebilen cihazlar": "Devices with access",
  "Henüz alt ağ yok. Bir cihaza rota ekle veya yönlendiricinin ilanını aşağıda onayla.":
    "No subnets yet. Add a route to a device or approve the router's advertisement below.",
  "Henüz hiçbir kural erişim vermiyor": "No rule gives access yet",
  "Kendi WireGuard sunucun, DNS çözücüsüyle birlikte çıkış düğümü olarak kullanılabilir. Tanımlamak için {set}, sunucu ayarı için {config}.":
    "Your own WireGuard server can be used as an exit node, together with its DNS resolver. To define one use {set}; for the server configuration use {config}.",
  "Onaylanan rotalar kök anahtarla imzalanan yeni belge sürümüne girer.": "Approved routes go into the new document version signed with the root key.",
  "Onaylı alt ağlar": "Approved subnets",
  Rastgele: "Random",
  "Rota ilanı": "Route advertisement",
  "Rota ilanı onayı": "Route advertisement approval",
  "Rotalar virgülle ayrılmış CIDR olmalı (ör. 192.168.1.0/24). En fazla 32.": "Routes must be comma-separated CIDRs (e.g. 192.168.1.0/24). At most 32.",
  "Rotaları düzenle…": "Edit routes…",
  "Rotaları onayla": "Approve routes",
  "Seçilenleri onayla": "Approve selected",
  Sıralı: "Sequential",
  "Tanımlı düz WireGuard çıkış düğümü yok.": "No plain WireGuard exit nodes are defined.",
  "Yalnızca özel aralıklar: 10/8, 172.16/12, 192.168/16, 100.64/10 ve fc00::/7.": "Private ranges only: 10/8, 172.16/12, 192.168/16, 100.64/10 and fc00::/7.",
  Yeni: "New",
  "Yeni cihaza hangi boş adresin verileceği.": "Which free address a new device gets.",
  "Yeni cihazlara adres verme yöntemi ve otomatik verilmeyen ayrılmış aralıklar. Değiştirmek için {command}.":
    "How new devices get addresses, and the reserved ranges that are never assigned automatically. To change it, use {command}.",
  Yönlendirici: "Router",
  "Yönlendirici Linux olmalıdır (iletim ve maskeleme). Windows yönlendirici olamaz; Windows istemciler rotaları kullanabilir.":
    "The router must run Linux (forwarding and masquerading). Windows cannot be a router; Windows clients can use the routes.",
  "Yönlendirici cihaz": "Router device",
  "Yönlendirici cihazda {command} çalıştır ve çıkan satırı buraya yapıştır. İlan cihazın kendi anahtarıyla imzalıdır; onay senin imzanla belgeye girer.":
    "Run {command} on the router device and paste the line it prints here. The advertisement is signed with the device's own key; the approval goes into the document with your signature.",
  Yöntem: "Method",
  "Zaten onaylı": "Already approved",
  "{device} şu alt ağları istiyor ({date}):": "{device} asks for these subnets ({date}):",
  "{name} rotaları için işlemler": "Actions for the routes of {name}",
  "İlan edilen alt ağlar": "Advertised subnets",
  "İlanı doğrula": "Verify advertisement",
  "İlk boş adres": "First free address",

  // Subnet inventory (routes/subnet-inventory.tsx)
  "Alt ağdaki cihazlar": "Devices on the subnet",
  "Cihaz adresini değiştirebilir; kural yazarken dikkat et.": "The device may change its address; take care when writing rules.",
  "Gizlilik için yalnızca üretici kısmı gösterilir": "Only the vendor part is shown, for privacy",
  "Kural için": "For rules",
  "Liste bu bilgisayarın komşu tablosundan okunur; ağa paket gönderilmez ve başka cihaza iletilmez. Yalnızca yakın zamanda konuşulan cihazlar görünür.":
    "The list is read from this computer's neighbor table; no packets are sent to the network and nothing is passed to another device. Only devices talked to recently show up.",
  "MAC (üretici)": "MAC (vendor)",
  "Rastgele MAC": "Random MAC",
  "Yönlendirilen ağlarda ({networks}) henüz konuşulan cihaz yok.": "No devices have been talked to yet on the routed networks ({networks}).",
  "{address} adresini kural için kopyala": "Copy {address} for a rule",
  Üretici: "Vendor",

  // Document history (history/history-view.tsx, history/diff-lines.ts)
  "Ağ oluşturuldu.": "Network created.",
  "Belge sürümleri": "Document versions",
  "En yeni sürüm en üstte. Yeşil satırlar eklenen, kırmızılar kaldırılan, sarılar değişen öğelerdir.":
    "Newest version on top. Green lines are added items, red ones removed, yellow ones changed.",
  "Geçmişte sorun bulundu": "Problems found in the history",
  "Sürüm {version}": "Version {version}",
  "{count} kural": "{count} rule|{count} rules",
  "{count} sürüm doğrulandı": "{count} version verified|{count} versions verified",
  "Ağ oluşturuldu": "Network created",
  "Geçerlilik süresi yenilendi": "Validity renewed",
  "Yalnızca geçerlilik süresi yenilendi": "Only the validity was renewed",
  "{count} ayar değişti": "{count} setting changed|{count} settings changed",
  "{count} cihaz değişti": "{count} device changed|{count} devices changed",
  "{count} cihaz eklendi": "{count} device added|{count} devices added",
  "{count} cihaz çıkarıldı": "{count} device removed|{count} devices removed",
  "{count} kural eklendi": "{count} rule added|{count} rules added",
  "{count} kural silindi": "{count} rule deleted|{count} rules deleted",

  // Diff lines (diff-list.tsx)
  "Ağ belgesinde değişen bir şey yok.": "Nothing changes in the network document.",
  "Değişir:": "Changes:",
  "Değişmeyen {count} satır gizlendi.": "{count} unchanged line hidden.|{count} unchanged lines hidden.",
  "Eklenir:": "Added:",
  "Kaldırılır:": "Removed:",
  "Sürüm {from} -> {to}": "Version {from} -> {to}",
  "cihaz {name}": "device {name}",
  "cihaz {name} (iptal)": "device {name} (revoked)",
  "grup {group}": "group {group}",
  "kural {rule}": "rule {rule}",
  "reddet: {rule}": "deny: {rule}",
  sonra: "then",
  "{rule} (kapalı)": "{rule} (off)",

  // Signing a change (sign-change.tsx)
  "Ağ belgesi sürüm {version} olarak YubiKey ile imzalandı.": "The network document was signed with the YubiKey as version {version}.",
  "Bu cihaza bağlı erişim kuralları da belgeden kalkar. Hangileri olduğu aşağıdaki farkta kırmızı satırlarda.":
    "The access rules tied to this device are removed from the document too. They are the red lines in the diff below.",
  "Bu işlem geri alınamaz; yanlış cihazı seçmediğinden emin olmak için adını yaz.": "This cannot be undone; type the name to make sure you did not pick the wrong device.",
  "Bununla birlikte silinecek: {count} kural": "Also deleted with it: {count} rule|Also deleted with it: {count} rules",
  "Değişiklik hesaplanıyor": "Working out the change",
  "Onaylamak için {name} yaz": "Type {name} to confirm",
  "Parola yalnızca bu imza için kullanılır, saklanmaz.": "The passphrase is used only for this signature and is not stored.",
  "İmzalanacak değişiklikler": "Changes to sign",
}
