// English texts (#224), keyed by the Turkish source text. See lib/i18n/i18n.tsx.

export const enDiag: Record<string, string> = {
  // Diagnostics page (diag-view, diag-errors)
  "Tanı bilgileri yalnızca o bilgisayarın kendi panelinde görünür; uzak panel bunları göstermez.":
    "Diagnostics are shown only in that computer's own panel; the remote panel does not show them.",
  "Tanı bilgileri bu bilgisayarın tünelinden gelir ve yalnızca masaüstü uygulamasında görünür. Komut satırında:":
    "Diagnostics come from this computer's tunnel and are shown only in the desktop app. On the command line:",
  "Tünel çalışmıyor. Bağlantıyı açınca eş yolları ve ağ denetimi burada görünür.":
    "The tunnel is not running. Once you connect, peer paths and the network check appear here.",
  "{section} yüklenemedi": "{section} could not be loaded",
  "Tanı verilerinin bir kısmı yüklenemedi": "Some diagnostics could not be loaded",
  "Etkilenen bölümler: {sections}.": "Affected sections: {sections}.",
  "Bu bölüm yüklenemedi; nedeni sayfanın üstünde.": "This section could not be loaded; the reason is at the top of the page.",
  "{section} yükleniyor": "Loading {section}",

  // Audit log (audit-card)
  "Eşitleme sayfasına git": "Go to the sync page",
  "Dinamik DNS ayarlarına git": "Go to the dynamic DNS settings",
  "Süreli bağlantılar": "Timed links",
  "Denetim kaydı": "Audit log",
  "Belge değişiklikleri, eklenen ve iptal edilen cihazlar, reddedilen belgeler, sızıntı kilidi (kill switch), eşitleme koruması ve yerel ayar değişiklikleri. Hash zinciriyle saklanır; doğrulamak için":
    "Document changes, added and revoked devices, rejected documents, the kill switch, the sync guard and local settings changes. Stored as a hash chain; to verify it, run",
  "Zincir sağlam: {count} kayıt": "Chain intact: {count} record|Chain intact: {count} records",
  "Denetim kaydının zinciri bozuk": "The audit log chain is broken",
  "Henüz güvenlik olayı yok. Ağ belgesi değiştiğinde veya bir cihaz eklendiğinde burada görünür.":
    "No security events yet. They appear here when the network document changes or a device is added.",
  "Güvenlik olayları": "Security events",
  Zaman: "Time",
  Önem: "Severity",
  Olay: "Event",

  // Denied connections (denied-card)
  bilinmeyen: "unknown",
  "{who} → bu cihaz": "{who} → this device",
  "bu cihaz → {who}": "this device → {who}",
  "{count} kez": "{count} time|{count} times",
  "Liste temizlendi.": "List cleared.",
  "Reddedilen bağlantılar": "Denied connections",
  "Bir bağlantı neden açılmadı? Kural yok, reddet kuralı, devre dışı kural veya kalkan. Yalnızca bellekte tutulur; diğer adresler kısaltılır. Komut satırında:":
    "Why did a connection not open? No rule, a deny rule, a disabled rule or a shield. Kept in memory only; other addresses are shortened. On the command line:",
  Temizle: "Clear",
  "Reddedilen bağlantı yok. Kuralların izin vermediği bir bağlantı denendiğinde burada nedeniyle birlikte görünür.":
    "No denied connections. When a connection the rules do not allow is attempted, it appears here with the reason.",
  Son: "Last",

  // DNS enforcement (dns-enforce-switch)
  "DNS zorlama açıldı.": "DNS enforcement turned on.",
  "DNS zorlama kapatıldı; kurallar kaldırılıyor.": "DNS enforcement turned off; the rules are being removed.",
  Uygulanıyor: "Active",
  "Tünel dışı DNS ve listedeki {count} DoH adresi engelleniyor.":
    "DNS outside the tunnel and {count} DoH address from the list are blocked.|DNS outside the tunnel and {count} DoH addresses from the list are blocked.",
  "Tünel dışı DNS engelleniyor. DoH listesi tanımlı değil.": "DNS outside the tunnel is blocked. No DoH list is set.",
  "DNS yalnızca tünelden": "DNS only through the tunnel",
  "Çıkış düğümü kullanılırken tünel dışına giden DNS ve DoT trafiğini işletim sisteminin güvenlik duvarıyla keser. Tünel kapanınca kurallar kendiliğinden kalkar.":
    "While an exit node is used, the operating system's firewall cuts DNS and DoT traffic that leaves outside the tunnel. The rules are removed automatically when the tunnel closes.",
  "Bu sistemde DNS zorlama yok.": "DNS enforcement is not available on this system.",

  // Events (events-card)
  "Aktarıcıya düştü": "Fell back to relay",
  "Giriş sayfası": "Sign-in page",
  Olaylar: "Events",
  "Servis çalıştığı sürece son 200 bağlantı olayı. Yalnızca bellekte tutulur; adres içermez.":
    "The last 200 connection events while the service runs. Kept in memory only; contains no addresses.",
  "Henüz olay yok. Bir eş çevrimiçi olduğunda, düştüğünde veya aktarıcıya geçtiğinde burada görünür.":
    "No events yet. They appear here when a peer comes online, drops or switches to the relay.",

  // Threats (guards-card)
  "{peer} cihazının engeli kaldırıldı.": "{peer} is no longer blocked.",
  Tehditler: "Threats",
  "Port taraması ve tuzak algılamaları yalnızca bu cihazda tutulur. DNSSEC sayaçları, çıkış düğümü recursive-dnssec çözücüsü kullanırken dolar.":
    "Port scan and decoy detections are kept on this device only. The DNSSEC counters fill while the exit node uses the recursive-dnssec resolver.",
  "Tarayıcı DNS ayarlarını denetle": "Check browser DNS settings",
  "{list} DNS'i kendi DoH sunucusuna gönderiyor; MagicDNS adları ve çıkış düğümü çözücüsü atlanır. Tarayıcının güvenli DNS ayarını kapat.":
    "{list} sends DNS to its own DoH server; MagicDNS names and the exit node resolver are bypassed. Turn off the browser's secure DNS setting.",
  "Tarayıcılarda sistem çözücüsünü atlayan DoH ayarı bulunmadı.": "No browser has a DoH setting that bypasses the system resolver.",
  "güvenli {n}": "secure {n}",
  "imzasız {n}": "unsigned {n}",
  "reddedilen {n}": "rejected {n}",
  "Engellenen cihazlar": "Blocked devices",
  "Engellenen cihaz": "Blocked device",
  "Engel bitişi": "Block ends",
  "{peer} engeli için işlemler": "Actions for the block on {peer}",
  "Engeli kaldır": "Unblock",
  "Algılama yok.": "No detections.",
  "Tünel çalışmıyor.": "The tunnel is not running.",
  Algılamalar: "Detections",
  Algılama: "Detection",
  Ayrıntı: "Details",
  "Algılama ve çözücü ayarları": "Detection and resolver settings",
  "{count} hedef": "{count} target|{count} targets",
  "Kaydedildi; tünel kısa süreliğine yeniden başlatılıyor.": "Saved; the tunnel is restarting briefly.",
  "Port taramasını algıla": "Detect port scans",
  "Tarayan cihazı geçici olarak engelle": "Temporarily block the scanning device",
  'Yanlış alarmda engel buradan veya "openscale threats unblock" ile kaldırılır.':
    'After a false alarm, remove the block here or with "openscale threats unblock".',
  "Çıkış düğümü üst çözücüsü": "Exit node upstream resolver",
  "boş: sistem çözücüsü; recursive-dnssec, tls://…, https://…": "empty: system resolver; recursive-dnssec, tls://…, https://…",
  "Yalnızca bu bilgisayar çıkış düğümüyken üyelerin DNS sorgularına uygulanır.":
    "Applies to members' DNS queries only while this computer is the exit node.",
  "Engel listesi dosyası": "Blocklist file",
  "C:\\OpenScale\\engel.txt": "C:\\OpenScale\\blocklist.txt",
  "Yerel dosya; hiçbir liste indirilmez.": "A local file; no list is downloaded.",

  // Network check (netcheck-card)
  "NAT yok": "No NAT",
  "Kolay NAT": "Easy NAT",
  "Zor (simetrik) NAT": "Hard (symmetric) NAT",
  "Henüz bilinmiyor": "Not known yet",
  "Koordinatör (UDP)": "Coordinator (UDP)",
  Ulaşılıyor: "Reachable",
  Ulaşılamıyor: "Unreachable",
  "NAT türü": "NAT type",
  "Dış adres": "External address",
  "Yerel port": "Local port",
  Eşler: "Peers",
  "{port} · korunuyor: {kept}": "{port} · preserved: {kept}",
  "{direct} doğrudan · {relayed} aktarıcı · {ipv6} IPv6": "{direct} direct · {relayed} relayed · {ipv6} IPv6",
  "Son bir saatte adres değişimi": "Address changes in the last hour",
  "Ağ denetimi": "Network check",
  "Koordinatöre UDP ile ulaşılabildiğini, NAT türünü ve IPv4/IPv6 durumunu ölçer. Yalnızca kendi koordinatörün ve eşlerin kullanılır; istek üzerine çalışır.":
    "Measures whether the coordinator is reachable over UDP, the NAT type and IPv4/IPv6 status. Only your own coordinator and peers are used; it runs on request.",
  Denetle: "Check",
  "Giriş sayfası algılandı": "Sign-in page detected",
  "Ölçüm: {at}": "Measured: {at}",
  "Sonuç görmek için “Denetle”ye bas.": "Press “Check” to see the result.",

  // Notifications and metrics (observe-settings-card)
  "Masaüstü bildirimleri": "Desktop notifications",
  "Yeni veya çıkarılan cihaz, kill switch devreye girmesi ve reddedilen ağ belgesi için tepside bildirim.":
    "A tray notification for a new or removed device, the kill switch engaging and a rejected network document.",
  "Yerel metrik uç noktası": "Local metrics endpoint",
  "Prometheus biçimi; yalnızca 127.0.0.1, uygulama anahtarı ve yönetici süreci ile. Komut satırında: openscale metrics print.":
    "Prometheus format; only on 127.0.0.1, with the app key and an administrator process. On the command line: openscale metrics print.",
  "Bildirim ve metrik": "Notifications and metrics",
  "Hiçbir kayıt veya ölçüm bu bilgisayarın dışına gönderilmez.": "No record or measurement is sent outside this computer.",

  // Network privacy (opsec-view)
  Otomatik: "Automatic",
  Kip: "Mode",
  "Çıkış düğümü müdahalesi": "Exit node interception",
  "Klon şüphesi": "Suspected clone",
  "Kayıp kip": "Lost mode",
  "Koordinatör tutarsızlığı": "Coordinator mismatch",
  Temiz: "Clean",
  "Anahtar öğrenildi": "Key learned",
  "Anahtar farklı: müdahale olabilir": "Key differs: possible interception",
  "Güvenilmeyen sertifika": "Untrusted certificate",
  Ulaşılamadı: "Unreachable",
  "Bu bilgisayarın trafiği nasıl gizlediği, karantinaya aldığı cihazlar ve ağ müdahalesi alarmları.":
    "How this computer disguises its traffic, the devices it has quarantined and network interception alarms.",
  "Ağ gizliliği durumu okunamadı": "Could not read the network privacy status",
  "Tünel kapalı. Ağ gizliliği durumu, bu bilgisayar ağa bağlandığında burada görünür.":
    "The tunnel is off. The network privacy status appears here once this computer connects to the network.",
  "Bu sürümde ağ gizliliği durumu masaüstü hizmetinden alınamıyor.":
    "In this version the network privacy status cannot be read from the desktop service.",
  "Bu cihaz kayıp olarak işaretlendi": "This device is marked as lost",
  "Yalnızca koordinatör bağlantısı açık.": "Only the coordinator connection is open.",
  "İşaret zamanı: {at}.": "Marked at: {at}.",
  "Trafik gizleme": "Traffic camouflage",
  "WireGuard paketleri sıradan şifreli web trafiğine benzetilir. Gizlilik WireGuard'dan gelir; bu katman yalnızca trafiğin VPN diye tanınmasını zorlaştırır.":
    "WireGuard packets are made to look like ordinary encrypted web traffic. Privacy comes from WireGuard; this layer only makes the traffic harder to recognise as a VPN.",
  "Dolgu kovaları": "Padding buckets",
  "{buckets} bayt": "{buckets} bytes",
  "Zamanlama gürültüsü": "Timing jitter",
  "en çok {value}": "at most {value}",
  "Gizlenen paket": "Disguised packets",
  "Açık kipte bütün cihazlar ve koordinatör güncel sürümde olmalı; emin değilseniz Otomatik seçin.":
    "In On mode every device and the coordinator must run the current version; if you are not sure, choose Automatic.",
  "Değiştirmek için:": "To change it:",
  "Ağ gizliliği alarmları": "Network privacy alarms",
  "Alarm yok. Tuzak port dokunuşu, tarama, klon şüphesi ve çıkış düğümü müdahalesi burada görünür.":
    "No alarms. Decoy port touches, scans, suspected clones and exit node interception appear here.",
  "{peer} karantinadan çıkarıldı.": "{peer} was released from quarantine.",
  "Karantinadaki cihazlar": "Quarantined devices",
  "Karantina yalnızca bu bilgisayarda geçerlidir. Cihazı ağdan tamamen çıkarmak için Cihazlar sayfasından iptal edin (kök imzası gerekir).":
    "Quarantine applies to this computer only. To remove the device from the network entirely, revoke it on the Devices page (needs the root signature).",
  "Karantinada cihaz yok.": "No devices in quarantine.",
  Başlangıç: "Start",
  "Siz kaldırana dek": "Until you remove it",
  "Karantinayı kaldır": "Release from quarantine",
  "{peer} karantinadan çıksın mı?": "Release {peer} from quarantine?",
  "Bu cihazın bu bilgisayarla bağlantısı yeniden açılacak. Emin misiniz?":
    "This device's connection to this computer will be opened again. Are you sure?",
  "Çıkış düğümü TLS denetimi": "Exit node TLS check",
  "Bilinen sunucuların anahtarı çıkış düğümü kullanılırken karşılaştırılır; fark, trafiğe müdahale edildiğini gösterebilir.":
    "The keys of known servers are compared while an exit node is used; a difference can mean the traffic is being intercepted.",
  "Denetlenecek sunucu yok. Eklemek için:": "No servers to check. To add one:",
  "openscale opsec canary --add sunucu:443": "openscale opsec canary --add server:443",
  "Çift sıçramalı çıkış": "Double-hop exit",
  "Bu sürümde zincir planı denetlenir; yönlendirme henüz bağlı değil.":
    "In this version the chain plan is checked; routing is not wired up yet.",
  "Giriş düğümü:": "Entry node:",
  "Son düğüm:": "Final node:",
  "Plan geçerli.": "The plan is valid.",

  // Peer paths (paths-card)
  "aktarıcı yoklaması": "relay probe",
  "son yol yoklaması": "last path probe",
  "Aktarıcı zorunlu": "Relay forced",
  "Adres bilinmiyor": "Address unknown",
  "Doğrudan deneme yanıtsız": "Direct attempt got no reply",
  "Neden: {reason}": "Reason: {reason}",
  "Yollar sıfırlandı; eşler yeniden yoklanıyor.": "Paths reset; peers are being probed again.",
  aktarıcı: "relay",
  "yol yok": "no path",
  "Aktarıcı üzerinden {ms} ms": "{ms} ms through the relay",
  "Her cihaza doğrudan mı yoksa koordinatörün aktarıcısı üzerinden mi ulaşıldığı, şifrelemenin kuantum sonrası mı klasik mi olduğu, son el sıkışma ve yoklama gecikmesi.":
    "Whether each device is reached directly or through the coordinator's relay, whether encryption is post-quantum or classic, the last handshake and the probe latency.",
  "Tünel kurulu eş yok. Kurallar bu cihazı başka bir cihazla eşleştirdiğinde burada görünür.":
    "No peers with a tunnel. They appear here when the rules pair this device with another device.",
  "Eş yolları": "Peer paths",
  Yoklama: "Probe",
  "El sıkışma {ago}": "Handshake {ago}",
  Ölçülüyor: "Measuring",
  hiç: "never",
  "{name} için tanı işlemleri": "Diagnostic actions for {name}",
  "Aktarıcı testi": "Relay test",

  // Device posture (posture-view)
  Güçlü: "Strong",
  değişti: "changed",
  silindi: "removed",
  eklendi: "added",
  "Önyükleme, disk şifreleme, ekran kilidi ve TPM durumu. Kurallar bu bilgilere göre bir cihaza daha az erişim verebilir.":
    "Boot, disk encryption, screen lock and TPM status. Rules can give a device less access based on this.",
  "Önyükleme ve kilit": "Boot and lock",
  "Ekran kilidi": "Screen lock",
  "{lock} ({minutes} dk, en çok {max} dk önerilir)": "{lock} ({minutes} min, at most {max} min recommended)",
  "Bu sürümde genişletilmiş duruş bilgisi yok.": "This version has no extended posture information.",
  "Var ({version})": "Yes ({version})",
  "Cihaz anahtarı": "Device key",
  "TPM'e bağlı ({kind})": "Bound to the TPM ({kind})",
  "TPM'e bağlı": "Bound to the TPM",
  "Cihaz anahtarı bu bilgisayarın TPM'ine bağlı değil.": "The device key is not bound to this computer's TPM.",
  "Kurcalama günlüğü": "Tamper log",
  "OpenScale dosyalarında dışarıdan yapılan değişiklikler imzalı ve zincirli olarak kaydedilir.":
    "Outside changes to OpenScale files are recorded, signed and chained.",
  "Dışarıdan değişiklik görülmedi.": "No outside changes seen.",

  // Resource use (resources-card)
  "OpenScale'in tüketimi": "OpenScale's resource use",
  "Servisin son 24 saatteki işlemci ve bellek kullanımı, beş dakikada bir ölçülür. Veriler yalnızca bu bilgisayarda tutulur.":
    "The service's CPU and memory use over the last 24 hours, measured every five minutes. The data stays on this computer.",
  "Henüz ölçüm yok; ilk örnek beş dakika içinde gelir.": "No measurements yet; the first sample arrives within five minutes.",
  "Ortalama %{avg}, en yüksek %{max} (bir çekirdeğin yüzdesi)": "Average {avg}%, peak {max}% (percent of one core)",
  "Bu sistemde işlem süresi okunamıyor.": "CPU time cannot be read on this system.",
  "%{value}": "{value}%",
  "En çok {max}; sistemden alınan {sys}": "At most {max}; {sys} taken from the system",
  "Bu bilgisayarda pil bulunamadı.": "No battery found on this computer.",
  "Pildeyken harcanan işlemci süresi: {seconds} sn; ölçümlerin %{share} kadarı pildeyken.":
    "CPU time spent on battery: {seconds} s; {share}% of the measurements were on battery.",

  // Blocking and plugins (blocking-view)
  "Reklam, izleyici ve telemetri engeli çıkış düğümünün DNS çözücüsünde çalışır. Kategoriler, abonelikler ve eklenti sabitlemeleri imzalı belgededir; koordinatör bunları değiştiremez.":
    "Ad, tracker and telemetry blocking runs in the exit node's DNS resolver. Categories, subscriptions and plugin pins are in the signed document; the coordinator cannot change them.",
  "İmzala ve yayınla": "Sign and publish",
  "Çalışma durumu": "Runtime status",
  "Sayaçlar yalnızca çıkış düğümü olan bu bilgisayarda görünür. Hangi ad sorulduğu hiç saklanmaz.":
    "The counters appear only on this computer when it is an exit node. Which names were queried is never stored.",
  "Engelleme bu bilgisayarda çalışmıyor. Çıkış düğümleri: {nodes}.": "Blocking is not running on this computer. Exit nodes: {nodes}.",
  "Ağda çıkış düğümü yok. Engelleme bir cihaz çıkış düğümü olunca çalışır.":
    "The network has no exit node. Blocking runs once a device becomes an exit node.",
  "Belge sürüm {version}. Yalnızca sayaçlar tutulur; sorulan adlar saklanmaz.":
    "Document version {version}. Only counters are kept; queried names are not stored.",
  Eksik: "Incomplete",
  "DoH adları": "DoH names",
  "Eklenti engeli": "Blocked by plugins",
  "En çok engellenen adlar": "Most blocked names",
  "Liste yalnızca bellekte tutuluyor, {at} tarihinde silinir.": "The list is kept in memory only and is deleted at {at}.",
  "Kapalı. Açınca en çok engellenen adlar en fazla 1 saat, yalnızca bellekte tutulur.":
    "Off. When on, the most blocked names are kept in memory only, for at most 1 hour.",
  "Kapat ve sil": "Turn off and delete",
  "1 saat aç": "Turn on for 1 hour",
  "Engelleme kategorilerini imzala": "Sign the blocking categories",
  "Seçilen kategoriler varsayılan olarak bütün cihazlara uygulanır. Etiket ve cihaz kayıtları varsa onlar önce gelir.":
    "The selected categories apply to every device by default. Tag and device entries, if any, take precedence.",
  Kategoriler: "Categories",
  "Çıkış düğümü kullanan cihazlarda varsayılan olarak engellenecek kategoriler.":
    "Categories blocked by default on devices that use an exit node.",
  "Her zaman izin verilen adlar (keep)": "Always allowed names (keep)",
  "Telemetri engeli güncelleme alanlarını kesebilir. Açmak için en az bir güncelleme alanı yazın.":
    "Telemetry blocking can cut off update domains. To turn it on, enter at least one update domain.",
  "Her satıra bir ad. Bu adlar ve altındakiler hiçbir kategoride engellenmez.":
    "One name per line. These names and everything under them are never blocked in any category.",
  "Engellenen DoH sunucu adları": "Blocked DoH server names",
  "Tarayıcılar bu adları çözemeyince ağın kendi DNS çözücüsüne döner.":
    "When browsers cannot resolve these names, they fall back to the network's own DNS resolver.",
  "Önizle ve imzala": "Preview and sign",
  "Liste aboneliğini imzala": "Sign the list subscription",
  "Çıkış düğümü listeyi yalnızca bu özetle aynıysa kullanır. Liste değişirse yeni özeti yeniden imzalamanız gerekir.":
    "The exit node uses the list only if it matches this digest. If the list changes, you need to sign the new digest again.",
  "Liste aboneliğini kaldır": "Remove the list subscription",
  "Liste bir sonraki belge sürümünde çıkış düğümünden kalkar.": "The list is removed from the exit node with the next document version.",
  Abonelikler: "Subscriptions",
  "Listeleri yalnızca çıkış düğümü indirir ve imzalı özetle karşılaştırır. Özeti hesaplamak için: openscale blocking digest <dosya> --category <kategori>":
    "Only the exit node downloads the lists and compares them with the signed digest. To compute the digest: openscale blocking digest <file> --category <category>",
  "Henüz abonelik yok.": "No subscriptions yet.",
  "{count} ad yüklü": "{count} name loaded|{count} names loaded",
  Yüklenmedi: "Not loaded",
  "Aboneliği kaldır": "Remove subscription",
  Kategori: "Category",
  "Adres (yalnızca https)": "Address (https only)",
  "SHA-256 özeti": "SHA-256 digest",
  "64 onaltılık karakter. İncelediğiniz dosyanın özeti olmalı.": "64 hexadecimal characters. It must be the digest of the file you reviewed.",
  "Aboneliği ekle": "Add subscription",
  "İzin listesini imzala": "Sign the allow list",
  "Bu adlar hiçbir cihazda engellenmez.": "These names are not blocked on any device.",
  "Ad bir saatliğine engellenmeyecek.": "The name will not be blocked for an hour.",
  "İzin listesi": "Allow list",
  "Kalıcı istisnalar imzalı belgededir. Süreli izin yalnızca çıkış düğümünün belleğinde tutulur ve en çok 24 saat sürer.":
    "Permanent exceptions are in the signed document. A temporary allowance is kept only in the exit node's memory and lasts at most 24 hours.",
  "Kalıcı istisnalar": "Permanent exceptions",
  "bankam.example": "mybank.example",
  "Her satıra bir ad. Ad ve altındaki bütün adlar engellenmez.": "One name per line. The name and every name under it are not blocked.",
  "Bir saatliğine izin ver": "Allow for one hour",
  "ad.example": "name.example",
  "Cihaz (boşsa bütün cihazlar)": "Device (empty for all devices)",
  "bütün cihazlar": "all devices",
  "{at} tarihine kadar": "until {at}",
  "{name} eklentisini sabitle": "Pin the {name} plugin",
  "Eklenti şunları görecek: {data}. Dosyalar bu özetlerden farklılaşırsa yüklenmez.":
    "The plugin will see: {data}. If the files differ from these digests, it is not loaded.",
  "Eklenti bir sonraki belge sürümünde çıkış düğümünde çalışmayı bırakır.":
    "The plugin stops running on the exit node with the next document version.",
  Eklentiler: "Plugins",
  "Eklentiler çıkış düğümünde ağ ve dosya erişimi olmadan, 16 MiB bellek ve kısa süre sınırıyla çalışır. Yalnızca imzalı belgede özeti sabitlenmiş olanlar yüklenir.":
    "Plugins run on the exit node without network or file access, limited to 16 MiB of memory and a short time. Only those whose digest is pinned in the signed document are loaded.",
  "Bu bilgisayarın eklenti klasöründe eklenti yok.": "There are no plugins in this computer's plugin folder.",
  "Görür: {data}": "Sees: {data}",
  "hiçbir şey": "nothing",
  "Kancalar: {hooks} · hata durumunda {onError} · {memory} MiB · {timeout} ms": "Hooks: {hooks} · on error {onError} · {memory} MiB · {timeout} ms",
  "HTTP Location kancası bu sürümde çağrılmaz: çıkış düğümü HTTP trafiğini aracı olarak taşımadığı için eklenti yalnızca DNS kancasıyla çalışır ve HTTP adreslerini görmez.":
    "The HTTP Location hook is not called in this version: the exit node does not carry HTTP traffic as a proxy, so the plugin runs with the DNS hook only and does not see HTTP addresses.",
  "Modül özetini kopyala": "Copy the module digest",
  "İncele ve sabitle": "Review and pin",
  "İmzalı belgede sabitli ama bu bilgisayarın eklenti klasöründe yok.": "Pinned in the signed document but missing from this computer's plugin folder.",
  "Dosya yok": "No file",
  "Son eklenti olayları": "Recent plugin events",
  "Olaylarda sorgu adı veya adres bulunmaz.": "Events contain no query names or addresses.",

  // Blocking categories (plugins/types)
  Reklamlar: "Ads",
  İzleyiciler: "Trackers",
  "Kripto madencileri": "Crypto miners",
  "Akıllı TV ve IoT": "Smart TV and IoT",
  "İşletim sistemi telemetrisi": "Operating system telemetry",

  // Device cards (device-cards)
  "Tünel içinden bu cihaza ölçüm. Aynı anda tek test çalışır.": "Measured to this device through the tunnel. One test runs at a time.",
  "İndirme {down} Mbit/sn · Yükleme {up} Mbit/sn": "Download {down} Mbit/s · Upload {up} Mbit/s",
  "Henüz ölçüm yok.": "No measurements yet.",
  "Hız testi yap": "Run a speed test",
  "Bağlantı kalitesi": "Connection quality",
  "Son 7 gün, saatlik ortalama": "Last 7 days, hourly average",
  "Son gün, 5 dakikalık ortalama": "Last day, 5-minute average",
  "Bu aralıkta ölçüm yok.": "No measurements in this range.",
  "Ortalama gecikme {ms} ms · kayıp %{loss}": "Average latency {ms} ms · loss {loss}%",
  "Gecikme grafiği, {count} ölçüm": "Latency chart, {count} measurement|Latency chart, {count} measurements",
  "{at}: {ms} ms, kayıp %{loss}": "{at}: {ms} ms, loss {loss}%",
  "Son günü göster": "Show the last day",
  "Son 7 günü göster": "Show the last 7 days",
  "{device} için uyandırma paketi gönderildi.": "Wake packet sent for {device}.",
  "Uyandırma bu sürümde masaüstü servisine bağlı değil.": "In this version waking is not wired to the desktop service.",
  Uyandır: "Wake up",
  "Paket önce bu bilgisayardan, olmazsa aynı yerel ağdaki çevrimiçi bir cihazdan gönderilir.":
    "The packet is sent from this computer first, otherwise from an online device on the same local network.",
  "Uyandırma paketi gönder": "Send wake packet",
  "Ağ sürücüsü ayrıldı.": "Network drive disconnected.",
  "Ağ sürücüsü bağlandı.": "Network drive connected.",
  "Ağ sürücüsü bu sürümde masaüstü servisine bağlı değil.": "In this version the network drive is not wired to the desktop service.",
  "Ağ sürücüsü": "Network drive",
  "Paylaşım tünel adresinden bağlanır. Parola OpenScale'e gelmez, işletim sisteminin kasasında kalır.":
    "The share connects through the tunnel address. The password never reaches OpenScale; it stays in the operating system's credential store.",
  Bağla: "Connect",
  Ayır: "Disconnect",

  // Monitoring events (monitor-events)
  "Servis düştü": "Service down",
  "Servis döndü": "Service back",
  "Cihaz çevrimdışı": "Device offline",
  "Cihaz döndü": "Device back",
  "Cihaz katıldı": "Device joined",
  "Cihaz ayrıldı": "Device left",
  "Ad değişti": "Renamed",
  "Disk doluyor": "Disk filling up",
  "Disk düzeldi": "Disk OK again",
  "Pil yıpranmış": "Battery worn",
  "Pil azaldı": "Battery low",
  "Yeni LAN cihazı": "New LAN device",
  "Açık port": "Open port",
  "Port kapandı": "Port closed",
  "Saldırı belirtisi": "Sign of attack",
  "Engel listesi": "Blocklist",
  "İzlemenin bulduğu son olaylar: servis ve cihaz durumu, disk ve pil, yeni LAN cihazı, internete açık port ve tünel içi tarama belirtileri. Yalnızca bellekte tutulur; adres içermez.":
    "Recent events found by monitoring: service and device status, disk and battery, new LAN devices, ports open to the internet and signs of scanning inside the tunnel. Kept in memory only; contains no addresses.",
  "Olaylar alınamadı.": "Could not get the events.",
  "Henüz izleme olayı yok.": "No monitoring events yet.",

  // Monitoring (monitor-view)
  "Yanıt yok": "No response",
  Masaüstü: "Desktop",
  "E-posta (SMTP)": "Email (SMTP)",
  Pazar: "Sunday",
  Pazartesi: "Monday",
  Salı: "Tuesday",
  Çarşamba: "Wednesday",
  Perşembe: "Thursday",
  Cuma: "Friday",
  Cumartesi: "Saturday",
  "Servislerin ayakta olup olmadığını, izlemeye aldığınız cihazların çevrimdışı kalmasını ve disk ile pil uyarılarını izler. Bildirimler yalnızca sizin seçtiğiniz kanallara gider.":
    "Watches whether services are up, whether the devices you monitor go offline, and disk and battery warnings. Notifications go only to the channels you choose.",
  "Bu sürümde izleme masaüstü servisine bağlı değil. Servis güncellenince bu sayfa kendiliğinden dolar.":
    "In this version monitoring is not wired to the desktop service. This page fills in by itself once the service is updated.",
  "İzleme durumu alınamadı: {error}": "Could not get the monitoring status: {error}",
  Servisler: "Services",
  "HTTP ve TCP yoklaması yalnızca tünel adreslerine veya sizin eklediğiniz özel ağlara yapılır.":
    "HTTP and TCP probes go only to tunnel addresses or to private networks you added.",
  "İzlenen servis yok.": "No monitored services.",
  "{since} beri yanıt yok: {error}": "No response (since {since}): {error}",
  "{since} beri yanıt yok": "No response (since {since})",
  "Son yanıt {ms} ms · toplam kesinti {downtime}": "Last response {ms} ms · total downtime {downtime}",
  "Yalnızca izlemeye aldığınız cihazlar çevrimdışı olunca bildirim üretir.": "Only the devices you monitor send a notification when they go offline.",
  "Henüz cihaz bilgisi yok.": "No device information yet.",
  "Son görülme {at}": "Last seen {at}",
  İzleniyor: "Monitored",
  İzlenmiyor: "Not monitored",
  "{label} kanalına deneme bildirimi gönderildi.": "Test notification sent to the {label} channel.",
  "Sessiz saatler kaydedildi.": "Quiet hours saved.",
  "Bildirim kanalları": "Notification channels",
  "Masaüstü, ntfy, Gotify, Matrix ve e-posta. Gömülü bir sunucu yoktur; adresleri siz verirsiniz. Belirteç ve parolalar burada gösterilmez.":
    "Desktop, ntfy, Gotify, Matrix and email. There is no built-in server; you provide the addresses. Tokens and passwords are not shown here.",
  "Bildirim ayarları masaüstü servisine bağlanınca burada görünür.": "Notification settings appear here once the desktop service is connected.",
  "Kanal yok. Kanal eklemek için: openscale notify (servis sürümüyle gelir).":
    "No channels. To add a channel: openscale notify (comes with the service version).",
  "en az {priority} önem": "priority {priority} or higher",
  "saatte en çok {count}": "at most {count} per hour",
  "Deneme gönder": "Send test",
  "Sessiz saat başlangıcı": "Quiet hours start",
  Bitişi: "End",
  "Bu aralıkta yalnızca acil öncelikli bildirimler gönderilir. İki değer aynıysa sessiz saat kapalıdır.":
    "In this range only urgent notifications are sent. If both values are the same, quiet hours are off.",
  "Haftalık rapor": "Weekly report",
  "Kullanım, engellenen sorgu sayısı ve güncelleme bekleyen cihazlar. Raporda adres, MAC veya alan adı bulunmaz.":
    "Usage, the number of blocked queries and devices waiting for updates. The report contains no addresses, MACs or domains.",
  "Haftalık raporu gönder": "Send the weekly report",
  "{day} günü saat {hour}:00": "{day} at {hour}:00",
  "Servis bağlanınca ayarlanabilir.": "Can be set once the service is connected.",
  Önizleme: "Preview",
  "Önizleme alınamadı: {error}": "Could not get the preview: {error}",
}
