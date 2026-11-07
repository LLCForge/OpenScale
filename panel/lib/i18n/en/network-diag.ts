// English texts (#224), keyed by the Turkish source text. See lib/i18n/i18n.tsx.

export const enNetworkDiag: Record<string, string> = {
  // Address list input (resolver picker)
  "Geçerli bir IPv4 veya IPv6 adresi gir (port olmadan)": "Enter a valid IPv4 or IPv6 address (without a port)",
  "Bu adres zaten listede": "This address is already in the list",
  "En fazla {max} adres": "At most {max} addresses",
  "Seçili çözücüler": "Selected resolvers",
  "{address} adresini çıkar": "Remove {address}",
  "Seçili çözücü yok.": "No resolver selected.",
  "Cihaz adresleri": "Device addresses",
  "{addresses} ağdaki bir cihazın tünel adresi değil; sunucu bu adresi kabul etmez.":
    "{addresses}: not the tunnel address of a device in the network; the server will not accept it.",

  // Join bundle download
  "Katılım paketini indir": "Download join bundle",

  // Coordinator form and dialog
  "Adres gerekli": "Address is required",
  "host:port biçiminde olmalı, ör. vpn.ornek.com:51820 veya 203.0.113.5:51820":
    "Must be in host:port form, e.g. vpn.example.com:51820 or 203.0.113.5:51820",
  "44 karakterlik base64 WireGuard anahtarı olmalı": "Must be a 44-character base64 WireGuard key",
  "XXXX-XXXX-XXXX-XXXX biçiminde olmalı": "Must be in XXXX-XXXX-XXXX-XXXX form",
  "Genel adres ve port": "Public address and port",
  "vpn.ornek.com:51820": "vpn.example.com:51820",
  "VPS'in IP adresi veya ev sunucun için dinamik DNS adı. UDP portu internete açık olmalı.":
    "The VPS's IP address, or a dynamic DNS name for your home server. The UDP port must be reachable from the internet.",
  "WireGuard açık anahtarı": "WireGuard public key",
  "Koordinatör parmak izi": "Coordinator fingerprint",
  "Sunucuda `openscale coordinator keygen` çıktısındakini elle yaz; eşleşmezse kaydedilmez.":
    "Type in the one from the `openscale coordinator keygen` output on the server; it is not saved if it does not match.",
  "Koordinatörü değiştir": "Change coordinator",
  "Koordinatör ekle": "Add coordinator",
  "Koordinatör cihazların birbirini bulmasını sağlar; ağ belgesini değiştiremez ve trafiği göremez.":
    "The coordinator lets devices find each other; it cannot change the network document and cannot see traffic.",

  // Coordinator independence (cross-checking, hardening)
  "Çapraz denetim": "Cross-checking",
  "Cihazlar belgeyi birden fazla koordinatörden alıp karşılaştırır; farklı sağlayıcı ve bölgeler bir koordinatörün yalan söylemesini görünür kılar.":
    "Devices fetch the document from more than one coordinator and compare; different providers and regions make a lying coordinator visible.",
  "Bölge bilinmiyor": "Region unknown",
  "Koordinatörler farklı bölgelerde; cihazlar belgeleri birbirine karşı denetleyebilir.":
    "The coordinators are in different regions; devices can check documents against each other.",
  "Sunucu sertleştirmesi": "Server hardening",
  "Koordinatör sertleştirmesi sunucuda 'openscale coordinator harden' ile açılır: port gizleme, kayıt tutmama, yalnızca RAM, kör koordinatör, klon karantinası.":
    "Coordinator hardening is turned on on the server with 'openscale coordinator harden': port hiding, no logging, RAM only, blind coordinator, clone quarantine.",
  "Sunucuda çalıştırın": "Run on the server",
  "Panel koordinatörde çalışmadığı için bu ayarlar buradan değiştirilmez.":
    "The panel does not run on the coordinator, so these settings cannot be changed here.",

  // Coordinator observation (this device)
  "Bu cihazın gözlemi": "This device's view",
  "Gözlem yok": "No observations",
  "Panel bu bilgisayarın tünel hizmetine bağlı değil; koordinatör yanıtları yalnızca tünel çalışırken izlenir.":
    "The panel is not connected to this computer's tunnel service; coordinator replies are tracked only while the tunnel is running.",
  "Cihaz her koordinatörün yanıtını ve bildirdiği belge sürümünü izler. Biri susarken diğerleri yanıt veriyorsa o koordinatör bu cihazı sansürlüyor olabilir.":
    "The device tracks each coordinator's replies and the document version it reports. If one goes silent while the others reply, that coordinator may be censoring this device.",
  "Henüz gözlem yok": "No observations yet",
  "Tünel açıldıktan sonra koordinatör yanıtları burada görünür.": "Coordinator replies appear here once the tunnel is up.",
  "Son yanıt {ago}, ardından {count} başarısız deneme":
    "Last reply {ago}, then {count} failed attempt|Last reply {ago}, then {count} failed attempts",
  "Son yanıt {ago}": "Last reply {ago}",
  "Bu açılıştan beri yanıt alınmadı.": "No reply since this start.",
  "Yanıt veriyor": "Replying",
  Susuyor: "Silent",
  "Bir koordinatör son 10 dakikadır yanıt vermiyor, diğerleri veriyor. Sunucunun çalıştığını sağlayıcısından denetleyin; sürerse çapraz denetim eksik kalır.":
    "One coordinator has not replied for the last 10 minutes while the others have. Check with its provider that the server is running; if it continues, cross-checking stays incomplete.",
  "{count} koordinatör son 10 dakikadır yanıt vermiyor, diğerleri veriyor. Sunucunun çalıştığını sağlayıcısından denetleyin; sürerse çapraz denetim eksik kalır.":
    "{count} coordinator has not replied for the last 10 minutes while the others have. Check with its provider that the server is running; if it continues, cross-checking stays incomplete.|{count} coordinators have not replied for the last 10 minutes while the others have. Check with their providers that the servers are running; if it continues, cross-checking stays incomplete.",

  // Coordinators card
  Birincil: "Primary",
  Ek: "Additional",
  "Bu cihaz bağlı": "This device is connected",
  "Geçiş süresi bitti": "Grace period over",
  "Geçiş süresi: {date} tarihine kadar": "Grace period: until {date}",
  "Gecikme {ms} ms": "Latency {ms} ms",
  "Gecikme bilinmiyor": "Latency unknown",
  "son yanıt {time}": "last reply {time}",
  "{count} başarısız deneme": "{count} failed attempt|{count} failed attempts",
  "Bütünlük uyarıları": "Integrity warnings",
  Kritik: "Critical",

  // Coordinators page
  "Birincil koordinatör": "Primary coordinator",
  "Cihazlar bu adrese WireGuard ile bağlanır; kontrol trafiği tünel içindedir.":
    "Devices connect to this address over WireGuard; control traffic stays inside the tunnel.",
  Tanımlı: "Configured",
  "Genel adres": "Public address",
  "Genel adresi kopyala": "Copy public address",
  "Parmak izini kopyala": "Copy fingerprint",
  "WireGuard anahtarı": "WireGuard key",
  "WireGuard anahtarını kopyala": "Copy WireGuard key",
  "Tünel içi adres": "Tunnel address",
  "Koordinatör tanımlı değil; cihazlar birbirini bulamaz.": "No coordinator is configured; devices cannot find each other.",
  "Tüm koordinatörler": "All coordinators",
  "Belgedeki ek koordinatörler ve bu bilgisayarın onlara bağlantısı.":
    "The additional coordinators in the document and this computer's connection to them.",
  "Sunucu kurulumu": "Server setup",
  "Koordinatörü bir VPS'te veya ev sunucusunda çalıştırma.": "Running the coordinator on a VPS or a home server.",
  "Kurulum komutları": "Setup commands",
  "Linux sunucuda root olarak çalıştırılır.": "Run as root on a Linux server.",
  "Komutları göster": "Show commands",
  "Komutları gizle": "Hide commands",
  "Çıkan anahtarı ve parmak izini \"Koordinatör ekle\" ile kaydet, sonra katılım paketini sunucuya kopyalayıp:":
    "Save the printed key and fingerprint with \"Add coordinator\", then copy the join bundle to the server and run:",
  "Ev sunucusunda modemde 51820/UDP'yi sunucuya yönlendir ve adres olarak dinamik DNS adını kullan.":
    "For a home server, forward 51820/UDP on the router to the server and use the dynamic DNS name as the address.",
  "Yanlış adres veya anahtar bütün cihazların bağlantısını keser; değişiklik belgeye imzalanır.":
    "A wrong address or key cuts off every device; the change is signed into the document.",
  Değiştir: "Change",

  // DNS dialog
  "{first} ve {second}": "{first} and {second}",
  "En fazla {max} çözücü": "At most {max} resolvers",
  "Geçersiz adres": "Invalid address",
  "Alan adı gerekli": "Domain is required",
  "En fazla 253 karakter": "At most 253 characters",
  "Küçük harf, rakam ve tireden oluşan etiketler; nokta ile ayrılır, ör. lan veya ev.lan":
    "Labels of lowercase letters, digits and hyphens, separated by dots, e.g. lan or home.lan",
  "{domains} ile aynı olamaz veya çakışamaz; bu alanları MagicDNS çözer":
    "Cannot be the same as or overlap {domains}; MagicDNS resolves these domains",
  "Bu alan için en az bir çözücü seç": "Choose at least one resolver for this domain",
  "En fazla {max} alan adı": "At most {max} domains",
  "En az bir genel çözücü veya bir alan adı gir. Bölümü kaldırmak için karttaki \"Kaldır\" düğmesini kullan.":
    "Enter at least one global resolver or one domain. To remove the section, use the \"Remove\" button on the card.",
  "Bu alan adı iki kez yazılmış": "This domain is entered twice",
  "Ağ DNS ayarları": "Network DNS settings",
  "Değişikliği kontrol et ve kök anahtarınla imzala.": "Check the change and sign it with your root key.",
  "Cihazlar, ağdan gelen DNS ayarlarını kabul ediyorsa bu çözücüleri kullanır. MagicDNS adları her zaman çalışmaya devam eder.":
    "Devices that accept DNS settings from the network use these resolvers. MagicDNS names always keep working.",
  "Genel çözücüler": "Global resolvers",
  "Bütün sorgular bu adreslere gider (en fazla {max}). Boş bırakırsan cihazlar kendi çözücülerini kullanır; yalnızca aşağıdaki alan adları yönlendirilir.":
    "All queries go to these addresses (at most {max}). If you leave it empty, devices use their own resolvers; only the domains below are routed.",
  "Alan adına göre yönlendirme": "Split DNS",
  "Yalnızca bu alan adlarındaki sorgular (ör. ev ağındaki \"lan\") seçtiğin çözücüye gider. En fazla {maxSplit} alan, her biri için 1-{max} çözücü.":
    "Only queries for these domains (e.g. \"lan\" on a home network) go to the resolver you choose. At most {maxSplit} domains, 1-{max} resolvers each.",
  "Yönlendirilen alan adı yok.": "No routed domains.",
  "Alan adı": "Domain",
  "{number}. alan adını kaldır": "Remove domain {number}",
  Çözücüler: "Resolvers",
  "Alan adı ekle": "Add domain",

  // DNS note
  "Genel internet çözücüleri (ör. 1.1.1.1) kabul edilmez; çözücü olarak yalnızca ağdaki bir cihazın tünel adresi seçilebilir ve o cihaza 53. port için erişim kuralı gerekir. Eski sürümlü cihazlar DNS bölümü olan belgeyi reddeder; önce bütün cihazları güncelleyin.":
    "Public internet resolvers (e.g. 1.1.1.1) are not accepted; only the tunnel address of a device in the network can be a resolver, and that device needs an access rule for port 53. Devices on older versions reject a document with a DNS section; update all devices first.",

  // DNS page
  "Cihazların adları nasıl çözdüğü: MagicDNS, ad sunucuları ve alan adına göre yönlendirme.":
    "How devices resolve names: MagicDNS, nameservers and split DNS.",
  "DNS bölümünü kaldır": "Remove DNS section",
  "Ağın DNS ayarları belgeden kaldırılır; cihazlar yeniden kendi çözücülerini kullanır. MagicDNS etkilenmez.":
    "The network's DNS settings are removed from the document; devices go back to their own resolvers. MagicDNS is not affected.",
  "Ağ DNS adı": "Network DNS name",
  "Cihazlar bu alanın altında kendi adlarıyla çözülür.": "Devices resolve under this domain by their own names.",
  "Örneğin masaustu.{domain}; ad yalnızca ağ içinde geçerlidir.": "For example desktop.{domain}; the name is valid only inside the network.",
  "Alan adını kopyala": "Copy domain",
  "Ad sunucuları": "Nameservers",
  "Cihazların DNS sorgularını gönderdiği çözücüler.": "The resolvers devices send their DNS queries to.",
  "Ad sunucusu ekle": "Add nameserver",
  "Ağ içindeki adları {resolver} yanıtlar; bu çözücü her zaman açıktır.":
    "{resolver} answers for names inside the network; this resolver is always on.",
  Kilitli: "Locked",
  "Ağ geneli çözücüler": "Network-wide resolvers",
  "Diğer bütün sorgular bu çözücülere gider.": "All other queries go to these resolvers.",
  "Tanımlı değil; cihazlar kendi çözücülerini kullanır.": "Not set; devices use their own resolvers.",
  "Çözücü olarak yalnızca ağdaki bir cihazın tünel adresi seçilebilir ve o cihaza 53. port için erişim kuralı gerekir. Eski sürümlü cihazlar DNS bölümü olan belgeyi reddeder.":
    "Only the tunnel address of a device in the network can be a resolver, and that device needs an access rule for port 53. Devices on older versions reject a document with a DNS section.",
  "Belirli alan adlarının sorgularını ayrı çözücülere gönderir.": "Sends queries for specific domains to separate resolvers.",
  "Alan adına göre yönlendirme yok.": "No split DNS.",
  "Arama alanları": "Search domains",
  "Kısa adlara eklenen alanlar; örneğin ssh masaustu.": "Domains appended to short names; for example ssh desktop.",
  "Arama alanı yok. Eklemek için:": "No search domains. To add one:",
  "Cihaz adlarının ağ içinde kendiliğinden çözülmesi.": "Device names resolve automatically inside the network.",
  "Her zaman açık": "Always on",
  "Her cihaz <ad>.{domain} olarak çözülür; ad sunucusu ayarlarından bağımsız çalışır.":
    "Each device resolves as <name>.{domain}; this works independently of the nameserver settings.",
  "Cihaz alt alanları": "Device subdomains",
  "Açıkken web.nas.{domain} gibi adlar da cihaza çözülür.": "When on, names like web.nas.{domain} also resolve to the device.",
  "Ek kayıtlar": "Extra records",
  "Alanın altındaki takma adlar ve SRV/TXT kayıtları; openscale network dns ile yönetilir.":
    "Aliases and SRV/TXT records under the domain; managed with openscale network dns.",
  "Ad sunucuları ve split DNS belgeden kaldırılır; cihazlar yeniden kendi çözücülerini kullanır.":
    "Nameservers and split DNS are removed from the document; devices go back to their own resolvers.",

  // Exit node users
  "Bütün cihazlar ağdaki çıkış düğümlerini kullanabilir.": "All devices can use the network's exit nodes.",
  "Hiçbir cihaz çıkış düğümü kullanamaz.": "No device can use an exit node.",
  "Yalnızca listedeki cihazlar çıkış düğümü seçebilir.": "Only the listed devices can choose an exit node.",
  "Çıkış düğümü kullanıcıları": "Exit node users",
  Kimse: "Nobody",
  Herkes: "Everyone",
  "Kırmızı etiketler hiçbir cihazda yok; bu başvurular hiçbir şeyle eşleşmez.":
    "The tags in red are on no device; these references match nothing.",
  "En fazla {max} giriş": "At most {max} entries",
  "En az bir cihaz, etiket veya grup seç; kimse kullanmasın istiyorsan \"Hiçbir cihaz\" seçeneğini seç":
    "Choose at least one device, tag or group; if nobody should use them, choose \"No device\"",
  "Bütün cihazlar": "All devices",
  "Her cihaz çıkış düğümlerini kullanabilir (varsayılan).": "Every device can use exit nodes (default).",
  "Yalnızca seçilenler": "Only selected",
  "Yalnızca seçtiğin cihazlar, etiketler ve gruplar kullanabilir.": "Only the devices, tags and groups you choose can use them.",
  "Hiçbir cihaz": "No device",
  "Hiçbir cihaz çıkış düğümü kullanamaz; roller belgede kalır.": "No device can use an exit node; the roles stay in the document.",
  "Kimlerin internet trafiğini ağdaki çıkış düğümleri üzerinden çıkarabileceğini seç. Cihazlar arası erişim kuralları bundan etkilenmez.":
    "Choose who can send internet traffic out through the network's exit nodes. Access rules between devices are not affected.",
  "Kimler kullanabilir?": "Who can use them?",
  "Kısıtlama boş bir listeyle kaydedilir: ağdaki hiçbir cihaz çıkış düğümü kullanamaz.":
    "The restriction is saved with an empty list: no device in the network can use an exit node.",
  Kullanabilecekler: "Allowed users",
  "Cihazlar, etiketler ve gruplar.": "Devices, tags and groups.",

  // Install commands (command-line join steps)
  "Yönetici olarak açılmış PowerShell'de:": "in PowerShell opened as administrator:",
  "root olarak (sudo ile):": "as root (with sudo):",
  "OpenScale'i yükle": "Install OpenScale",
  "openscale.exe dosyasını bu bilgisayara kopyala ve PATH'e ekle (ör. C:\\Program Files\\OpenScale).":
    "Copy openscale.exe to this computer and add it to PATH (e.g. C:\\Program Files\\OpenScale).",
  "openscale ikilisini /usr/local/bin/openscale konumuna kopyala ve çalıştırılabilir yap.":
    "Copy the openscale binary to /usr/local/bin/openscale and make it executable.",
  "Cihaz anahtarlarını üret": "Generate device keys",
  "Kayıt isteğini panele ekle": "Add the enrollment request in the panel",
  "Çıkan osreq1... satırını Cihazlar > Cihaz ekle'ye yapıştır ve ekrandaki parmak izini panelde yaz.":
    "Paste the printed osreq1... line into Devices > Add device and type the fingerprint shown on screen into the panel.",
  "Ağa katıl": "Join the network",
  "Tüneli aç ({elevated})": "Bring the tunnel up ({elevated})",
  "Android / iOS (yakında)": "Android / iOS (coming soon)",
  "Komut satırıyla kurulum": "Command-line setup",

  // Blind coordinator (members-only document)
  "Kör koordinatör": "Blind coordinator",
  "Cihaz adları, etiketler, kurallar ve DNS ayarları belgede yalnızca üyelerin açabileceği şekilde şifrelenir; koordinatör bunları göremez.":
    "Device names, tags, rules and DNS settings are encrypted in the document so that only members can open them; the coordinator cannot see them.",
  "Belgeyi üyelere mühürle": "Seal the document to members",
  "Asgari istemci sürümü şu an {version}.": "The minimum client version is currently {version}.",
  "Asgari istemci sürümü belirlenmemiş.": "No minimum client version is set.",
  "Kör koordinatör kipini aç": "Turn on blind coordinator mode",
  "Kör koordinatör kipini kapat": "Turn off blind coordinator mode",
  "Yeni sürüm üyelere mühürlenmiş olarak imzalanır. Koordinatörün de kör çalışması için sunucuda 'openscale coordinator harden --blind on' çalıştırın.":
    "The new version is signed sealed to members. For the coordinator to run blind as well, run 'openscale coordinator harden --blind on' on the server.",
  "Yeni sürüm mühürsüz imzalanır; cihaz adları, etiketler ve kurallar yeniden koordinatöre görünür.":
    "The new version is signed unsealed; device names, tags and rules become visible to the coordinator again.",
  "İmzalamadan önce": "Before signing",

  // Network name
  "Ad gerekli; adı kaldırmak için \"Adı kaldır\" düğmesini kullan": "Name is required; to remove the name, use the \"Remove name\" button",
  "Başta veya sonda boşluk olamaz": "Cannot start or end with a space",
  "Ad verilmemiş; panel ve uygulamalar yalnızca ağ kimliğini gösterir.": "No name set; the panel and the apps show only the network ID.",
  "Ad ver": "Set name",
  "Ağ adını kaldır": "Remove network name",
  "Ağın görünen adı belgeden kaldırılır; panel ve uygulamalar adı göstermez.":
    "The network's display name is removed from the document; the panel and the apps no longer show a name.",
  "Ağ adını değiştir": "Change network name",
  "Ağa ad ver": "Name the network",
  "Ad ağ belgesine imzalanır.": "The name is signed into the network document.",
  "Ad değişmedi": "The name did not change",
  "Ev ağı": "Home network",
  "En fazla 64 karakter; Türkçe karakter ve boşluk kullanılabilir.": "Up to 64 characters; non-English letters and spaces are allowed.",

  // Network report
  "Okunur rapor": "Readable report",
  "Ağın cihazlarını, kurallarını ve adlarını düz metin olarak indir.": "Download the network's devices, rules and names as plain text.",
  "Raporu indir": "Download report",
  "Rapor anahtar, parmak izi veya davet kodu içermez; ağa giriş sağlamaz. Cihaz adlarını, tünel adreslerini, kuralları ve koordinatör adresini içerir; kimle paylaştığına dikkat et.":
    "The report contains no keys, fingerprints or invite codes; it gives no way into the network. It does contain device names, tunnel addresses, rules and the coordinator address; be careful who you share it with.",
  "Markdown indir": "Download Markdown",
  "HTML indir": "Download HTML",
  "Kurallar cümle olarak": "Rules as sentences",
  "Raporun kural bölümünün önizlemesi.": "A preview of the report's rules section.",
  Önizle: "Preview",
  "Ağda kural yok; hiçbir cihaz başka cihaza ulaşamaz.": "The network has no rules; no device can reach another device.",
  "(kapalı)": "(disabled)",

  // Network page
  "Ağ belgesinde imzalı, bütün cihazların gördüğü bilgiler.": "Information signed in the network document and seen by every device.",
  "Ağ kimliği": "Network ID",
  "Ağı diğer OpenScale ağlarından ayıran kimlik.": "The ID that tells this network apart from other OpenScale networks.",
  "Ağ kimliğini kopyala": "Copy network ID",
  "Adres aralıkları": "Address ranges",
  "Cihazların tünel içi adresleri bu aralıklardan verilir.": "Devices' tunnel addresses are assigned from these ranges.",
  "Belge sürümü": "Document version",
  "Her imzalı değişiklik sürümü bir artırır.": "Every signed change raises the version by one.",
  Katılım: "Joining",
  "Yeni cihazlar kök anahtarı bu bilgilerle doğrular.": "New devices verify the root key with this information.",
  "Kök anahtar parmak izi": "Root key fingerprint",
  "Yeni bir cihazda katılırken yazılan parmak izi.": "The fingerprint typed in on a new device when joining.",
  "Katılım paketi": "Join bundle",
  "Kök anahtarı ve koordinatörü tanıtan paket; yalnızca açık bilgi içerir.":
    "The bundle that introduces the root key and the coordinator; it contains only public information.",
  "Yeni bir bilgisayarı ağa katmak için o bilgisayarda çalıştırılacak adımlar.": "The steps to run on a new computer to join it to the network.",
  "Adımları göster": "Show steps",
  "Adımları gizle": "Hide steps",
  "İnternet trafiğini ağdaki bir cihaz üzerinden çıkarma.": "Sending internet traffic out through a device in the network.",

  // Root key verification code
  "Ağın doğrulama kodu": "Network verification code",
  "Katılan cihazın gösterdiği kök anahtar kodu bununla aynı olmalı; farklıysa başka bir ağa bağlanıyordur.":
    "The root key code shown by the joining device must match this; if it differs, the device is joining a different network.",
}
