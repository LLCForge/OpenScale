// English texts (#224), keyed by the Turkish source text. See lib/i18n/i18n.tsx.
//
// The error code catalog (internal/errcode/catalog.go): title, cause and
// steps of every code, shown by the error code dialog and the
// troubleshooting page. Titles also feed error-codes-en.ts.

export const enErrcodes: Record<string, string> = {
  // OS-1001
  "Kök anahtar parolası yanlış": "Wrong root key passphrase",
  "Girilen parola kök anahtar dosyasını açmadı; parola yanlış yazıldı veya dosya bozuldu.": "The passphrase entered did not open the root key file; it was mistyped or the file is corrupted.",
  "Büyük/küçük harfi ve klavye dilini denetleyip parolayı yeniden yazın.": "Check upper/lower case and the keyboard language, then type the passphrase again.",
  "Parolayı hatırlamıyorsanız kök anahtarı parolalı yedekten geri yükleyin: openscale network restore.": "If you do not remember the passphrase, restore the root key from the passphrase-protected backup: openscale network restore.",
  "Dosya bozulduysa yedekten geri yükleyin; yedek yoksa ağ yeniden kurulmalıdır.": "If the file is corrupted, restore it from a backup; without a backup the network must be set up again.",

  // OS-1002
  "İmza doğrulanamadı": "Signature could not be verified",
  "Ağ belgesinin veya bir dosyanın imzası bu ağın kök anahtarıyla doğrulanmadı; dosya yolda değişmiş, başka bir ağa ait veya başka bir amaçla imzalanmış.": "The signature of the network document or a file was not verified with this network's root key; the file was changed on the way, belongs to another network or was signed for another purpose.",
  "Dosyayı yeniden ve güvendiğiniz bir kanaldan alın.": "Get the file again through a channel you trust.",
  "Dosyanın doğru ağa ait olduğunu kök parmak iziyle denetleyin.": "Check with the root fingerprint that the file belongs to the right network.",
  "Tekrarlıyorsa denetim kaydına bakın; birisi belgeyi değiştirmeye çalışıyor olabilir.": "If it keeps happening, look at the audit log; someone may be trying to change the document.",

  // OS-1003
  "Ağ belgesinin süresi doldu": "Network document has expired",
  "İmzalı ağ belgesinin geçerlilik süresi geçti; cihazlar süresi dolmuş belgeyle yeni bağlantı kurmaz.": "The signed network document is past its validity period; devices do not make new connections with an expired document.",
  "Yönetici bilgisayarda belgeyi yenileyin: openscale network renew --dir ./ag.": "Renew the document on the admin computer: openscale network renew --dir ./ag.",
  "Cihazlar yeni belgeyi koordinatörden kendiliğinden alır; almıyorsa OS-3001'e bakın.": "Devices get the new document from the coordinator by themselves; if they do not, see OS-3001.",
  "Saatin doğru olduğunu denetleyin; yanlış saat süresi dolmuş gibi görünmeye yol açar.": "Check that the clock is correct; a wrong clock can make the document look expired.",

  // OS-1004
  "Eski belge reddedildi (geri alma)": "Older document rejected (rollback)",
  "Bu cihazın gördüğünden daha eski sürümlü bir belge sunuldu; eski kurallara dönmeyi önlemek için reddedildi.": "A document older than the version this device has seen was offered; it was rejected to prevent going back to old rules.",
  "Koordinatörün güncel belgeyi sunduğunu denetleyin (koordinatör yedekten geri yüklendiyse eski kalmış olabilir).": "Check that the coordinator serves the current document (it may be outdated if the coordinator was restored from a backup).",
  "Yönetici bilgisayarda belgeyi yeniden imzalayın: openscale network renew.": "Sign the document again on the admin computer: openscale network renew.",
  "Sebebini bilmiyorsanız denetim kaydını inceleyin.": "If you do not know the reason, review the audit log.",

  // OS-1005
  "Çelişkili belge görüldü": "Conflicting document seen",
  "Aynı sürüm numarasıyla iki farklı belge veya güncel belgeyle çelişen bir kök geçişi görüldü; kök anahtar kötüye kullanılmış olabilir.": "Two different documents with the same version number, or a root transition that conflicts with the current document, were seen; the root key may have been misused.",
  "Kök anahtarın bulunduğu bilgisayarları denetleyin; parola başkasıyla paylaşıldı mı?": "Check the computers that hold the root key; was the passphrase shared with someone?",
  "Kök anahtar ele geçirildiyse kurtarma anahtarıyla kök geçişi yapın.": "If the root key was compromised, perform a root transition with the recovery key.",
  "Bütün cihazlardaki denetim kayıtlarını karşılaştırın.": "Compare the audit logs on all devices.",

  // OS-1006
  "Başka ağa ait veri veya parmak izi uyuşmuyor": "Data from another network or fingerprint mismatch",
  "Paket, yedek veya belge bu ağın kök anahtarıyla eşleşmiyor; başka bir ağa ait ya da yolda değiştirilmiş.": "The bundle, backup or document does not match this network's root key; it belongs to another network or was changed on the way.",
  "Yönetici ekranındaki kök parmak iziyle karşılaştırın.": "Compare it with the root fingerprint on the admin screen.",
  "Doğru ağ klasörünü (--dir veya --network) seçtiğinizi denetleyin.": "Check that you chose the right network folder (--dir or --network).",
  "Paketi yöneticiden yeniden isteyin.": "Ask the admin for the bundle again.",

  // OS-1007
  "Desteklenmeyen imza algoritması": "Unsupported signature algorithm",
  "Veri bu sürümün tanımadığı bir algoritmayla imzalanmış; genellikle bu cihazdaki OpenScale eskidir.": "The data is signed with an algorithm this version does not know; usually OpenScale on this device is out of date.",
  "Bu cihazdaki OpenScale'i güncelleyin.": "Update OpenScale on this device.",
  "Güncelleme sonrası da sürüyorsa dosyanın kaynağını denetleyin.": "If it continues after the update, check where the file came from.",

  // OS-1008
  "Parola yeterince güçlü değil": "Passphrase is not strong enough",
  "Yeni parola çok kısa, tekrar eden karakterlerden oluşuyor veya kolay tahmin edilir.": "The new passphrase is too short, consists of repeated characters or is easy to guess.",
  "Birbiriyle ilgisiz dört beş kelimeden veya rastgele karakterlerden bir parola seçin.": "Choose a passphrase of four or five unrelated words or random characters.",
  "Parolanın gücünü önceden ölçün: openscale key strength.": "Measure the passphrase strength first: openscale key strength.",

  // OS-1009
  "Belge başka yerden değiştirildi": "Document was changed elsewhere",
  "Değişiklik hazırlanırken ağ belgesi başka bir yerde (ör. başka bir CLI veya panel) değişti; üzerine yazmamak için işlem durdu.": "While the change was being prepared, the network document changed elsewhere (e.g. another CLI or panel); the operation stopped so as not to overwrite it.",
  "Sayfayı yenileyin veya komutu yeniden çalıştırın.": "Refresh the page or run the command again.",
  "Aynı ağı aynı anda iki yerden yönetmeyin.": "Do not manage the same network from two places at the same time.",

  // OS-1010
  "Kayıtlı belge bozuk": "Saved document is corrupted",
  "Bu cihazdaki ağ belgesi okunamadı ve geçerli bir kopyası kalmadı.": "The network document on this device could not be read and no valid copy is left.",
  "Başka bir cihazdan network.json kopyalayın.": "Copy network.json from another device.",
  "Onarın: openscale state repair --document <network.json>.": "Repair it: openscale state repair --document <network.json>.",

  // OS-1011
  "Rastgele sayı üreteci sağlıksız": "Random number generator is unhealthy",
  "İşletim sisteminin rastgele sayı üreteci sağlık denetiminden geçmedi; güvenlik için anahtar üretilmedi.": "The operating system's random number generator failed its health check; no key was generated for safety.",
  "Bilgisayarı yeniden başlatıp yeniden deneyin.": "Restart the computer and try again.",
  "Sanal makinedeyseniz sanal makineye rastgelelik kaynağı (virtio-rng) ekleyin.": "On a virtual machine, add a randomness source (virtio-rng) to it.",

  // OS-1012
  "Belge henüz geçerli değil (saat farkı)": "Document is not valid yet (clock difference)",
  "Belgenin başlangıç zamanı bu cihazın saatine göre gelecekte; genellikle cihazın saati yanlıştır.": "The document's start time is in the future according to this device's clock; usually the device's clock is wrong.",
  "Cihazın saatini ve saat dilimini düzeltin (otomatik saat eşitlemesini açın).": "Fix the device's time and time zone (turn on automatic time sync).",
  "Saat doğruysa yönetici bilgisayarın saatini denetleyin.": "If the clock is correct, check the clock of the admin computer.",

  // OS-2001
  "Bu cihaz henüz bir ağa katılmamış": "This device has not joined a network yet",
  "Seçilen durum klasöründe katılım bilgisi yok.": "The chosen state folder has no join information.",
  "Katılım paketiyle katılın: openscale join, veya davet koduyla: openscale invite-join.": "Join with a join bundle: openscale join, or with an invite code: openscale invite-join.",
  "Başka bir klasör veya ağ profili kullanıyorsanız --state-dir ya da --network verin.": "If you use another folder or network profile, pass --state-dir or --network.",

  // OS-2002
  "Cihaz ağ belgesinde yok": "Device is not in the network document",
  "Bu cihaz iptal edilmiş, üyeliği bitmiş veya henüz eklenmemiş.": "This device was revoked, its membership ended or it has not been added yet.",
  "Yöneticiden cihazı eklemesini veya üyeliğini uzatmasını isteyin.": "Ask the admin to add the device or extend its membership.",
  "İptal edildiyse yeni anahtar üretip yeniden katılın: openscale keygen.": "If it was revoked, generate a new key and join again: openscale keygen.",

  // OS-2003
  "İsteğin süresi doldu": "Request has expired",
  "Kayıt veya anahtar yenileme isteğinin süresi geçti.": "The enrollment or key rotation request is past its validity.",
  "Cihazda isteği yeniden oluşturun (openscale keygen veya openscale device rotate-key).": "Create the request again on the device (openscale keygen or openscale device rotate-key).",
  "Yeni isteği süre dolmadan yöneticiye ulaştırın.": "Get the new request to the admin before it expires.",

  // OS-2004
  "Doğrulama kodu veya parmak izi eşleşmedi": "Verification code or fingerprint did not match",
  "İki tarafta görünen kısa kodlar veya parmak izleri farklı; istek yolda değişmiş olabilir, cihaz eklenmedi.": "The short codes or fingerprints shown on the two sides differ; the request may have been changed on the way, the device was not added.",
  "İsteği yeniden ve doğrudan (yüz yüze, telefonla) doğrulanan bir kanaldan alın.": "Get the request again through a directly verified channel (in person, by phone).",
  "Kodları sesli okuyup karşılaştırın.": "Read the codes aloud and compare them.",

  // OS-2005
  "Davet geçersiz": "Invalid invite",
  "Davet bulunamadı, süresi doldu, kullanıldı, başka bir cihaza verildi veya koordinatör kaydı reddetti.": "The invite was not found, expired, was used, was given to another device or the coordinator rejected the enrollment.",
  "Yöneticiden yeni bir davet kodu isteyin: openscale invite create.": "Ask the admin for a new invite code: openscale invite create.",
  "Kodu eksiksiz kopyaladığınızı denetleyin.": "Check that you copied the code completely.",

  // OS-2006
  "Cihaz adı kullanılamaz": "Device name cannot be used",
  "Ad başka bir cihazda kullanılıyor, koordinatöre ayrılmış veya izin verilmeyen karakter içeriyor.": "The name is used by another device, reserved for the coordinator or contains characters that are not allowed.",
  "Yalnızca küçük harf, rakam ve tire kullanın (en çok 63 karakter).": "Use only lowercase letters, digits and hyphens (at most 63 characters).",
  "Başka bir ad seçin; 'coordinator' ayrılmıştır.": "Choose another name; 'coordinator' is reserved.",

  // OS-2007
  "Cihaz kimliği başka bilgisayardan kopyalanmış": "Device identity was copied from another computer",
  "Bu durum klasörü başka bir bilgisayarda oluşturulmuş; aynı kimlik iki bilgisayarda ağda çakışır.": "This state folder was created on another computer; the same identity on two computers conflicts in the network.",
  "Bilerek taşıdıysanız: openscale device rebind.": "If you moved it on purpose: openscale device rebind.",
  "Değilse bu bilgisayarı yeni bir davetle ayrı cihaz olarak ekleyin.": "Otherwise add this computer as a separate device with a new invite.",

  // OS-2008
  "Ağın adres alanı doldu": "Network address space is full",
  "Ağın IP aralığında yeni cihaza verilecek adres kalmadı.": "There is no address left in the network's IP range for a new device.",
  "Kullanılmayan cihazları kaldırın: openscale device inactive, sonra device revoke.": "Remove unused devices: openscale device inactive, then device revoke.",
  "Gerekirse ağı daha geniş bir aralığa taşıyın: openscale network readdress.": "If needed, move the network to a larger range: openscale network readdress.",

  // OS-3001
  "Koordinatör yanıt vermiyor": "Coordinator is not responding",
  "Koordinatöre UDP ile ulaşılamadı: sunucu kapalı, port kapalı, adres yanlış veya bu ağ UDP'yi engelliyor.": "The coordinator could not be reached over UDP: the server is down, the port is closed, the address is wrong or this network blocks UDP.",
  "Koordinatör sunucusunun çalıştığını denetleyin (sunucuda: openscale service status).": "Check that the coordinator server is running (on the server: openscale service status).",
  "Sunucunun güvenlik duvarında ve bulut güvenlik grubunda UDP portunun açık olduğunu denetleyin.": "Check that the UDP port is open in the server's firewall and the cloud security group.",
  "Bu ağ UDP'yi engelliyorsa (otel, şirket) TCP yedeğine düşülür; adresini denetleyin: openscale get tcp-fallback (boşsa koordinatör:443; sunucuda 443/tcp açık olmalı).": "If this network blocks UDP (hotel, company), the TCP fallback is used; check its address: openscale get tcp-fallback (if empty, coordinator:443; 443/tcp must be open on the server).",
  "Belgedeki koordinatör adresini denetleyin: openscale network show.": "Check the coordinator address in the document: openscale network show.",

  // OS-3002
  "Doğrudan bağlantı kurulamıyor, aktarıcı kullanılıyor": "No direct connection, using a relay",
  "İki cihazın NAT türleri (genellikle simetrik NAT veya CGNAT) doğrudan delik açmaya izin vermiyor; trafik koordinatör üzerinden aktarılıyor. Bağlantı çalışır ama daha yavaştır.": "The NAT types of the two devices (usually symmetric NAT or CGNAT) do not allow direct hole punching; traffic is relayed through the coordinator. The connection works but is slower.",
  "Modemde UPnP veya NAT-PMP'yi açın; OpenScale port eşlemeyi kendisi ister.": "Turn on UPnP or NAT-PMP on the modem; OpenScale requests port mapping itself.",
  "Taraflardan birinde yönlendiricide UDP port yönlendirmesi yapın.": "Set up UDP port forwarding on the router of one of the sides.",
  "Mobil veri CGNAT kullanıyorsa doğrudan yol mümkün olmayabilir; bu beklenen bir durumdur.": "If mobile data uses CGNAT, a direct path may not be possible; this is expected.",

  // OS-3003
  "Tünel arayüzü kayboldu": "Tunnel interface disappeared",
  "İşletim sistemi tünel arayüzünü kaldırdı (sürücü güncellemesi, uyku, başka bir VPN).": "The operating system removed the tunnel interface (driver update, sleep, another VPN).",
  "Tüneli yeniden başlatın: openscale down ve openscale up, veya servis: openscale service restart.": "Restart the tunnel: openscale down and openscale up, or the service: openscale service restart.",
  "Aynı anda çalışan başka bir VPN istemcisini kapatın.": "Close any other VPN client running at the same time.",

  // OS-3004
  "UDP engelli": "UDP is blocked",
  "Bulunduğunuz ağ giden UDP trafiğini engelliyor; WireGuard UDP kullandığı için tünel kurulamıyor.": "The network you are on blocks outgoing UDP traffic; the tunnel cannot be set up because WireGuard uses UDP.",
  "TCP yedeğinin adresini denetleyin: openscale get tcp-fallback (boşsa koordinatör:443 kullanılır; sunucuda 443/tcp açık olmalı).": "Check the TCP fallback address: openscale get tcp-fallback (if empty, coordinator:443 is used; 443/tcp must be open on the server).",
  "Mümkünse başka bir ağ (mobil veri) deneyin.": "If possible, try another network (mobile data).",

  // OS-3005
  "Varsayılan ağ geçidi bulunamadı": "No default gateway found",
  "Bu bilgisayarın internete çıkış yolu yok; Wi-Fi veya kablo bağlı değil.": "This computer has no route to the internet; Wi-Fi or cable is not connected.",
  "İnternet bağlantınızı denetleyin.": "Check your internet connection.",
  "Otel veya havaalanı ağıysa önce giriş sayfasını açın (OS-5003).": "On a hotel or airport network, open the sign-in page first (OS-5003).",

  // OS-3006
  "Büyük paketler geçmiyor (MTU)": "Large packets do not get through (MTU)",
  "Yoldaki bir cihaz büyük paketleri sessizce düşürüyor; küçük istekler çalışır, büyük sayfalar ve dosya aktarımı takılır.": "A device on the path silently drops large packets; small requests work, large pages and file transfers stall.",
  "MTU'yu düşürün: openscale set mtu=1280.": "Lower the MTU: openscale set mtu=1280.",
  "Sorun sürerse yolu denetleyin: openscale packet-trace.": "If the problem continues, check the path: openscale packet-trace.",

  // OS-4001
  "DNS ayarları başka bir program tarafından değiştirildi": "DNS settings were changed by another program",
  "OpenScale'in yazdığı DNS ayarlarını başka bir program (Linux'ta NetworkManager, dhclient veya resolvconf; Windows'ta başka bir VPN) geri yazdı.": "Another program (NetworkManager, dhclient or resolvconf on Linux; another VPN on Windows) wrote back the DNS settings OpenScale set.",
  "Linux'ta systemd-resolved kullanın; OpenScale onu resolvectl ile bağlantıya özel ayarlar ve geri yazılmaz.": "On Linux, use systemd-resolved; OpenScale sets it per connection with resolvectl and it is not overwritten.",
  "NetworkManager resolv.conf'u yönetiyorsa dns=systemd-resolved kipine geçin.": "If NetworkManager manages resolv.conf, switch to dns=systemd-resolved mode.",
  "Başka bir VPN istemcisi çalışıyorsa kapatın.": "If another VPN client is running, close it.",
  "Tüneli yeniden bağlayın: openscale debug reconnect.": "Reconnect the tunnel: openscale debug reconnect.",

  // OS-4002
  "Ağ DNS ayarları bu sistemde uygulanamıyor": "Network DNS settings cannot be applied on this system",
  "Bu sistemde OpenScale'in DNS'i güvenle ayarlayabileceği bir yöntem bulunamadı (Linux'ta systemd-resolved yok ve resolv.conf başka bir programın).": "No method was found on this system for OpenScale to set DNS safely (on Linux, systemd-resolved is missing and resolv.conf belongs to another program).",
  "Linux'ta systemd-resolved'ı etkinleştirin.": "On Linux, enable systemd-resolved.",
  "Ya da MagicDNS adları yerine IP adreslerini kullanın; tünel DNS olmadan da çalışır.": "Or use IP addresses instead of MagicDNS names; the tunnel also works without DNS.",

  // OS-4003
  "resolv.conf yedeklenemedi veya okunamadı": "resolv.conf could not be backed up or read",
  "Linux'ta /etc/resolv.conf yedeklenemedi; dosya salt okunur, değişmez işaretli veya başka bir programın bağlantısı.": "/etc/resolv.conf could not be backed up on Linux; the file is read-only, marked immutable or a link to another program's file.",
  "Dosyanın kime ait olduğunu denetleyin: ls -l /etc/resolv.conf.": "Check who owns the file: ls -l /etc/resolv.conf.",
  "Değişmez işaret varsa kaldırın (chattr -i) veya systemd-resolved kullanın.": "If it has the immutable flag, remove it (chattr -i) or use systemd-resolved.",
  "Komutu root olarak çalıştırın.": "Run the command as root.",

  // OS-4004
  "MagicDNS adları çözülmüyor": "MagicDNS names do not resolve",
  "Cihaz adı (ör. nas.ag.internal) çözülmüyor; tünel DNS'i kabul edilmemiş, işletim sistemi başka bir çözücü kullanıyor veya ad yanlış.": "The device name (e.g. nas.ag.internal) does not resolve; tunnel DNS was not accepted, the operating system uses another resolver or the name is wrong.",
  "Tünel DNS'inin açık olduğunu denetleyin: openscale get accept-dns.": "Check that tunnel DNS is on: openscale get accept-dns.",
  "Adı doğrudan sorun: openscale dns query <ad>.": "Query the name directly: openscale dns query <ad>.",
  "Tarayıcıda 'güvenli DNS' (DoH) açıksa tünel adlarını görmez; kapatın veya ağ alanını istisna yapın.": "If 'secure DNS' (DoH) is on in the browser, it does not see tunnel names; turn it off or add the network domain as an exception.",

  // OS-5001
  "Kalıcı kill switch bu sistemde yok": "Persistent kill switch is not available on this system",
  "Bu işletim sisteminde kalıcı kill switch uygulanmadı.": "The persistent kill switch is not implemented on this operating system.",
  "Tünel çalışırken kill switch korumasını kullanın; kalıcı koruma için Windows veya Linux gerekir.": "Use kill switch protection while the tunnel is running; persistent protection needs Windows or Linux.",

  // OS-5002
  "Kill switch kurulu değil": "Kill switch is not installed",
  "İstenen işlem kurulu bir kill switch gerektiriyor ama şu an kurulu değil.": "The requested operation needs an installed kill switch, but none is installed now.",
  "Durumu görün: openscale killswitch status.": "See the status: openscale killswitch status.",
  "Kill switch'i ayarlardan veya openscale set kill-switch=true ile açın.": "Turn on the kill switch in the settings or with openscale set kill-switch=true.",

  // OS-5003
  "Giriş sayfası (captive portal) açılmıyor": "Sign-in page (captive portal) does not open",
  "Kill switch açıkken otel veya havaalanı ağının giriş sayfasına çıkış engellenir.": "While the kill switch is on, access to the sign-in page of a hotel or airport network is blocked.",
  "Kısa süreli istisna açın: openscale killswitch captive --sure 5m.": "Open a short exception: openscale killswitch captive --sure 5m.",
  "macOS'ta istisna yoktur; giriş için geçici olarak openscale killswitch off kullanın ve sonra yeniden açın.": "macOS has no exception; to sign in, temporarily use openscale killswitch off and turn it on again afterwards.",

  // OS-5004
  "Windows Güvenlik Duvarı gelen bağlantıyı engelliyor": "Windows Firewall blocks incoming connections",
  "Tünel çalışıyor ama bu bilgisayardaki bir hizmete (paylaşım, uzak masaüstü, web sunucusu) diğer cihazlardan ulaşılamıyor; Windows tünel arayüzünü 'Ortak' ağ sayarak gelen bağlantıları reddediyor.": "The tunnel works but a service on this computer (sharing, remote desktop, web server) cannot be reached from other devices; Windows treats the tunnel interface as a 'Public' network and rejects incoming connections.",
  "Önce OpenScale kuralının bağlantıya izin verdiğini görün: openscale denied.": "First check that the OpenScale rule allows the connection: openscale denied.",
  "Windows Defender Güvenlik Duvarı'nda ilgili uygulamaya veya porta yalnızca OpenScale arayüzü için izin verin.": "In Windows Defender Firewall, allow the app or port only for the OpenScale interface.",
  "Tünel arayüzünü 'Özel' ağ yapmak bütün özel ağ kurallarını açar; bunu yalnızca bilerek yapın.": "Making the tunnel interface a 'Private' network opens all private network rules; only do this on purpose.",

  // OS-5005
  "Güvenlik duvarı kuralları yüklenemedi": "Firewall rules could not be loaded",
  "Kill switch veya çıkış düğümü kuralları sistem güvenlik duvarına (Windows WFP, Linux nftables/iptables, macOS pf) yazılamadı.": "The kill switch or exit node rules could not be written to the system firewall (Windows WFP, Linux nftables/iptables, macOS pf).",
  "Komutu yönetici veya root olarak çalıştırın.": "Run the command as administrator or root.",
  "Linux'ta nftables veya iptables'ın kurulu olduğunu denetleyin.": "On Linux, check that nftables or iptables is installed.",
  "Başka bir güvenlik duvarı yazılımı kuralları kilitliyorsa geçici olarak kapatın.": "If other firewall software locks the rules, turn it off temporarily.",

  // OS-5006
  "OpenScale kapandı ama internet hâlâ kesik": "OpenScale closed but the internet is still cut off",
  "Kalıcı kill switch, tünel beklenmedik biçimde kapandığında sızıntıyı önlemek için trafiği engellemeye devam eder; bu tasarım gereğidir.": "When the tunnel closes unexpectedly, the persistent kill switch keeps blocking traffic to prevent a leak; this is by design.",
  "Tüneli yeniden başlatın; bağlantı gelir.": "Restart the tunnel; the connection comes back.",
  "İnterneti tünelsiz kullanmanız gerekiyorsa: openscale killswitch off (yönetici gerekir).": "If you need the internet without the tunnel: openscale killswitch off (requires administrator).",

  // OS-6001
  "Yetki yok": "No permission",
  "İşlem yönetici (Windows) veya root (Linux, macOS) yetkisi gerektiriyor ya da dosya başka bir kullanıcıya ait.": "The operation needs administrator (Windows) or root (Linux, macOS) rights, or the file belongs to another user.",
  "Windows'ta terminali 'Yönetici olarak çalıştır' ile açın.": "On Windows, open the terminal with 'Run as administrator'.",
  "Linux ve macOS'ta komutu sudo ile çalıştırın.": "On Linux and macOS, run the command with sudo.",
  "Dosyanın sahibini denetleyin.": "Check who owns the file.",

  // OS-6002
  "Port kullanımda veya ayrılmış": "Port is in use or reserved",
  "İstenen port başka bir program tarafından kullanılıyor veya işletim sistemi tarafından ayrılmış.": "The requested port is used by another program or reserved by the operating system.",
  "Çalışan başka bir openscale olup olmadığını denetleyin.": "Check whether another openscale is running.",
  "--port ile başka bir port (0: boş bir port) seçin.": "Choose another port with --port (0: any free port).",
  "Windows'ta ayrılmış aralıklar: netsh interface ipv4 show excludedportrange protocol=udp.": "Reserved ranges on Windows: netsh interface ipv4 show excludedportrange protocol=udp.",

  // OS-6003
  "Dosya bulunamadı": "File not found",
  "Verilen yol yok veya yanlış klasör seçildi.": "The given path does not exist or the wrong folder was chosen.",
  "Yolu ve --dir / --state-dir değerini denetleyin.": "Check the path and the --dir / --state-dir value.",
  "Ağ profili kullanıyorsanız --network ile doğru profili seçin.": "If you use network profiles, choose the right profile with --network.",

  // OS-6004
  "Gizli dosyanın izinleri fazla açık": "Secret file permissions are too open",
  "Anahtar dosyası başka kullanıcılar tarafından okunabiliyor; güvenlik için açılmadı.": "The key file can be read by other users; it was not opened for safety.",
  "Linux ve macOS'ta: chmod 600 <dosya>.": "On Linux and macOS: chmod 600 <dosya>.",
  "Windows'ta dosyanın yalnızca sizin ve Yöneticiler grubunun erişimine açık olduğunu denetleyin.": "On Windows, check that the file is accessible only to you and the Administrators group.",

  // OS-6005
  "Servis yönetimi bu sistemde desteklenmiyor": "Service management is not supported on this system",
  "Servis kurulumu Windows'ta veya systemd kullanan Linux'ta yapılabilir.": "The service can be installed on Windows or on Linux with systemd.",
  "Tüneli ön planda çalıştırın: openscale up.": "Run the tunnel in the foreground: openscale up.",
  "Kendi servis yöneticiniz için openscale up komutunu bir birim olarak tanımlayın.": "For your own service manager, define the openscale up command as a unit.",

  // OS-7001
  "Çalışan tünele ulaşılamadı": "Could not reach the running tunnel",
  "Komut tünelin yerel API'sini bulamadı: servis çalışmıyor, komut yönetici olarak açılmadı veya farklı bir durum klasörü kullanılıyor.": "The command could not find the tunnel's local API: the service is not running, the command was not opened as administrator or a different state folder is used.",
  "Windows'ta OpenScale servisinin çalıştığını denetleyin ve komutu yönetici olarak çalıştırın.": "On Windows, check that the OpenScale service is running and run the command as administrator.",
  "Linux'ta önce aynı kullanıcıyla openscale up çalıştırın; farklı klasörse --state-dir verin.": "On Linux, first run openscale up as the same user; for a different folder, pass --state-dir.",

  // OS-7002
  "Panel salt okunur": "Panel is read-only",
  "Bu bilgisayarda panel salt okunur kipte; değişiklikler reddedilir.": "The panel on this computer is in read-only mode; changes are rejected.",
  "Değişiklik için bu bilgisayarda yönetici olarak: openscale panel readonly off.": "To make changes, as administrator on this computer: openscale panel readonly off.",

  // OS-7003
  "Çok fazla başarısız deneme": "Too many failed attempts",
  "Kısa sürede çok fazla yanlış parola veya istek geldi; kaba kuvvete karşı bir süre bekletiliyor.": "Too many wrong passwords or requests came in a short time; you have to wait a while as protection against brute force.",
  "Beş dakika bekleyip yeniden deneyin.": "Wait five minutes and try again.",
}
