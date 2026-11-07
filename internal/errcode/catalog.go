package errcode

import (
	"errors"
	"io/fs"
	"syscall"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/svcmgr"
	"github.com/openscale/openscale/internal/trust"
)

// catalog is every code ever issued. Append only (ADR-0165): a new code
// takes the next free number of its area; a code that no longer happens
// is marked Deprecated, never removed.
var catalog = []Entry{
	// 1xxx: trust document and root key.
	{Code: "OS-1001", Area: AreaDocument, Title: "Kök anahtar parolası yanlış",
		Cause:    "Girilen parola kök anahtar dosyasını açmadı; parola yanlış yazıldı veya dosya bozuldu.",
		Steps:    []string{"Büyük/küçük harfi ve klavye dilini denetleyip parolayı yeniden yazın.", "Parolayı hatırlamıyorsanız kök anahtarı parolalı yedekten geri yükleyin: openscale network restore.", "Dosya bozulduysa yedekten geri yükleyin; yedek yoksa ağ yeniden kurulmalıdır."},
		Commands: []string{"openscale key status --dir ./ag"}},
	{Code: "OS-1002", Area: AreaDocument, Title: "İmza doğrulanamadı",
		Cause:    "Ağ belgesinin veya bir dosyanın imzası bu ağın kök anahtarıyla doğrulanmadı; dosya yolda değişmiş, başka bir ağa ait veya başka bir amaçla imzalanmış.",
		Steps:    []string{"Dosyayı yeniden ve güvendiğiniz bir kanaldan alın.", "Dosyanın doğru ağa ait olduğunu kök parmak iziyle denetleyin.", "Tekrarlıyorsa denetim kaydına bakın; birisi belgeyi değiştirmeye çalışıyor olabilir."},
		Commands: []string{"openscale network verify --dir ./ag", "openscale audit list"}},
	{Code: "OS-1003", Area: AreaDocument, Title: "Ağ belgesinin süresi doldu",
		Cause:    "İmzalı ağ belgesinin geçerlilik süresi geçti; cihazlar süresi dolmuş belgeyle yeni bağlantı kurmaz.",
		Steps:    []string{"Yönetici bilgisayarda belgeyi yenileyin: openscale network renew --dir ./ag.", "Cihazlar yeni belgeyi koordinatörden kendiliğinden alır; almıyorsa OS-3001'e bakın.", "Saatin doğru olduğunu denetleyin; yanlış saat süresi dolmuş gibi görünmeye yol açar."},
		Commands: []string{"openscale network show --dir ./ag"}},
	{Code: "OS-1004", Area: AreaDocument, Title: "Eski belge reddedildi (geri alma)",
		Cause:    "Bu cihazın gördüğünden daha eski sürümlü bir belge sunuldu; eski kurallara dönmeyi önlemek için reddedildi.",
		Steps:    []string{"Koordinatörün güncel belgeyi sunduğunu denetleyin (koordinatör yedekten geri yüklendiyse eski kalmış olabilir).", "Yönetici bilgisayarda belgeyi yeniden imzalayın: openscale network renew.", "Sebebini bilmiyorsanız denetim kaydını inceleyin."},
		Commands: []string{"openscale audit list", "openscale network show --dir ./ag"}},
	{Code: "OS-1005", Area: AreaDocument, Title: "Çelişkili belge görüldü",
		Cause:    "Aynı sürüm numarasıyla iki farklı belge veya güncel belgeyle çelişen bir kök geçişi görüldü; kök anahtar kötüye kullanılmış olabilir.",
		Steps:    []string{"Kök anahtarın bulunduğu bilgisayarları denetleyin; parola başkasıyla paylaşıldı mı?", "Kök anahtar ele geçirildiyse kurtarma anahtarıyla kök geçişi yapın.", "Bütün cihazlardaki denetim kayıtlarını karşılaştırın."},
		Commands: []string{"openscale network transitions --dir ./ag", "openscale audit verify"}},
	{Code: "OS-1006", Area: AreaDocument, Title: "Başka ağa ait veri veya parmak izi uyuşmuyor",
		Cause:    "Paket, yedek veya belge bu ağın kök anahtarıyla eşleşmiyor; başka bir ağa ait ya da yolda değiştirilmiş.",
		Steps:    []string{"Yönetici ekranındaki kök parmak iziyle karşılaştırın.", "Doğru ağ klasörünü (--dir veya --network) seçtiğinizi denetleyin.", "Paketi yöneticiden yeniden isteyin."},
		Commands: []string{"openscale network show --dir ./ag"}},
	{Code: "OS-1007", Area: AreaDocument, Title: "Desteklenmeyen imza algoritması",
		Cause:    "Veri bu sürümün tanımadığı bir algoritmayla imzalanmış; genellikle bu cihazdaki OpenScale eskidir.",
		Steps:    []string{"Bu cihazdaki OpenScale'i güncelleyin.", "Güncelleme sonrası da sürüyorsa dosyanın kaynağını denetleyin."},
		Commands: []string{"openscale version", "openscale update status"}},
	{Code: "OS-1008", Area: AreaDocument, Title: "Parola yeterince güçlü değil",
		Cause: "Yeni parola çok kısa, tekrar eden karakterlerden oluşuyor veya kolay tahmin edilir.",
		Steps: []string{"Birbiriyle ilgisiz dört beş kelimeden veya rastgele karakterlerden bir parola seçin.", "Parolanın gücünü önceden ölçün: openscale key strength."}},
	{Code: "OS-1009", Area: AreaDocument, Title: "Belge başka yerden değiştirildi",
		Cause: "Değişiklik hazırlanırken ağ belgesi başka bir yerde (ör. başka bir CLI veya panel) değişti; üzerine yazmamak için işlem durdu.",
		Steps: []string{"Sayfayı yenileyin veya komutu yeniden çalıştırın.", "Aynı ağı aynı anda iki yerden yönetmeyin."}},
	{Code: "OS-1010", Area: AreaDocument, Title: "Kayıtlı belge bozuk",
		Cause:    "Bu cihazdaki ağ belgesi okunamadı ve geçerli bir kopyası kalmadı.",
		Steps:    []string{"Başka bir cihazdan network.json kopyalayın.", "Onarın: openscale state repair --document <network.json>."},
		Commands: []string{"openscale configtest"}},
	{Code: "OS-1011", Area: AreaDocument, Title: "Rastgele sayı üreteci sağlıksız",
		Cause:    "İşletim sisteminin rastgele sayı üreteci sağlık denetiminden geçmedi; güvenlik için anahtar üretilmedi.",
		Steps:    []string{"Bilgisayarı yeniden başlatıp yeniden deneyin.", "Sanal makinedeyseniz sanal makineye rastgelelik kaynağı (virtio-rng) ekleyin."},
		Commands: []string{"openscale selftest"}},
	{Code: "OS-1012", Area: AreaDocument, Title: "Belge henüz geçerli değil (saat farkı)",
		Cause: "Belgenin başlangıç zamanı bu cihazın saatine göre gelecekte; genellikle cihazın saati yanlıştır.",
		Steps: []string{"Cihazın saatini ve saat dilimini düzeltin (otomatik saat eşitlemesini açın).", "Saat doğruysa yönetici bilgisayarın saatini denetleyin."}},

	// 2xxx: membership, devices and invites.
	{Code: "OS-2001", Area: AreaMembership, Title: "Bu cihaz henüz bir ağa katılmamış",
		Cause:    "Seçilen durum klasöründe katılım bilgisi yok.",
		Steps:    []string{"Katılım paketiyle katılın: openscale join, veya davet koduyla: openscale invite-join.", "Başka bir klasör veya ağ profili kullanıyorsanız --state-dir ya da --network verin."},
		Commands: []string{"openscale network list"}},
	{Code: "OS-2002", Area: AreaMembership, Title: "Cihaz ağ belgesinde yok",
		Cause:    "Bu cihaz iptal edilmiş, üyeliği bitmiş veya henüz eklenmemiş.",
		Steps:    []string{"Yöneticiden cihazı eklemesini veya üyeliğini uzatmasını isteyin.", "İptal edildiyse yeni anahtar üretip yeniden katılın: openscale keygen."},
		Commands: []string{"openscale status", "openscale whoami"}},
	{Code: "OS-2003", Area: AreaMembership, Title: "İsteğin süresi doldu",
		Cause: "Kayıt veya anahtar yenileme isteğinin süresi geçti.",
		Steps: []string{"Cihazda isteği yeniden oluşturun (openscale keygen veya openscale device rotate-key).", "Yeni isteği süre dolmadan yöneticiye ulaştırın."}},
	{Code: "OS-2004", Area: AreaMembership, Title: "Doğrulama kodu veya parmak izi eşleşmedi",
		Cause: "İki tarafta görünen kısa kodlar veya parmak izleri farklı; istek yolda değişmiş olabilir, cihaz eklenmedi.",
		Steps: []string{"İsteği yeniden ve doğrudan (yüz yüze, telefonla) doğrulanan bir kanaldan alın.", "Kodları sesli okuyup karşılaştırın."}},
	{Code: "OS-2005", Area: AreaMembership, Title: "Davet geçersiz",
		Cause:    "Davet bulunamadı, süresi doldu, kullanıldı, başka bir cihaza verildi veya koordinatör kaydı reddetti.",
		Steps:    []string{"Yöneticiden yeni bir davet kodu isteyin: openscale invite create.", "Kodu eksiksiz kopyaladığınızı denetleyin."},
		Commands: []string{"openscale invite list --dir ./ag"}},
	{Code: "OS-2006", Area: AreaMembership, Title: "Cihaz adı kullanılamaz",
		Cause: "Ad başka bir cihazda kullanılıyor, koordinatöre ayrılmış veya izin verilmeyen karakter içeriyor.",
		Steps: []string{"Yalnızca küçük harf, rakam ve tire kullanın (en çok 63 karakter).", "Başka bir ad seçin; 'coordinator' ayrılmıştır."}},
	{Code: "OS-2007", Area: AreaMembership, Title: "Cihaz kimliği başka bilgisayardan kopyalanmış",
		Cause: "Bu durum klasörü başka bir bilgisayarda oluşturulmuş; aynı kimlik iki bilgisayarda ağda çakışır.",
		Steps: []string{"Bilerek taşıdıysanız: openscale device rebind.", "Değilse bu bilgisayarı yeni bir davetle ayrı cihaz olarak ekleyin."}},
	{Code: "OS-2008", Area: AreaMembership, Title: "Ağın adres alanı doldu",
		Cause: "Ağın IP aralığında yeni cihaza verilecek adres kalmadı.",
		Steps: []string{"Kullanılmayan cihazları kaldırın: openscale device inactive, sonra device revoke.", "Gerekirse ağı daha geniş bir aralığa taşıyın: openscale network readdress."}},

	// 3xxx: coordinator, NAT, relay and the tunnel.
	{Code: "OS-3001", Area: AreaConnection, Title: "Koordinatör yanıt vermiyor",
		Cause:    "Koordinatöre UDP ile ulaşılamadı: sunucu kapalı, port kapalı, adres yanlış veya bu ağ UDP'yi engelliyor.",
		Steps:    []string{"Koordinatör sunucusunun çalıştığını denetleyin (sunucuda: openscale service status).", "Sunucunun güvenlik duvarında ve bulut güvenlik grubunda UDP portunun açık olduğunu denetleyin.", "Bu ağ UDP'yi engelliyorsa (otel, şirket) TCP yedeğine düşülür; adresini denetleyin: openscale get tcp-fallback (boşsa koordinatör:443; sunucuda 443/tcp açık olmalı).", "Belgedeki koordinatör adresini denetleyin: openscale network show."},
		Commands: []string{"openscale netcheck", "openscale coordinator reach"}},
	{Code: "OS-3002", Area: AreaConnection, Title: "Doğrudan bağlantı kurulamıyor, aktarıcı kullanılıyor",
		Cause:    "İki cihazın NAT türleri (genellikle simetrik NAT veya CGNAT) doğrudan delik açmaya izin vermiyor; trafik koordinatör üzerinden aktarılıyor. Bağlantı çalışır ama daha yavaştır.",
		Steps:    []string{"Modemde UPnP veya NAT-PMP'yi açın; OpenScale port eşlemeyi kendisi ister.", "Taraflardan birinde yönlendiricide UDP port yönlendirmesi yapın.", "Mobil veri CGNAT kullanıyorsa doğrudan yol mümkün olmayabilir; bu beklenen bir durumdur."},
		Commands: []string{"openscale netcheck", "openscale paths", "openscale debug relay-test"}},
	{Code: "OS-3003", Area: AreaConnection, Title: "Tünel arayüzü kayboldu",
		Cause:    "İşletim sistemi tünel arayüzünü kaldırdı (sürücü güncellemesi, uyku, başka bir VPN).",
		Steps:    []string{"Tüneli yeniden başlatın: openscale down ve openscale up, veya servis: openscale service restart.", "Aynı anda çalışan başka bir VPN istemcisini kapatın."},
		Commands: []string{"openscale health"}},
	{Code: "OS-3004", Area: AreaConnection, Title: "UDP engelli",
		Cause:    "Bulunduğunuz ağ giden UDP trafiğini engelliyor; WireGuard UDP kullandığı için tünel kurulamıyor.",
		Steps:    []string{"TCP yedeğinin adresini denetleyin: openscale get tcp-fallback (boşsa koordinatör:443 kullanılır; sunucuda 443/tcp açık olmalı).", "Mümkünse başka bir ağ (mobil veri) deneyin."},
		Commands: []string{"openscale netcheck"}},
	{Code: "OS-3005", Area: AreaConnection, Title: "Varsayılan ağ geçidi bulunamadı",
		Cause: "Bu bilgisayarın internete çıkış yolu yok; Wi-Fi veya kablo bağlı değil.",
		Steps: []string{"İnternet bağlantınızı denetleyin.", "Otel veya havaalanı ağıysa önce giriş sayfasını açın (OS-5003)."}},
	{Code: "OS-3006", Area: AreaConnection, Title: "Büyük paketler geçmiyor (MTU)",
		Cause:    "Yoldaki bir cihaz büyük paketleri sessizce düşürüyor; küçük istekler çalışır, büyük sayfalar ve dosya aktarımı takılır.",
		Steps:    []string{"MTU'yu düşürün: openscale set mtu=1280.", "Sorun sürerse yolu denetleyin: openscale packet-trace."},
		Commands: []string{"openscale netcheck"}},

	// 4xxx: DNS.
	{Code: "OS-4001", Area: AreaDNS, Title: "DNS ayarları başka bir program tarafından değiştirildi",
		Cause:    "OpenScale'in yazdığı DNS ayarlarını başka bir program (Linux'ta NetworkManager, dhclient veya resolvconf; Windows'ta başka bir VPN) geri yazdı.",
		Steps:    []string{"Linux'ta systemd-resolved kullanın; OpenScale onu resolvectl ile bağlantıya özel ayarlar ve geri yazılmaz.", "NetworkManager resolv.conf'u yönetiyorsa dns=systemd-resolved kipine geçin.", "Başka bir VPN istemcisi çalışıyorsa kapatın.", "Tüneli yeniden bağlayın: openscale debug reconnect."},
		Commands: []string{"openscale dns status"}},
	{Code: "OS-4002", Area: AreaDNS, Title: "Ağ DNS ayarları bu sistemde uygulanamıyor",
		Cause:    "Bu sistemde OpenScale'in DNS'i güvenle ayarlayabileceği bir yöntem bulunamadı (Linux'ta systemd-resolved yok ve resolv.conf başka bir programın).",
		Steps:    []string{"Linux'ta systemd-resolved'ı etkinleştirin.", "Ya da MagicDNS adları yerine IP adreslerini kullanın; tünel DNS olmadan da çalışır."},
		Commands: []string{"openscale dns status"}},
	{Code: "OS-4003", Area: AreaDNS, Title: "resolv.conf yedeklenemedi veya okunamadı",
		Cause: "Linux'ta /etc/resolv.conf yedeklenemedi; dosya salt okunur, değişmez işaretli veya başka bir programın bağlantısı.",
		Steps: []string{"Dosyanın kime ait olduğunu denetleyin: ls -l /etc/resolv.conf.", "Değişmez işaret varsa kaldırın (chattr -i) veya systemd-resolved kullanın.", "Komutu root olarak çalıştırın."}},
	{Code: "OS-4004", Area: AreaDNS, Title: "MagicDNS adları çözülmüyor",
		Cause:    "Cihaz adı (ör. nas.ag.internal) çözülmüyor; tünel DNS'i kabul edilmemiş, işletim sistemi başka bir çözücü kullanıyor veya ad yanlış.",
		Steps:    []string{"Tünel DNS'inin açık olduğunu denetleyin: openscale get accept-dns.", "Adı doğrudan sorun: openscale dns query <ad>.", "Tarayıcıda 'güvenli DNS' (DoH) açıksa tünel adlarını görmez; kapatın veya ağ alanını istisna yapın."},
		Commands: []string{"openscale dns status", "openscale dns query <ad>"}},

	// 5xxx: kill switch and firewalls.
	{Code: "OS-5001", Area: AreaKillSwitch, Title: "Kalıcı kill switch bu sistemde yok",
		Cause: "Bu işletim sisteminde kalıcı kill switch uygulanmadı.",
		Steps: []string{"Tünel çalışırken kill switch korumasını kullanın; kalıcı koruma için Windows veya Linux gerekir."}},
	{Code: "OS-5002", Area: AreaKillSwitch, Title: "Kill switch kurulu değil",
		Cause:    "İstenen işlem kurulu bir kill switch gerektiriyor ama şu an kurulu değil.",
		Steps:    []string{"Durumu görün: openscale killswitch status.", "Kill switch'i ayarlardan veya openscale set kill-switch=true ile açın."},
		Commands: []string{"openscale killswitch status"}},
	{Code: "OS-5003", Area: AreaKillSwitch, Title: "Giriş sayfası (captive portal) açılmıyor",
		Cause:    "Kill switch açıkken otel veya havaalanı ağının giriş sayfasına çıkış engellenir.",
		Steps:    []string{"Kısa süreli istisna açın: openscale killswitch captive --sure 5m.", "macOS'ta istisna yoktur; giriş için geçici olarak openscale killswitch off kullanın ve sonra yeniden açın."},
		Commands: []string{"openscale killswitch status"}},
	{Code: "OS-5004", Area: AreaKillSwitch, Title: "Windows Güvenlik Duvarı gelen bağlantıyı engelliyor",
		Cause:    "Tünel çalışıyor ama bu bilgisayardaki bir hizmete (paylaşım, uzak masaüstü, web sunucusu) diğer cihazlardan ulaşılamıyor; Windows tünel arayüzünü 'Ortak' ağ sayarak gelen bağlantıları reddediyor.",
		Steps:    []string{"Önce OpenScale kuralının bağlantıya izin verdiğini görün: openscale denied.", "Windows Defender Güvenlik Duvarı'nda ilgili uygulamaya veya porta yalnızca OpenScale arayüzü için izin verin.", "Tünel arayüzünü 'Özel' ağ yapmak bütün özel ağ kurallarını açar; bunu yalnızca bilerek yapın."},
		Commands: []string{"openscale denied", "openscale ping <cihaz>"}},
	{Code: "OS-5005", Area: AreaKillSwitch, Title: "Güvenlik duvarı kuralları yüklenemedi",
		Cause:    "Kill switch veya çıkış düğümü kuralları sistem güvenlik duvarına (Windows WFP, Linux nftables/iptables, macOS pf) yazılamadı.",
		Steps:    []string{"Komutu yönetici veya root olarak çalıştırın.", "Linux'ta nftables veya iptables'ın kurulu olduğunu denetleyin.", "Başka bir güvenlik duvarı yazılımı kuralları kilitliyorsa geçici olarak kapatın."},
		Commands: []string{"openscale killswitch status", "openscale configtest"}},
	{Code: "OS-5006", Area: AreaKillSwitch, Title: "OpenScale kapandı ama internet hâlâ kesik",
		Cause:    "Kalıcı kill switch, tünel beklenmedik biçimde kapandığında sızıntıyı önlemek için trafiği engellemeye devam eder; bu tasarım gereğidir.",
		Steps:    []string{"Tüneli yeniden başlatın; bağlantı gelir.", "İnterneti tünelsiz kullanmanız gerekiyorsa: openscale killswitch off (yönetici gerekir)."},
		Commands: []string{"openscale killswitch status"}},

	// 6xxx: permissions, ports, files and services.
	{Code: "OS-6001", Area: AreaSystem, Title: "Yetki yok",
		Cause: "İşlem yönetici (Windows) veya root (Linux, macOS) yetkisi gerektiriyor ya da dosya başka bir kullanıcıya ait.",
		Steps: []string{"Windows'ta terminali 'Yönetici olarak çalıştır' ile açın.", "Linux ve macOS'ta komutu sudo ile çalıştırın.", "Dosyanın sahibini denetleyin."}},
	{Code: "OS-6002", Area: AreaSystem, Title: "Port kullanımda veya ayrılmış",
		Cause:    "İstenen port başka bir program tarafından kullanılıyor veya işletim sistemi tarafından ayrılmış.",
		Steps:    []string{"Çalışan başka bir openscale olup olmadığını denetleyin.", "--port ile başka bir port (0: boş bir port) seçin.", "Windows'ta ayrılmış aralıklar: netsh interface ipv4 show excludedportrange protocol=udp."},
		Commands: []string{"openscale configtest"}},
	{Code: "OS-6003", Area: AreaSystem, Title: "Dosya bulunamadı",
		Cause: "Verilen yol yok veya yanlış klasör seçildi.",
		Steps: []string{"Yolu ve --dir / --state-dir değerini denetleyin.", "Ağ profili kullanıyorsanız --network ile doğru profili seçin."}},
	{Code: "OS-6004", Area: AreaSystem, Title: "Gizli dosyanın izinleri fazla açık",
		Cause:    "Anahtar dosyası başka kullanıcılar tarafından okunabiliyor; güvenlik için açılmadı.",
		Steps:    []string{"Linux ve macOS'ta: chmod 600 <dosya>.", "Windows'ta dosyanın yalnızca sizin ve Yöneticiler grubunun erişimine açık olduğunu denetleyin."},
		Commands: []string{"openscale configtest"}},
	{Code: "OS-6005", Area: AreaSystem, Title: "Servis yönetimi bu sistemde desteklenmiyor",
		Cause: "Servis kurulumu Windows'ta veya systemd kullanan Linux'ta yapılabilir.",
		Steps: []string{"Tüneli ön planda çalıştırın: openscale up.", "Kendi servis yöneticiniz için openscale up komutunu bir birim olarak tanımlayın."}},

	// 7xxx: panel and local API.
	{Code: "OS-7001", Area: AreaPanel, Title: "Çalışan tünele ulaşılamadı",
		Cause:    "Komut tünelin yerel API'sini bulamadı: servis çalışmıyor, komut yönetici olarak açılmadı veya farklı bir durum klasörü kullanılıyor.",
		Steps:    []string{"Windows'ta OpenScale servisinin çalıştığını denetleyin ve komutu yönetici olarak çalıştırın.", "Linux'ta önce aynı kullanıcıyla openscale up çalıştırın; farklı klasörse --state-dir verin."},
		Commands: []string{"openscale service status"}},
	{Code: "OS-7002", Area: AreaPanel, Title: "Panel salt okunur",
		Cause:    "Bu bilgisayarda panel salt okunur kipte; değişiklikler reddedilir.",
		Steps:    []string{"Değişiklik için bu bilgisayarda yönetici olarak: openscale panel readonly off."},
		Commands: []string{"openscale panel readonly status"}},
	{Code: "OS-7003", Area: AreaPanel, Title: "Çok fazla başarısız deneme",
		Cause: "Kısa sürede çok fazla yanlış parola veya istek geldi; kaba kuvvete karşı bir süre bekletiliyor.",
		Steps: []string{"Beş dakika bekleyip yeniden deneyin."}},
}

type sentinel struct {
	target error
	code   string
}

// sentinelMatchers are tried first, in order; specific errors before
// general ones.
var sentinelMatchers = []sentinel{
	{trust.ErrWrongPassphrase, "OS-1001"},
	{trust.ErrBadSignature, "OS-1002"},
	{trust.ErrWrongContext, "OS-1002"},
	{trust.ErrExpired, "OS-1003"},
	{trust.ErrRollback, "OS-1004"},
	{trust.ErrEquivocation, "OS-1005"},
	{trust.ErrTransitionStale, "OS-1005"},
	{trust.ErrRootFingerprintMismatch, "OS-1006"},
	{trust.ErrWrongNetwork, "OS-1006"},
	{admin.ErrBackupKeyMismatch, "OS-1006"},
	{trust.ErrUnsupportedAlgorithm, "OS-1007"},
	{trust.ErrWeakPassphrase, "OS-1008"},
	{trust.ErrGuessablePassphrase, "OS-1008"},
	{admin.ErrConcurrentChange, "OS-1009"},
	{admin.ErrHistoryVersionUsed, "OS-1009"},
	{member.ErrNeedsDocument, "OS-1010"},
	{trust.ErrRandomUnhealthy, "OS-1011"},
	{trust.ErrNotYetValid, "OS-1012"},
	{member.ErrNotJoined, "OS-2001"},
	{node.ErrNotMember, "OS-2002"},
	{trust.ErrRevokedKey, "OS-2002"},
	{trust.ErrEnrollmentExpired, "OS-2003"},
	{trust.ErrRotationExpired, "OS-2003"},
	{admin.ErrSASMismatch, "OS-2004"},
	{admin.ErrFingerprintMismatch, "OS-2004"},
	{trust.ErrInviteNotFound, "OS-2005"},
	{trust.ErrInviteExpired, "OS-2005"},
	{trust.ErrInviteUsed, "OS-2005"},
	{node.ErrInviteGone, "OS-2005"},
	{node.ErrInviteTaken, "OS-2005"},
	{node.ErrInviteRejected, "OS-2005"},
	{trust.ErrNameTaken, "OS-2006"},
	{trust.ErrInvalidName, "OS-2006"},
	{trust.ErrNameReserved, "OS-2006"},
	{node.ErrMachineChanged, "OS-2007"},
	{trust.ErrAddressSpaceFull, "OS-2008"},
	{node.ErrNoReply, "OS-3001"},
	{node.ErrTunnelLost, "OS-3003"},
	{osnet.ErrNoGateway, "OS-3005"},
	{osnet.ErrDNSOverwritten, "OS-4001"},
	{osnet.ErrNetworkDNSUnsupported, "OS-4002"},
	{osnet.ErrKillSwitchUnsupported, "OS-5001"},
	{osnet.ErrKillSwitchNotInstalled, "OS-5002"},
	{osnet.ErrCaptiveUnsupportedDarwin, "OS-5003"},
	{securefile.ErrInsecurePermissions, "OS-6004"},
	{svcmgr.ErrNeedsAdmin, "OS-6001"},
	{svcmgr.ErrNeedsRoot, "OS-6001"},
	{svcmgr.ErrUnsupported, "OS-6005"},
}

// lateMatchers are general errors tried after the text matchers, so a
// more specific message wins over "file not found".
var lateMatchers = []sentinel{
	{fs.ErrNotExist, "OS-6003"},
}

type textMatch struct {
	text string // lower case
	code string
}

// textMatchers recognise messages of tools and of the local API whose
// errors carry no sentinel. They are lower case.
var textMatchers = []textMatch{
	{"address already in use", "OS-6002"},
	{"only one usage of each socket address", "OS-6002"},
	{"forbidden by its access permissions", "OS-6002"},
	{"tünelin yerel api'sine ulaşılamadı", "OS-7001"},
	{"çalışan bir openscale tüneli bulunamadı", "OS-7001"},
	{"salt okunur", "OS-7002"},
	{"resolv.conf", "OS-4003"},
	{"pf ana kural kümesi", "OS-5005"},
	{"pf etkinleştirilemedi", "OS-5005"},
	{"nft: ", "OS-5005"},
	{"iptables: ", "OS-5005"},
}

// classifyErrno maps operating system errors.
func classifyErrno(err error) string {
	switch {
	case errors.Is(err, syscall.EADDRINUSE):
		return "OS-6002"
	case errors.Is(err, fs.ErrPermission), errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return "OS-6001"
	}
	return ""
}
