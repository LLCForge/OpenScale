// English texts (#224), keyed by the Turkish source text. See lib/i18n/i18n.tsx.
//
// Diagnostics and observability, phase 2: the layered troubleshooter
// (#835, components/diag/troubleshoot-*.tsx), the flight recorder (#836,
// components/diag/flight-recorder-card.tsx), the event stream (#328) and
// the settings that restart the connection (#799,
// components/settings/restarts-connection.tsx).

export const enObservability: Record<string, string> = {
  // Troubleshooter: layers and statuses
  "Tünel arayüzü": "Tunnel interface",
  "Yerel ağ geçidi": "Local gateway",
  DNS: "DNS",
  Atlandı: "Skipped",
  "Bağlantı sorununu bul": "Find the connection problem",
  "Arayüz, yerel ağ geçidi, DNS, koordinatör, aktarıcı ve her eş sırayla denetlenir; ilk kalan adımın üstü atlanır. Yalnızca kendi koordinatörünüze bağlanılır.":
    "The interface, the local gateway, DNS, the coordinator, the relay and every peer are checked in turn; the steps above the first failure are skipped. Only your own coordinator is contacted.",
  "Yeniden denetle": "Check again",
  "Denetimi başlat": "Start the check",
  "Denetleniyor…": "Checking…",
  "Sorun bulunmadı.": "No problem found.",
  "Bir sorun bulundu.": "A problem was found.",
  "Denetim çalıştırılamadı": "The check could not run",
  "Bağlantıda sorun varsa denetimi başlatın; birkaç saniye sürer.": "If the connection has a problem, start the check; it takes a few seconds.",
  "İlk sorun: {step}": "First problem: {step}",
  "Sorun bulunmadı": "No problem found",
  "Bütün katmanlar geçti; uyarılar varsa aşağıda.": "Every layer passed; any warnings are listed below.",
  "Denetim adımları": "Check steps",
  "Öneri:": "Suggestion:",
  "Denetim zamanı: {at}": "Checked at: {at}",

  // Troubleshooter: results by key
  "{layer} adımı başarısız olduğu için denenmedi; önce o adımı düzeltin.": "Not tried because the {layer} step failed; fix that step first.",
  "Tünel çalışıyor.": "The tunnel is running.",
  "Tünel kapalı (bağlantı elle kesildi).": "The tunnel is off (the connection was turned off by hand).",
  "Tepsi simgesinden veya Kontrol Merkezi'nden bağlantıyı açın.": "Turn the connection on from the tray icon or the Control Center.",
  "Tünel çalışmıyor.": "The tunnel is not running.",
  "Servisi yeniden başlatın; sürüyorsa servis günlüğüne bakın.": "Restart the service; if it continues, look at the service log.",
  "{name} arayüzü işletim sisteminde kapalı görünüyor.": "The {name} interface looks down in the operating system.",
  "Bağlantıyı yeniden kurun; olmazsa servisi yeniden başlatın.": "Reconnect; if that does not help, restart the service.",
  "Varsayılan ağ geçidi var.": "A default gateway is present.",
  "Varsayılan ağ geçidi bulunamadı; bu bilgisayar yerel ağa veya internete bağlı değil.":
    "No default gateway was found; this computer is not connected to a local network or the internet.",
  "Wi-Fi veya kablo bağlantısını denetleyin; modemi yeniden başlatın.": "Check the Wi-Fi or cable connection; restart the modem.",
  "Bu bilgisayar henüz bir ağa katılmamış; koordinatör adı yok.": "This computer has not joined a network yet; there is no coordinator name.",
  "Koordinatör IP adresiyle tanımlı; ad çözmeye gerek yok.": "The coordinator is given by IP address; no name needs resolving.",
  "Koordinatörün adı çözüldü.": "The coordinator's name resolved.",
  "Sistem DNS'i koordinatörün adını çözemedi.": "The system DNS could not resolve the coordinator's name.",
  "Ağın DNS sunucusunu denetleyin; koordinatörün DNS kaydının doğru olduğundan emin olun.":
    "Check the network's DNS server; make sure the coordinator's DNS record is correct.",
  "MagicDNS çözücüsü çalışmıyor; cihaz adları çözülmeyebilir.": "The MagicDNS resolver is not working; device names may not resolve.",
  "Başka bir DNS programı 53. portu tutuyor olabilir; ayrıntı için bu sayfadaki ağ denetimine bakın.":
    "Another DNS program may be holding port 53; see the network check on this page for details.",
  "Bu bilgisayar henüz bir ağa katılmamış.": "This computer has not joined a network yet.",
  "Koordinatör yanıt verdi ({ms} ms).": "The coordinator answered ({ms} ms).",
  "Ağ bir giriş sayfası (captive portal) istiyor; koordinatöre ulaşılamıyor.": "The network wants a sign-in page (captive portal); the coordinator cannot be reached.",
  "Tarayıcıda ağın giriş sayfasını açıp oturum açın.": "Open the network's sign-in page in the browser and sign in.",
  "Koordinatör yanıt vermedi.": "The coordinator did not answer.",
  "Koordinatörün çalıştığını ve güvenlik duvarında UDP portunun açık olduğunu denetleyin; UDP engelliyse TCP yedeğini açın.":
    "Check that the coordinator is running and its UDP port is open in the firewall; if UDP is blocked, turn on the TCP fallback.",
  "Koordinatöre yalnızca TCP üzerinden ulaşılıyor ({ms} ms); UDP engelli.": "The coordinator is reached over TCP only ({ms} ms); UDP is blocked.",
  "Ağ UDP'yi engelliyor; doğrudan bağlantılar kurulamayabilir. Başka bir ağ deneyin.": "The network blocks UDP; direct connections may not work. Try another network.",
  "Aktarıcıyı denemek için çevrimiçi bir eş yok.": "There is no online peer to try the relay with.",
  "Aktarıcı üzerinden {peer}: {ms} ms.": "Through the relay to {peer}: {ms} ms.",
  "Koordinatörün aktarıcısı üzerinden {peer} cihazına ulaşılamadı.": "{peer} could not be reached through the coordinator's relay.",
  "Doğrudan bağlantı kurulamayan eşlere ulaşılamaz; koordinatörün aktarıcı sınırlarını ve sürümünü denetleyin.":
    "Peers without a direct connection cannot be reached; check the coordinator's relay limits and version.",
  "Bu cihazın tünel kurabileceği bir eş yok.": "This device has no peer to build a tunnel to.",
  "{count} eş daha denetlenmedi.": "{count} more peer was not checked.|{count} more peers were not checked.",
  "{peer} ile son birkaç dakikada el sıkışma olmadı.": "No handshake with {peer} in the last few minutes.",
  "Cihazın açık ve OpenScale'in çalıştığını denetleyin; uzun süredir çevrimdışıysa kendi bağlantısını denetleyin.":
    "Check that the device is on and OpenScale is running; if it has been offline for long, check its own connection.",
  "{peer} aktarıcı üzerinden bağlı; doğrudan yol kurulamadı.": "{peer} is connected through the relay; no direct path could be made.",
  "Bağlantı çalışır ama daha yavaştır; iki taraftan birinde UDP port yönlendirmesi doğrudan yolu açar.":
    "The connection works but is slower; UDP port forwarding on either side opens a direct path.",
  "{peer} doğrudan bağlı.": "{peer} is connected directly.",
  "arıza ayıklayıcı için çalışan bir OpenScale servisi gerekli": "the troubleshooter needs a running OpenScale service",

  // Flight recorder
  "Uçuş kaydedici": "Flight recorder",
  "Son 30 dakikanın ayrıntılı günlüğü bellekte tutulur; anahtarlar, IP adresleri ve cihaz adları maskelenir. Kopma olunca kendiliğinden saklanır; bu bilgisayarın dışına yalnızca yardımcının anahtarına şifrelenerek çıkar.":
    "A detailed log of the last 30 minutes is kept in memory; keys, IP addresses and device names are masked. It is saved by itself when the connection drops, and leaves this computer only encrypted to a helper's key.",
  "Son kopmayı kaydet": "Save the last dropout",
  Elle: "By hand",
  "Tünel düştü": "Tunnel went down",
  "Koordinatör koptu": "Coordinator lost",
  "Son {min} dakikanın kaydı saklandı.": "The recording of the last {min} minutes was saved.",
  "Bellekte {count} kayıt, {size} / {max}.": "{count} record in memory, {size} / {max}.|{count} records in memory, {size} / {max}.",
  "Kopmada kendiliğinden saklanır (en çok {min} dakikada bir).": "Saved by itself on a dropout (at most once every {min} minutes).",
  "Saklanan kayıt yok. Bağlantı koptuğunda veya düğmeye bastığınızda burada görünür.": "No saved recordings. They appear here when the connection drops or you press the button.",
  "Saklanan uçuş kayıtları": "Saved flight recordings",
  "Dışa ver": "Export",
  "Kaydı yardımcıya şifrele": "Encrypt the recording for a helper",
  "Yardım edecek kişi anahtarını şu komutla üretir:": "The person who will help makes their key with:",
  "Yardımcının açık anahtarı": "Helper's public key",
  "Kayıt bu anahtara şifrelenir. Parmak izini yardımcıyla sesli karşılaştırın.": "The recording is encrypted to this key. Compare the fingerprint with the helper by voice.",
  "Şifreli indir": "Download encrypted",
  "Şifreli kayıt indirildi; yalnızca anahtarın sahibi açabilir.": "The encrypted recording was downloaded; only the key's owner can open it.",
  "Anahtar çok uzun.": "The key is too long.",
  "'osbk1:' ile başlayan anahtarı eksiksiz yapıştırın.": "Paste the whole key that starts with 'osbk1:'.",
  "uçuş kaydedici çalışmıyor": "the flight recorder is not running",
  "uçuş kaydedicide henüz kayıt yok": "the flight recorder has no records yet",
  "kayıt bulunamadı": "recording not found",
  "geçersiz kayıt kimliği": "invalid recording id",
  "Uçuş kaydı elle donduruldu.": "A flight recording was saved by hand.",
  "Uçuş kaydı yardımcının anahtarına şifrelenip dışa verildi.": "A flight recording was encrypted to a helper's key and exported.",

  // Settings that restart the connection
  "Bağlantıyı yeniden başlatır": "Restarts the connection",
  "Bu ayar değişince tünel birkaç saniyeliğine yeniden başlar; açık bağlantılar kopar.": "Changing this restarts the tunnel for a few seconds; open connections drop.",
  "Bağlantı yeniden başlayacak": "The connection will restart",
  "Bu bilgisayara OpenScale üzerinden uzaktan bağlısınız. Bu ayar tüneli yeniden başlatır; uzak oturumunuz kopabilir ve tünel geri gelince yeniden bağlanmanız gerekir.":
    "You are connected to this computer remotely through OpenScale. This setting restarts the tunnel; your remote session may drop and you will need to reconnect once the tunnel is back.",
  "Yine de kaydet": "Save anyway",
}
