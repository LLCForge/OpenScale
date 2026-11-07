package cli

// diagCommands are the connection, diagnostics and preference commands
// (Faz 1 CLI ve tanı). They are listed after the network commands.
func diagCommands() []command {
	return []command{
		{"status", "Bu cihazı ve eşleri gösterir: yol (doğrudan/aktarıcı), el sıkışma, bayt, gecikme", cmdStatus},
		{"down", "Tüneli kapatır (servis); --for ile süreli", cmdDown},
		{"ping", "Bir cihaza tünel içinden ping atar; yol türü ve gecikme (--until-direct)", cmdPing},
		{"netcheck", "Ağ koşullarını denetler: koordinatör UDP, NAT türü, IPv4/IPv6", cmdNetcheck},
		{"debug reconnect", "Yolları sıfırlayıp yeniden bağlanmayı zorlar", cmdDebugReconnect},
		{"debug relay-test", "Bir cihaza koordinatörün aktarıcısı üzerinden gidiş-dönüş ölçer", cmdDebugRelayTest},
		{"debug endpoints", "Eşlerin uç noktalarını, adaylarını ve değişim geçmişini gösterir", cmdDebugEndpoints},
		{"debug fake-device", "Sahte cihaz eklemeyi önizler (yalnızca --dry-run; belgeye yazmaz)", cmdDebugFakeDevice},
		{"dns status", "MagicDNS ve ağ DNS ayarlarının bu cihazdaki durumunu gösterir", cmdDNSStatus},
		{"dns query", "Bir adı bu cihazın MagicDNS çözücüsüne sorar", cmdDNSQuery},
		{"whois", "IP adresinden veya addan cihazı bulur", cmdWhois},
		{"whoami", "Bu cihazın ağdaki kimliğini gösterir", cmdWhoami},
		{"get", "Kalıcı tercihleri gösterir (--json)", cmdGet},
		{"set", "Kalıcı tercihleri değiştirir: openscale set <ayar>=<değer> ...", cmdSet},
		{"log level", "Günlük seviyesini çalışırken gösterir veya değiştirir: debug|info|warn|error", cmdLogLevel},
		{"configtest", "Ayar dosyalarını, anahtar izinlerini, belgeyi ve portları tek geçişte denetler", cmdConfigtest},
		{"wg show", "WireGuard durumunu salt okunur gösterir (gizli anahtar göstermez)", cmdWGShow},
		{"packet-trace", "Bir paketin kurallarda nasıl karar bulduğunu adım adım açıklar", cmdPacketTrace},
		{"health", "Sağlık denetimi: canlı/hazır; çıkış kodu 0 hazır, 1 değil", cmdHealth},
	}
}
