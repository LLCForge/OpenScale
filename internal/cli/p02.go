package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/openscale/openscale/internal/enrollkit"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/trust"
)

// Commands of package P02: access request from a member device (#383,
// ADR-0158) and nearby pairing announcement (#358, ADR-0156).
func p02Commands() []command {
	return []command{
		{"access request", "Bu cihazdan başka bir cihaza süreli erişim isteği üretir (cihaz anahtarıyla imzalı; sahip panelde onaylar)", cmdAccessRequest},
		{"nearby announce", "Kayıt isteğini 5 dakika boyunca yerel ağa duyurur; sahip panelde 'yakındaki istekler' listesinden onaylar", cmdNearbyAnnounce},
	}
}

func p02SplitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func cmdAccessRequest(env *Env, args []string) error {
	fs := newFlagSet(env, "access request")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü (varsayılan: kullanıcı yapılandırma klasörü)")
	to := fs.String("to", "", "erişilmek istenen cihazın adı (zorunlu)")
	service := fs.String("service", "", "servis: ssh, files, rdesk, sync... (--protocol ile birlikte verilmez)")
	protocol := fs.String("protocol", "", "tcp veya udp (--ports ile)")
	ports := fs.String("ports", "", "virgülle ayrılmış portlar veya aralıklar, ör. 8096 veya 5900-5910")
	users := fs.String("users", "", "ssh isteğinde virgülle ayrılmış yerel hesaplar")
	hours := fs.Int("hours", 8, fmt.Sprintf("erişim süresi, saat (1-%d)", trust.MaxAccessHours))
	reason := fs.String("reason", "", "kısa gerekçe (sahip panelde görür)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *to == "" {
		return usageError("--to zorunlu")
	}
	if (*service == "") == (*protocol == "") {
		return usageError("--service veya --protocol/--ports verin (ikisinden yalnız biri)")
	}
	dir, err := resolveStateDir(env, *stateDir)
	if err != nil {
		return err
	}
	store, err := member.Open(dir)
	if err != nil {
		return err
	}
	secrets, err := readSecrets(filepath.Join(dir, deviceKeyFile))
	if err != nil {
		return fmt.Errorf("cihaz anahtarı okunamadı: %w", err)
	}
	line, req, err := secrets.NewAccessRequest(store.Document(), trust.AccessRequestInput{
		To: *to, Service: trust.RuleService(strings.ToLower(*service)), Protocol: trust.Protocol(strings.ToLower(*protocol)),
		Ports: p02SplitList(*ports), Users: p02SplitList(*users), Hours: *hours, Reason: *reason,
	}, env.Now(), env.Random)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Erişim isteği: %s -> %s, %d saat.\n", req.From, req.To, req.Hours)
	fmt.Fprintln(env.Stdout, "Aşağıdaki satırı ağ sahibine gönderin; sahip panelde Erişim istekleri kutusuna yapıştırıp onaylar:")
	fmt.Fprintln(env.Stdout, line)
	fmt.Fprintf(env.Stdout, "İstek %d gün içinde onaylanmazsa geçersiz olur. Kendiliğinden onay yoktur.\n", int(trust.AccessRequestMaxAge.Hours()/24))
	return nil
}

func cmdNearbyAnnounce(env *Env, args []string) error {
	fs := newFlagSet(env, "nearby announce")
	stateDir := fs.String("state-dir", "", "durum klasörü (varsayılan: kullanıcı yapılandırma klasörü)")
	name := fs.String("name", "", "önerilen cihaz adı (varsayılan: bilgisayar adı)")
	to := fs.String("to", "", "duyuru adresi (varsayılan: yerel ağ yayını, UDP 41823)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	dir, err := resolveStateDir(env, *stateDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	secrets, _, err := loadOrCreateDeviceSecrets(env, filepath.Join(dir, deviceKeyFile))
	if err != nil {
		return err
	}
	hostname := *name
	if hostname == "" {
		hostname, _ = env.Hostname()
	}
	envl, req, err := secrets.NewEnrollmentRequest(hostname, env.Now())
	if err != nil {
		return err
	}
	line, err := trust.EncodeEnrollment(envl)
	if err != nil {
		return err
	}
	pkt, err := enrollkit.NearbyPacket(line)
	if err != nil {
		return err
	}
	var dst net.Addr = enrollkit.BroadcastAddr()
	if *to != "" {
		ua, err := net.ResolveUDPAddr("udp4", *to)
		if err != nil {
			return usageError("--to geçersiz: %v", err)
		}
		dst = ua
	}
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Fprintf(env.Stdout, "Onay kodu: %s\n", req.SAS())
	fmt.Fprintln(env.Stdout, "Yönetici panelinde Cihazlar > Yakındaki istekler listesinde bu cihazı seçip yukarıdaki kodu yazın.")
	fmt.Fprintln(env.Stdout, "Duyuru 5 dakika sürer (Ctrl+C ile durdur). Kod ekranda değilse onaylamayın.")
	sent, err := enrollkit.Announce(envContext(env), conn, dst, pkt, enrollkit.NearbyInterval, enrollkit.NearbyWindow)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("duyuru gönderilemedi: %w", err)
	}
	fmt.Fprintf(env.Stdout, "Duyuru bitti (%d paket). Onaylandıysa belgeyi 'openscale join' ile alın.\n", sent)
	return nil
}
