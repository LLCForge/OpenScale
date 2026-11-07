package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/upstream"
)

// Tor exit commands and the WARP import resolver (ADR-0142, Tor and WARP
// appendix). The commands only touch <state-dir>/upstream; the running
// "openscale up" applies them within a few seconds. OpenScale never edits
// /etc/tor/torrc: "tor torrc" prints the lines for the owner.

// lookupEndpoint resolves an Endpoint name at import; tests replace it.
var lookupEndpoint = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// endpointLookupTimeout bounds the one query of an import.
const endpointLookupTimeout = 10 * time.Second

// importResolver resolves an Endpoint name once, preferring IPv4: an exit
// node without IPv6 could not reach an IPv6 endpoint.
func importResolver(env *Env) upstream.Resolver {
	return func(host string) (netip.Addr, error) {
		ctx, cancel := context.WithTimeout(envContext(env), endpointLookupTimeout)
		defer cancel()
		addrs, err := lookupEndpoint(ctx, host)
		if err != nil {
			return netip.Addr{}, err
		}
		var v6 netip.Addr
		for _, a := range addrs {
			a = a.Unmap()
			if a.Is4() {
				return a, nil
			}
			if !v6.IsValid() {
				v6 = a
			}
		}
		if v6.IsValid() {
			return v6, nil
		}
		return netip.Addr{}, errors.New("adres yok")
	}
}

func warnTorPlatform(env *Env) {
	if !osnet.TorSupported() {
		fmt.Fprintln(env.Stderr, "uyarı: Tor çıkışı yalnızca Linux çıkış düğümlerinde çalışır; bu bilgisayarda ayar yalnızca saklanır.")
	}
}

func validTorPort(name string, p int) error {
	if p < 1 || p > 65535 {
		return usageError("--%s 1 ile 65535 arasında olmalı", name)
	}
	return nil
}

func cmdTorEnable(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-node upstream tor enable")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü (sunucuda genellikle /var/lib/openscale/device)")
	transPort := fs.Int("trans-port", upstream.DefaultTorTransPort, "Tor TransPort (torrc ile aynı olmalı)")
	dnsPort := fs.Int("dns-port", upstream.DefaultTorDNSPort, "Tor DNSPort (torrc ile aynı olmalı; 127.0.0.1'de)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := validTorPort("trans-port", *transPort); err != nil {
		return err
	}
	if err := validTorPort("dns-port", *dnsPort); err != nil {
		return err
	}
	if *transPort == *dnsPort {
		return usageError("--trans-port ve --dns-port farklı olmalı")
	}
	st, err := upstreamStore(env, *stateDir)
	if err != nil {
		return err
	}
	previous, err := st.EnableTor(*transPort, *dnsPort)
	if err != nil {
		return err
	}
	w := env.Stdout
	fmt.Fprintf(w, "Tor çıkışı seçildi (TransPort %d, DNSPort 127.0.0.1:%d).\n", *transPort, *dnsPort)
	if previous != "" {
		fmt.Fprintf(w, "WireGuard üst çıkış profili %q artık kullanılmıyor (profil silinmedi).\n", previous)
	}
	fmt.Fprintln(env.Stderr, "UYARI: Tor yalnızca TCP taşır. Üyelerin UDP (QUIC, oyun, VoIP), ICMP (ping) ve bütün IPv6 internet")
	fmt.Fprintln(env.Stderr, "       trafiği bu çıkış düğümünde DÜŞÜRÜLÜR; bu sunucunun adresinden çıkmaz. Siteler Tor çıkış rölesini görür;")
	fmt.Fprintln(env.Stderr, "       Tor ağı üçüncü taraftır ve çıkış rölesi şifrelenmemiş trafiği görebilir (yalnızca HTTPS kullanın).")
	fmt.Fprintln(w, "Tor çalışmıyorsa veya portlar dinlemiyorsa üyelerin trafiği kesilir; bu sunucunun adresinden çıkmaz.")
	fmt.Fprintln(w, "torrc satırları için: openscale exit-node upstream tor torrc")
	fmt.Fprintln(w, "Çalışan 'openscale up' değişikliği birkaç saniye içinde uygular. Denetim: openscale exit-node upstream tor status")
	warnTorPlatform(env)
	return nil
}

func cmdTorDisable(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-node upstream tor disable")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	st, err := upstreamStore(env, *stateDir)
	if err != nil {
		return err
	}
	was, err := st.DisableTor()
	if err != nil {
		return err
	}
	if !was {
		fmt.Fprintln(env.Stdout, "Tor çıkışı zaten kapalı.")
		return nil
	}
	fmt.Fprintln(env.Stdout, "Tor çıkışı kapatıldı. Bu sunucu çıkış düğümüyse üyelerin trafiği artık kendi adresinden çıkar.")
	fmt.Fprintln(env.Stdout, "torrc'ye eklediğin satırlar yerinde kalır; gerekmiyorsa kaldırıp 'systemctl restart tor' çalıştır.")
	return nil
}

func cmdTorStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-node upstream tor status")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	st, err := upstreamStore(env, *stateDir)
	if err != nil {
		return err
	}
	settings, err := st.Settings()
	if err != nil {
		return err
	}
	status, ok, err := st.ReadStatus()
	if err != nil {
		return err
	}
	stale := !ok || status.Stale(env.Now()) || status.Kind != upstream.KindTor
	if *asJSON {
		var tor *upstream.TorStatus
		if !stale {
			tor = status.Tor
		}
		return printJSON(env.Stdout, struct {
			Enabled bool                  `json:"enabled"`
			Config  *upstream.TorSettings `json:"config,omitempty"`
			Mode    string                `json:"mode,omitempty"`
			Status  *upstream.TorStatus   `json:"status,omitempty"`
			Error   string                `json:"error,omitempty"`
			Stale   bool                  `json:"stale"`
		}{settings.TorEnabled(), settings.Tor, modeIf(!stale, status.Mode), tor, errorIf(!stale, status.Error), stale})
	}
	if !settings.TorEnabled() {
		fmt.Fprintln(env.Stdout, "Tor çıkışı: kapalı (açmak için: openscale exit-node upstream tor enable)")
		return nil
	}
	printTorStatus(env, settings, status, stale)
	return nil
}

func modeIf(ok bool, mode string) string {
	if !ok {
		return ""
	}
	return mode
}

func errorIf(ok bool, e string) string {
	if !ok {
		return ""
	}
	return e
}

// printTorStatus is the Tor exit part of "status" and "tor status".
func printTorStatus(env *Env, settings upstream.Settings, status upstream.Status, stale bool) {
	w := env.Stdout
	trans, dns := settings.Tor.Ports()
	fmt.Fprintln(w, "Üst çıkış:       Tor (tür: tor)")
	fmt.Fprintf(w, "Portlar:         TransPort %d, DNSPort 127.0.0.1:%d\n", trans, dns)
	fmt.Fprintln(w, "Taşınan:         üyelerin TCP ve DNS trafiği; UDP, ICMP ve IPv6 düşürülür")
	if stale || status.Kind != upstream.KindTor || status.Tor == nil {
		fmt.Fprintln(w, "Çalışan çıkış:   rapor yok veya eski; 'openscale up' bu cihazda çalışıyor mu ve cihaz çıkış düğümü mü?")
		return
	}
	switch status.Mode {
	case upstream.ModeTunnel:
		fmt.Fprintln(w, "Durum:           bağlı: üyelerin TCP ve DNS trafiği Tor'dan çıkıyor")
	case upstream.ModeBlocked:
		fmt.Fprintln(w, "Durum:           Tor dinlemiyor: üyelerin internet trafiği kesiliyor (sızıntı yok)")
	default:
		fmt.Fprintln(w, "Durum:           kurallar kurulamadı: çıkış düğümü kapalı tutuluyor")
	}
	ts := status.Tor
	listen := ts.Listen
	if listen == "" {
		listen = "OpenScale adresi"
	}
	fmt.Fprintf(w, "TransPort:       %s (%s:%d)\n", listening(ts.TransUp), listen, ts.TransPort)
	if ts.TransLoopbackOnly {
		fmt.Fprintln(w, "                 yalnızca 127.0.0.1'de dinliyor; yönlendirilen bağlantılar oraya ulaşmaz (torrc'yi düzelt)")
	}
	fmt.Fprintf(w, "DNSPort:         %s (127.0.0.1:%d)\n", listening(ts.DNSUp), ts.DNSPort)
	if status.Error != "" {
		fmt.Fprintf(w, "Son hata:        %s\n", status.Error)
	}
	fmt.Fprintln(w, "Not: yoklama yalnızca portların dinlenip dinlenmediğine bakar; Tor'un devre kurabildiğini bir üyeden doğrulayın.")
}

func listening(b bool) string {
	if b {
		return "dinliyor"
	}
	return "dinlemiyor"
}

func cmdTorTorrc(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-node upstream tor torrc")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	listen := fs.String("listen", "", "TransPort'un dinleyeceği OpenScale IPv4 adresi (varsayılan: bu cihazın ağdaki adresi)")
	transPort := fs.Int("trans-port", 0, "Tor TransPort (varsayılan: seçili ayar veya 9040)")
	dnsPort := fs.Int("dns-port", 0, "Tor DNSPort (varsayılan: seçili ayar veya 5353)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	trans, dns := upstream.TorSettings{}.Ports()
	if st, err := upstreamStore(env, *stateDir); err == nil {
		if s, err := st.Settings(); err == nil && s.Tor != nil {
			trans, dns = s.Tor.Ports()
		}
	}
	if *transPort != 0 {
		if err := validTorPort("trans-port", *transPort); err != nil {
			return err
		}
		trans = uint16(*transPort)
	}
	if *dnsPort != 0 {
		if err := validTorPort("dns-port", *dnsPort); err != nil {
			return err
		}
		dns = uint16(*dnsPort)
	}
	if trans == dns {
		return usageError("TransPort ve DNSPort farklı olmalı")
	}
	addr, err := torListenAddr(env, *stateDir, *listen)
	if err != nil {
		return err
	}
	w := env.Stdout
	fmt.Fprintln(w, "## OpenScale Tor çıkışı (openscale exit-node upstream tor torrc)")
	fmt.Fprintln(w, "## /etc/tor/torrc sonuna ekleyin, sonra: systemctl restart tor@default")
	fmt.Fprintln(w, "## TransPort yalnızca OpenScale adresinde dinler; üyelerin TCP bağlantıları nftables ile buraya yönlenir.")
	fmt.Fprintf(w, "TransPort %s:%d\n", addr, trans)
	fmt.Fprintln(w, "## DNSPort yalnızca bu sunucuda; üyelerin DNS'ini OpenScale çıkış DNS ileticisi buraya gönderir.")
	fmt.Fprintf(w, "DNSPort 127.0.0.1:%d\n", dns)
	fmt.Fprintln(w, "## .onion adları sanal adreslere eşlenir; bu aralık özel olmamalı ki üyeler onu çıkış düğümüne göndersin.")
	fmt.Fprintln(w, "AutomapHostsOnResolve 1")
	fmt.Fprintln(w, "AutomapHostsSuffixes .onion")
	fmt.Fprintf(w, "VirtualAddrNetworkIPv4 %s\n", upstream.TorVirtualNetwork)
	fmt.Fprintln(w, "##")
	fmt.Fprintln(w, "## Tor, OpenScale arayüzü kurulmadan başlarsa TransPort açılamaz. Sıralama için:")
	fmt.Fprintln(w, "##   systemctl edit tor@default  ->  [Unit]")
	fmt.Fprintln(w, "##                                   Wants=openscale-wait-online.service")
	fmt.Fprintln(w, "##                                   After=openscale-wait-online.service")
	return nil
}

// torListenAddr is the address TransPort listens on: the flag, else this
// device's own OpenScale address (from its state, or from the running
// Tor exit's report).
func torListenAddr(env *Env, stateDir, flagValue string) (netip.Addr, error) {
	if flagValue != "" {
		a, err := netip.ParseAddr(flagValue)
		if err != nil || !a.Is4() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() {
			return netip.Addr{}, usageError("--listen bu cihazın OpenScale IPv4 adresi olmalı")
		}
		return a, nil
	}
	if store, secrets, err := deviceState(env, stateDir); err == nil {
		if doc := store.Document(); doc != nil {
			if self, err := selfDevice(doc, secrets); err == nil && self.IPv4.IsValid() {
				return self.IPv4, nil
			}
		}
	}
	if st, err := upstreamStore(env, stateDir); err == nil {
		if status, ok, err := st.ReadStatus(); err == nil && ok && status.Tor != nil {
			if a, err := netip.ParseAddr(status.Tor.Listen); err == nil && a.Is4() {
				return a, nil
			}
		}
	}
	return netip.Addr{}, errors.New("bu cihazın OpenScale adresi okunamadı (root olarak çalıştır veya --listen <adres> ver; adres: openscale status)")
}
