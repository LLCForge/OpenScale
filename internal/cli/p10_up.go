package cli

import (
	"context"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/osnet"
)

// "openscale up" flags of P10 (ADR-0133): subnet routing on/off and the
// masquerade option (#70), exit node exceptions (#79), the automatic
// exit node on untrusted networks (#80), exit failover and fastest choice
// (#81) and the per-member exit rate limit (#83).

type upP10Flags struct {
	noRoutes     *bool
	noMasquerade *bool
	exitExcept   *string
	exitAuto     *string
	candidates   *string
	untrusted    *bool
	trustedWiFi  *string
	trustWired   *bool
	exitRate     *string
}

func addUpP10Flags(fs *flag.FlagSet) upP10Flags {
	return upP10Flags{
		noRoutes:     fs.Bool("no-subnet-routes", false, "alt ağ rotalarını işletim sistemine ekleme ve bu cihaz yönlendiriciyse iletme"),
		noMasquerade: fs.Bool("subnet-no-masquerade", false, "yönlendirici: üye adreslerini maskeleme (LAN'da ağ aralığına dönüş rotası gerekir)"),
		exitExcept:   fs.String("exit-except", "", "çıkış düğümü dışında tutulacak hedefler, CIDR virgülle (ör. banka IP aralığı; kill switch açıkken engellenir)"),
		exitAuto:     fs.String("exit-auto", "", "çıkış düğümünü otomatik seç: failover (sırayla yedek) veya fastest (en düşük gecikme)"),
		candidates:   fs.String("exit-candidates", "", "otomatik seçimde aday çıkış düğümleri, öncelik sırasıyla (boş: kullanılabilen hepsi)"),
		untrusted:    fs.Bool("exit-untrusted", false, "çıkış düğümünü yalnızca güvenilmeyen ağlarda aç (--trusted-wifi listesi dışındaki ağlar)"),
		trustedWiFi:  fs.String("trusted-wifi", "", "güvenilir Wi-Fi adları (SSID), virgülle"),
		trustWired:   fs.Bool("trust-wired", false, "kablolu ağları güvenilir say"),
		exitRate:     fs.String("exit-rate-limit", "", "bu cihaz çıkış düğümüyse üye başına yön başına hız sınırı (ör. 20mbit, 5MB; Linux)"),
	}
}

type upP10Options struct {
	routes     bool
	noMasq     bool
	except     []string
	auto       string
	candidates []string
	untrusted  *osnet.NetworkTrust
	exitRate   uint64
}

func (f upP10Flags) resolve() (upP10Options, error) {
	o := upP10Options{routes: !*f.noRoutes, noMasq: *f.noMasquerade, candidates: splitList(*f.candidates)}
	if s := strings.TrimSpace(*f.exitExcept); s != "" {
		prefixes, err := parsePrefixList(s)
		if err != nil {
			return o, err
		}
		if len(prefixes) > node.MaxExitExceptions {
			return o, usageError("--exit-except en fazla %d aralık alır", node.MaxExitExceptions)
		}
		for _, p := range prefixes {
			if p.Bits() == 0 {
				return o, usageError("--exit-except bütün interneti kapsayamaz")
			}
			o.except = append(o.except, p.String())
		}
	}
	switch a := strings.TrimSpace(*f.exitAuto); a {
	case "", node.ExitModeFailover, node.ExitModeFastest:
		o.auto = a
	default:
		return o, usageError("--exit-auto failover veya fastest olmalı")
	}
	if *f.untrusted {
		o.untrusted = &osnet.NetworkTrust{Trusted: splitTrustedNames(*f.trustedWiFi), TrustWired: *f.trustWired}
		if o.auto == "" {
			o.auto = node.ExitModeFailover
		}
	} else if *f.trustedWiFi != "" || *f.trustWired {
		return o, usageError("--trusted-wifi ve --trust-wired yalnızca --exit-untrusted ile kullanılır")
	}
	if len(o.candidates) > 0 && o.auto == "" {
		return o, usageError("--exit-candidates yalnızca --exit-auto veya --exit-untrusted ile kullanılır")
	}
	rate, err := parseRate(*f.exitRate)
	if err != nil {
		return o, usageError("--exit-rate-limit: %v", err)
	}
	if err := osnet.ValidateExitRateLimit(rate); err != nil {
		return o, usageError("--exit-rate-limit: %v", err)
	}
	o.exitRate = rate
	return o, nil
}

// parseRate parses "20mbit", "500kbit", "5MB", "800KB" or plain bytes per
// second. Bit units are decimal (network speeds), byte units binary.
func parseRate(s string) (uint64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "0" {
		return 0, nil
	}
	units := []struct {
		suffix string
		mul    float64
	}{
		{"gbit", 1e9 / 8}, {"mbit", 1e6 / 8}, {"kbit", 1e3 / 8},
		{"gb", 1 << 30}, {"mb", 1 << 20}, {"kb", 1 << 10},
		{"g", 1 << 30}, {"m", 1 << 20}, {"k", 1 << 10}, {"b", 1},
	}
	mul := 1.0
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			s, mul = strings.TrimSuffix(s, u.suffix), u.mul
			break
		}
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || v <= 0 || v > 1e12 {
		return 0, fmt.Errorf("hız 20mbit, 5MB veya bayt/sn olarak yazılmalı")
	}
	return uint64(v * mul), nil
}

// routeApplier returns the OS subnet router, or nil when turned off.
func (o upP10Options) routeApplier() node.RouteApplier {
	if !o.routes {
		return nil
	}
	return osnet.NewSubnetRouter()
}

// start applies the engine options and runs the automatic exit node
// choice. The returned function stops it.
func (o upP10Options) start(ctx context.Context, env *Env, engine *node.Engine) func() {
	engine.SetSubnetMasquerade(!o.noMasq)
	if len(o.except) > 0 {
		prefixes, _ := parsePrefixList(strings.Join(o.except, ","))
		if err := engine.SetExitExceptions(prefixes); err != nil {
			fmt.Fprintf(env.Stderr, "uyarı: çıkış istisnaları uygulanamadı: %v\n", err)
		}
	}
	if o.auto == "" {
		return func() {}
	}
	actx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		engine.RunExitAuto(actx, node.ExitAutoConfig{
			Candidates: o.candidates,
			Mode:       o.auto,
			Untrusted:  o.untrusted,
			Networks:   osnet.CurrentNetworks,
			OnChange: func(exit, reason string) {
				if exit == "" {
					fmt.Fprintf(env.Stdout, "Çıkış düğümü kapalı: %s\n", reason)
					return
				}
				fmt.Fprintf(env.Stdout, "Çıkış düğümü: %s (%s)\n", exit, reason)
			},
		})
	}()
	return func() {
		cancel()
		<-done
	}
}
