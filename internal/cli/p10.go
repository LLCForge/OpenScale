package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/trust"
)

// Routing commands of P10 (ADR-0133, ADR-0134): subnet routes and their
// approval (#70, #258), route conflicts (#165), plain WireGuard exit nodes
// (#264), address strategy (#267), current networks for the untrusted
// network rule (#80) and the Linux per-application split tunnel (#78).

func p10Commands() []command {
	return []command{
		{"route advertise", "Bu cihazın yönlendirebileceği alt ağları imzalı ilan olarak yazar (sahip 'route approve' ile onaylar)", cmdRouteAdvertise},
		{"route approve", "Bir cihazın rota ilanını doğrular ve onaylı rotalarına ekler (kök anahtarla imzalanır)", cmdRouteApprove},
		{"route set", "Bir cihazın onaylı alt ağ rotalarını belirler: --device <ad> --routes 192.168.1.0/24,... (boş: hepsini kaldır)", cmdRouteSet},
		{"route rm", "Bir cihazın tek bir onaylı rotasını kaldırır", cmdRouteRemove},
		{"route list", "Onaylı alt ağ rotalarını ve yönlendiricilerini listeler", cmdRouteList},
		{"route check", "Ağ aralığı ve alt ağ rotalarının bu bilgisayarın ağlarıyla çakışmasını denetler", cmdRouteCheck},
		{"exit-node external set", "Sahibin düz WireGuard sunucusunu çıkış düğümü olarak tanımlar (DNS çözücüsüyle)", cmdExternalExitSet},
		{"exit-node external rm", "Düz WireGuard çıkış düğümünü kaldırır", cmdExternalExitRemove},
		{"exit-node external config", "Düz WireGuard sunucusuna eklenecek [Peer] bölümlerini yazar", cmdExternalExitConfig},
		{"exit-node networks", "Bağlı ağları (Wi-Fi adı, kablolu) ve güvenilir sayılıp sayılmadığını gösterir", cmdExitNetworks},
		{"address strategy", "Yeni cihazlara adres verme yöntemi: first|sequential|random [--reserve aralıklar]", cmdAddressStrategy},
		{"device address", "Bir cihazı ağ içinde başka bir IPv4 adresine taşır (ör. ayrılmış havuza)", cmdDeviceAddress},
		{"split-tunnel run", "Linux: komutu çıkış düğümünü atlayan grupta çalıştırır: -- <komut> [argümanlar] (root gerekir)", cmdSplitTunnelRun},
		{"split-tunnel off", "Linux: uygulama bazlı tünel kurallarını kaldırır", cmdSplitTunnelOff},
	}
}

// parsePrefixList parses "a/24,b/16".
func parsePrefixList(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range splitList(s) {
		p, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, usageError("%q CIDR olmalı (ör. 192.168.1.0/24)", item)
		}
		if p != p.Masked() {
			return nil, usageError("%s maskeli olmalı (%s)", p, p.Masked())
		}
		out = append(out, p)
	}
	return out, nil
}

// deviceState loads this device's store and keys.
func deviceState(env *Env, stateDir string) (*member.Store, *trust.DeviceSecrets, error) {
	dir, err := resolveStateDir(env, stateDir)
	if err != nil {
		return nil, nil, err
	}
	store, err := member.Open(dir)
	if err != nil {
		return nil, nil, err
	}
	secrets, err := readSecrets(filepath.Join(dir, deviceKeyFile))
	if err != nil {
		return nil, nil, fmt.Errorf("cihaz anahtarı okunamadı: %w", err)
	}
	return store, secrets, nil
}

func cmdRouteAdvertise(env *Env, args []string) error {
	fs := newFlagSet(env, "route advertise")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü (varsayılan: kullanıcı yapılandırma klasörü)")
	routes := fs.String("routes", "", "ilan edilecek alt ağlar, virgülle: 192.168.1.0/24,fd12::/48 (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	prefixes, err := parsePrefixList(*routes)
	if err != nil {
		return err
	}
	if len(prefixes) == 0 {
		return usageError("--routes zorunlu")
	}
	for _, p := range prefixes {
		if err := trust.ValidateRoutePrefix(p); err != nil {
			return usageError("%v", err)
		}
	}
	store, secrets, err := deviceState(env, *stateDir)
	if err != nil {
		return err
	}
	doc := store.Document()
	self, err := selfDevice(doc, secrets)
	if err != nil {
		return err
	}
	if !osnet.RouterSupported() {
		fmt.Fprintln(env.Stderr, "uyarı: bu işletim sistemi alt ağ yönlendirici olamaz (yalnızca Linux); onaylansa da trafik iletilmez.")
	}
	line, err := trust.NewRouteAdvertisement(secrets, doc.NetworkID, self.ID, prefixes, env.Now())
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Rota ilanı (sahibe verin: 'openscale route approve --advertisement ...' veya panelde Rotalar):")
	fmt.Fprintln(env.Stdout, line)
	return nil
}

func cmdRouteApprove(env *Env, args []string) error {
	fs := newFlagSet(env, "route approve")
	f := addEditFlags(fs)
	advert := fs.String("advertisement", "", "rota ilanı (osroute1.) veya @dosya (zorunlu)")
	only := fs.String("only", "", "yalnızca bu rotaları onayla, virgülle (boş: ilandaki hepsi)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *advert == "" {
		return usageError("--advertisement zorunlu")
	}
	line, err := readArg(*advert, maxP08File)
	if err != nil {
		return err
	}
	subset, err := parsePrefixList(*only)
	if err != nil {
		return err
	}
	now := env.Now()
	err = runEdit(env, f, func(doc *trust.Document) error {
		dev, routes, err := doc.ApproveRouteAdvertisement(line, subset, now)
		if err == nil {
			fmt.Fprintf(env.Stdout, "%s için onaylanan rotalar: %s\n", dev.Name, prefixText(routes))
		}
		return err
	})
	if err == nil {
		printRouteRuleHint(env)
	}
	return err
}

func cmdRouteSet(env *Env, args []string) error {
	fs := newFlagSet(env, "route set")
	f := addEditFlags(fs)
	device := fs.String("device", "", "yönlendirici cihazın adı (zorunlu)")
	routes := fs.String("routes", "", "onaylı alt ağlar, virgülle; boş bırakılırsa cihazın bütün rotaları kaldırılır")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *device == "" {
		return usageError("--device zorunlu")
	}
	prefixes, err := parsePrefixList(*routes)
	if err != nil {
		return err
	}
	err = runEdit(env, f, func(doc *trust.Document) error { return doc.SetDeviceRoutes(*device, prefixes) })
	if err == nil && len(prefixes) > 0 {
		printRouteRuleHint(env)
	}
	return err
}

func cmdRouteRemove(env *Env, args []string) error {
	fs := newFlagSet(env, "route rm")
	f := addEditFlags(fs)
	device := fs.String("device", "", "yönlendirici cihazın adı (zorunlu)")
	route := fs.String("route", "", "kaldırılacak rota (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *device == "" || *route == "" {
		return usageError("--device ve --route zorunlu")
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(*route))
	if err != nil {
		return usageError("--route CIDR olmalı")
	}
	return runEdit(env, f, func(doc *trust.Document) error { return doc.RemoveDeviceRoute(*device, p) })
}

func printRouteRuleHint(env *Env) {
	fmt.Fprintln(env.Stdout, "Not: Rota tek başına erişim açmaz. Erişim için CIDR hedefli kural ekleyin, ör.:")
	fmt.Fprintln(env.Stdout, "  openscale rule add --from laptop --to 192.168.1.0/24 --protocol tcp --ports 445 --dir ...")
	fmt.Fprintln(env.Stdout, "\"*\" kuralları yönlendirilen adresleri kapsamaz. Eski sürümlü cihazlar ağ dışı CIDR içeren belgeyi reddeder; önce bütün cihazları güncelleyin.")
}

func prefixText(ps []netip.Prefix) string {
	if len(ps) == 0 {
		return "yok"
	}
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}

// listDocument reads the owner's document (--dir) or this device's copy.
func listDocument(env *Env, dir, stateDir string) (*trust.Document, error) {
	if dir != "" {
		n, err := admin.Load(dir, env.adminOptions())
		if err != nil {
			return nil, err
		}
		return n.Document()
	}
	d, err := resolveStateDir(env, stateDir)
	if err != nil {
		return nil, err
	}
	store, err := member.Open(d)
	if err != nil {
		return nil, err
	}
	doc := store.Document()
	if doc == nil {
		return nil, errors.New("bu cihazda ağ belgesi yok")
	}
	return doc, nil
}

type routeListJSON struct {
	Routes        []trust.DeviceRoute  `json:"routes"`
	ExternalExits []trust.ExternalExit `json:"external_exits"`
	Addressing    *trust.Addressing    `json:"addressing"`
}

func cmdRouteList(env *Env, args []string) error {
	fs := newFlagSet(env, "route list")
	dir := fs.String("dir", "", "ağ klasörü (sahip); boşsa bu cihazın belgesi")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	asJSON := fs.Bool("json", false, "JSON çıktısı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	doc, err := listDocument(env, *dir, *stateDir)
	if err != nil {
		return err
	}
	out := routeListJSON{Routes: doc.AllRoutes(), ExternalExits: doc.ExternalExits, Addressing: doc.Addressing}
	if *asJSON {
		if out.Routes == nil {
			out.Routes = []trust.DeviceRoute{}
		}
		if out.ExternalExits == nil {
			out.ExternalExits = []trust.ExternalExit{}
		}
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	if len(out.Routes) == 0 {
		fmt.Fprintln(env.Stdout, "Onaylı alt ağ rotası yok.")
	}
	for _, r := range out.Routes {
		fmt.Fprintf(env.Stdout, "%-20s yönlendirici %s\n", r.Prefix, r.Device)
	}
	for _, x := range out.ExternalExits {
		fmt.Fprintf(env.Stdout, "düz WireGuard çıkış düğümü %s  %s  DNS %s\n", x.Name, x.Endpoint, x.DNS)
	}
	return nil
}

func cmdRouteCheck(env *Env, args []string) error {
	fs := newFlagSet(env, "route check")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	iface := fs.String("interface", defaultInterfaceName, "tünel arayüzünün adı (denetimden çıkarılır)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	store, secrets, err := deviceState(env, *stateDir)
	if err != nil {
		return err
	}
	doc := store.Document()
	self, err := selfDevice(doc, secrets)
	if err != nil {
		return err
	}
	routes := map[netip.Prefix]string{}
	for _, d := range doc.Devices {
		for _, p := range doc.RoutesVia(self.Name, d.Name) {
			routes[p] = d.Name
		}
	}
	locals, err := osnet.LocalNetworks(*iface)
	if err != nil {
		return err
	}
	conflicts := osnet.RouteConflicts([]netip.Prefix{doc.IPv4Prefix, doc.IPv6Prefix}, routes, locals)
	if len(conflicts) == 0 {
		fmt.Fprintf(env.Stdout, "Çakışma yok: ağ aralığı %s ve %d alt ağ rotası bu bilgisayarın ağlarıyla örtüşmüyor.\n", doc.IPv4Prefix, len(routes))
		return nil
	}
	for _, c := range conflicts {
		fmt.Fprintln(env.Stdout, "uyarı: "+c.Message)
	}
	return nil
}

func cmdExternalExitSet(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-node external set")
	f := addEditFlags(fs)
	name := fs.String("name", "", "çıkış düğümünün adı (küçük harf, rakam, tire; zorunlu)")
	key := fs.String("key", "", "sunucunun WireGuard açık anahtarı (base64; zorunlu)")
	endpoint := fs.String("endpoint", "", "sunucunun adresi host:port (zorunlu)")
	dns := fs.String("dns", "", "sunucunun tünel içindeki DNS çözücüsü, IPv4 (zorunlu; DNS sızıntısını önler)")
	desc := fs.String("description", "", "açıklama")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" || *key == "" || *endpoint == "" || *dns == "" {
		return usageError("--name, --key, --endpoint ve --dns zorunlu")
	}
	k, err := trust.ParseKey(strings.TrimSpace(*key))
	if err != nil {
		return usageError("--key geçerli bir WireGuard anahtarı olmalı")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(*dns))
	if err != nil {
		return usageError("--dns IPv4 adresi olmalı")
	}
	x := trust.ExternalExit{Name: *name, WireGuardKey: k, Endpoint: strings.TrimSpace(*endpoint), DNS: addr, Description: *desc}
	err = runEdit(env, f, func(doc *trust.Document) error { return doc.SetExternalExit(x) })
	if err == nil {
		fmt.Fprintln(env.Stdout, "Sunucuya cihazları eklemek için: openscale exit-node external config --dir ...")
	}
	return err
}

func cmdExternalExitRemove(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-node external rm")
	f := addEditFlags(fs)
	name := fs.String("name", "", "kaldırılacak çıkış düğümü (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" {
		return usageError("--name zorunlu")
	}
	return runEdit(env, f, func(doc *trust.Document) error { return doc.RemoveExternalExit(*name) })
}

func cmdExternalExitConfig(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-node external config")
	dir := fs.String("dir", "", "ağ klasörü (sahip); boşsa bu cihazın belgesi")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	doc, err := listDocument(env, *dir, *stateDir)
	if err != nil {
		return err
	}
	fmt.Fprint(env.Stdout, doc.ExternalExitPeerConfig())
	return nil
}

func cmdExitNetworks(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-node networks")
	trusted := fs.String("trusted-wifi", "", "güvenilir Wi-Fi adları, virgülle (sonucu denemek için)")
	trustWired := fs.Bool("trust-wired", false, "kablolu ağları güvenilir say")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	nets, err := osnet.CurrentNetworks()
	for _, n := range nets {
		kind := "Wi-Fi"
		if n.Kind == osnet.NetworkWired {
			kind = "kablolu"
		}
		name := n.Name
		if name == "" {
			name = "(adı okunamadı)"
		}
		fmt.Fprintf(env.Stdout, "%-8s %s\n", kind, name)
	}
	if err != nil {
		fmt.Fprintf(env.Stderr, "uyarı: ağlar okunamadı: %v\n", err)
	}
	t := osnet.NetworkTrust{Trusted: splitTrustedNames(*trusted), TrustWired: *trustWired}
	if t.IsTrusted(nets, err) {
		fmt.Fprintln(env.Stdout, "Sonuç: güvenilir ağ; --exit-untrusted ile çıkış düğümü kapalı kalır.")
	} else {
		fmt.Fprintln(env.Stdout, "Sonuç: güvenilmeyen ağ; --exit-untrusted ile çıkış düğümü açılır.")
	}
	return nil
}

// splitTrustedNames splits a comma separated list of Wi-Fi names, keeping
// case and inner spaces (SSIDs are case-sensitive).
func splitTrustedNames(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func cmdAddressStrategy(env *Env, args []string) error {
	fs := newFlagSet(env, "address strategy")
	f := addEditFlags(fs)
	strategy := fs.String("strategy", "first", "first (ilk boş adres), sequential (en yüksek adresten sonra) veya random")
	reserve := fs.String("reserve", "", "otomatik verilmeyecek aralıklar, virgülle (ağ içinde)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	var s string
	switch *strategy {
	case "first", "":
		s = trust.AssignFirstFree
	case trust.AssignSequential, trust.AssignRandom:
		s = *strategy
	default:
		return usageError("--strategy first, sequential veya random olmalı")
	}
	reserved, err := parsePrefixList(*reserve)
	if err != nil {
		return err
	}
	sort.Slice(reserved, func(i, j int) bool { return reserved[i].Addr().Less(reserved[j].Addr()) })
	return runEdit(env, f, func(doc *trust.Document) error {
		return doc.SetAddressing(&trust.Addressing{Strategy: s, Reserved: reserved})
	})
}

func cmdDeviceAddress(env *Env, args []string) error {
	fs := newFlagSet(env, "device address")
	f := addEditFlags(fs)
	name := fs.String("name", "", "cihazın adı (zorunlu)")
	ipv4 := fs.String("ipv4", "", "yeni IPv4 adresi, ağ aralığında (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" || *ipv4 == "" {
		return usageError("--name ve --ipv4 zorunlu")
	}
	a, err := netip.ParseAddr(strings.TrimSpace(*ipv4))
	if err != nil || !a.Is4() {
		return usageError("--ipv4 IPv4 adresi olmalı")
	}
	return runEdit(env, f, func(doc *trust.Document) error { return doc.SetDeviceAddress(*name, a) })
}

func cmdSplitTunnelOff(env *Env, args []string) error {
	fs := newFlagSet(env, "split-tunnel off")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if !osnet.SplitTunnelSupported() {
		return osnet.ErrSplitTunnelUnsupported
	}
	if err := osnet.DisableSplitTunnel(envContext(env)); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Uygulama bazlı tünel kuralları kaldırıldı; gruptaki programlar artık çıkış düğümünü kullanır.")
	return nil
}
