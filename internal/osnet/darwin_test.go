package osnet

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/launchd"
	"github.com/openscale/openscale/internal/trust"
)

// fakeDarwin records commands; replies maps a command line prefix to its
// output and error (longest prefix wins).
type fakeDarwin struct {
	mu      sync.Mutex
	calls   []string
	stdin   map[string]string
	replies map[string]darwinReply
}

type darwinReply struct {
	out string
	err error
}

func (f *fakeDarwin) run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, line)
	if stdin != nil {
		if f.stdin == nil {
			f.stdin = map[string]string{}
		}
		f.stdin[line] = string(stdin)
	}
	best := -1
	var r darwinReply
	for prefix, rep := range f.replies {
		if strings.HasPrefix(line, prefix) && len(prefix) > best {
			best, r = len(prefix), rep
		}
	}
	return []byte(r.out), r.err
}

func (f *fakeDarwin) set(prefix, out string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.replies == nil {
		f.replies = map[string]darwinReply{}
	}
	f.replies[prefix] = darwinReply{out: out, err: err}
}

func (f *fakeDarwin) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeDarwin) index(prefix string) int {
	for i, c := range f.callList() {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

func darwinTestConfig() Config {
	return Config{
		Interface: "utun4",
		IPv4:      netip.MustParsePrefix("100.80.0.7/16"),
		IPv6:      netip.MustParsePrefix("fd7a:115c:a1e0::7/48"),
		MTU:       1280,
	}
}

func TestConfigureDarwin(t *testing.T) {
	f := &fakeDarwin{}
	f.set("/sbin/route -q -n add -inet6", "route: writing to routing socket: File exists", errors.New("exit status 1"))
	if err := configureDarwin(context.Background(), f.run, darwinTestConfig()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/sbin/ifconfig utun4 mtu 1280",
		"/sbin/ifconfig utun4 inet 100.80.0.7/16 100.80.0.7 alias",
		"/sbin/ifconfig utun4 inet6 fd7a:115c:a1e0::7 prefixlen 48 alias",
		"/sbin/ifconfig utun4 up",
		"/sbin/route -q -n add -inet 100.80.0.0/16 -interface utun4",
		"/sbin/route -q -n add -inet6 fd7a:115c:a1e0::/48 -interface utun4",
	}
	if got := f.callList(); !reflect.DeepEqual(got, want) {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestConfigureDarwinErrors(t *testing.T) {
	c := darwinTestConfig()
	c.Interface = "OpenScale"
	if err := configureDarwin(context.Background(), (&fakeDarwin{}).run, c); err == nil {
		t.Fatal("non-utun interface accepted")
	}
	f := &fakeDarwin{}
	f.set("/sbin/route -q -n add -inet ", "route: bad", errors.New("exit status 1"))
	if err := configureDarwin(context.Background(), f.run, darwinTestConfig()); err == nil {
		t.Fatal("route failure ignored")
	}
}

func TestDarwinTUNName(t *testing.T) {
	for in, want := range map[string]string{
		"OpenScale": "utun", "utun": "utun", "utun7": "utun7", "utun07": "utun", "utun-1": "utun", "utunx": "utun",
	} {
		if got := darwinTUNName(in); got != want {
			t.Errorf("darwinTUNName(%q) = %q, want %q", in, got, want)
		}
	}
	for name, ok := range map[string]bool{"utun0": true, "utun12": true, "utun": false, "utun01": false, "en0": false, "utun1;x": false, "utun12345": false} {
		if validDarwinIface(name) != ok {
			t.Errorf("validDarwinIface(%q) != %v", name, ok)
		}
	}
}

const darwinNetstat4 = `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
0/1                utun4              USc                 utun4
default            192.168.1.1        UGScg                 en0
default            link#18            UCSIg               utun3
default            10.0.0.1           UGScIg                en7
100.80/16          utun4              USc                 utun4
127                127.0.0.1          UCS                   lo0
`

func TestParseDarwinDefaultRoutes(t *testing.T) {
	routes := parseDarwinDefaultRoutes([]byte(darwinNetstat4))
	if len(routes) != 2 || routes[0].Netif != "en0" || routes[1].Netif != "en7" || !routes[1].scoped() || routes[0].scoped() {
		t.Fatalf("routes = %+v", routes)
	}
	def, ok := darwinPhysicalDefault(routes)
	if !ok || def.Netif != "en0" {
		t.Fatalf("default = %+v", def)
	}
	f := &fakeDarwin{}
	f.set("/usr/sbin/netstat -rn -f inet", darwinNetstat4, nil)
	gws, err := defaultGatewaysDarwin(context.Background(), f.run)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("10.0.0.1")}
	if !reflect.DeepEqual(gws, want) {
		t.Fatalf("gateways = %v", gws)
	}
	if _, ok := darwinPhysicalDefault(nil); ok {
		t.Fatal("no routes gave a default")
	}
	f2 := &fakeDarwin{}
	f2.set("/usr/sbin/netstat", "default  link#6  UCS  en0\n", nil)
	if gws, err := defaultGatewaysDarwin(context.Background(), f2.run); err != nil || len(gws) != 0 {
		t.Fatalf("interface route gave %v, %v", gws, err)
	}
}

func darwinTestMagic() DNSConfig {
	return DNSConfig{Interface: "utun4", Server: netip.MustParseAddr("100.80.255.254"), Domain: "openscale.internal"}
}

func TestDarwinResolverFiles(t *testing.T) {
	dir := t.TempDir()
	f := &fakeDarwin{}
	d := darwinDNS{dir: dir, run: f.run}
	ctx := context.Background()
	// A file of another program must never be touched.
	foreign := filepath.Join(dir, "corp.example")
	if err := os.WriteFile(foreign, []byte("nameserver 10.1.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := d.configure(ctx, darwinTestMagic()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "openscale.internal"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != darwinResolverMarker+"\nnameserver 100.80.255.254\n" {
		t.Fatalf("resolver file = %q", got)
	}
	if fi, err := os.Stat(filepath.Join(dir, "openscale.internal")); err != nil || (fi.Mode().Perm()&0o044 == 0 && os.PathSeparator == '/') {
		t.Fatalf("resolver file must be world-readable: %v %v", fi, err)
	}
	if f.index("/usr/bin/dscacheutil -flushcache") < 0 || f.index("/usr/bin/killall -HUP mDNSResponder") < 0 {
		t.Fatalf("cache not flushed: %v", f.callList())
	}

	n := NetworkDNS{Split: []SplitDomain{{Domain: "home.lan", Nameservers: []netip.Addr{netip.MustParseAddr("100.80.0.2"), netip.MustParseAddr("fd7a:115c:a1e0::2")}}}}
	if err := d.configureNetwork(ctx, darwinTestMagic(), n); err != nil {
		t.Fatal(err)
	}
	split, _ := os.ReadFile(filepath.Join(dir, "home.lan"))
	if !strings.Contains(string(split), "nameserver 100.80.0.2\nnameserver fd7a:115c:a1e0::2\n") {
		t.Fatalf("split file = %q", split)
	}
	if err := d.verify(darwinTestMagic(), n); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "home.lan"), []byte("nameserver 9.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := d.verify(darwinTestMagic(), n); !errors.Is(err, ErrDNSOverwritten) {
		t.Fatalf("overwritten file not noticed: %v", err)
	}
	// The overwritten file is no longer OpenScale's: applying again must
	// refuse it rather than take it over.
	if err := d.configureNetwork(ctx, darwinTestMagic(), n); err == nil {
		t.Fatal("foreign split file overwritten")
	}
	if err := os.Remove(filepath.Join(dir, "home.lan")); err != nil {
		t.Fatal(err)
	}
	if err := d.configureNetwork(ctx, darwinTestMagic(), n); err != nil {
		t.Fatal(err)
	}
	// A split domain dropped from the document goes away.
	if err := d.configureNetwork(ctx, darwinTestMagic(), NetworkDNS{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "home.lan")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stale split file kept: %v", err)
	}
	// Network-wide resolvers have no per-domain form.
	err = d.configureNetwork(ctx, darwinTestMagic(), NetworkDNS{Nameservers: []netip.Addr{netip.MustParseAddr("100.80.0.2")}})
	if !errors.Is(err, ErrNetworkDNSUnsupported) {
		t.Fatalf("network-wide resolvers: %v", err)
	}
	if err := d.configureNetwork(ctx, darwinTestMagic(), NetworkDNS{Nameservers: []netip.Addr{netip.MustParseAddr("100.80.0.2")}, ExitActive: true}); err != nil {
		t.Fatalf("exit active: %v", err)
	}
	if err := d.removeAll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "openscale.internal")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("MagicDNS file kept")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign file removed: %v", err)
	}
	if err := d.write("../evil", nil); err == nil {
		t.Fatal("path traversal accepted")
	}
}

// markBindRecorder is a conn.Bind that records SetMark only.
type markBindRecorder struct {
	conn.Bind
	mu    sync.Mutex
	marks []uint32
	fail  bool
}

func (b *markBindRecorder) SetMark(m uint32) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail {
		return errors.New("no")
	}
	b.marks = append(b.marks, m)
	return nil
}

func (b *markBindRecorder) list() []uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]uint32(nil), b.marks...)
}

// memFiles is an in-memory private file store.
type memFiles struct {
	mu    sync.Mutex
	files map[string][]byte
}

func newMemFiles() *memFiles { return &memFiles{files: map[string][]byte{}} }

func (m *memFiles) write(p string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[p] = append([]byte(nil), data...)
	return nil
}

func (m *memFiles) read(p string, limit int64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.files[p]
	if !ok {
		return nil, fmt.Errorf("open %s: %w", p, fs.ErrNotExist)
	}
	if int64(len(d)) > limit {
		return nil, errors.New("too large")
	}
	return append([]byte(nil), d...), nil
}

func (m *memFiles) remove(p string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[p]; !ok {
		return fmt.Errorf("remove %s: %w", p, fs.ErrNotExist)
	}
	delete(m.files, p)
	return nil
}

func (m *memFiles) has(p string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.files[p]
	return ok
}

func newTestDarwinExit(f *fakeDarwin, mem *memFiles) *darwinExit {
	f.set("/usr/sbin/netstat -rn -f inet", darwinNetstat4, nil)
	f.set("/usr/sbin/networksetup -listallnetworkservices", "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nUSB 10/100/1000 LAN\n", nil)
	f.set("/usr/sbin/networksetup -getdnsservers Wi-Fi", "There aren't any DNS Servers set on Wi-Fi.\n", nil)
	f.set("/usr/sbin/networksetup -getdnsservers USB 10/100/1000 LAN", "1.1.1.1\n9.9.9.9\n", nil)
	return &darwinExit{
		run:      f.run,
		stateDir: "/var/db/openscale",
		write:    mem.write,
		read:     mem.read,
		remove:   mem.remove,
		ifIndex: func(name string) (int, error) {
			switch name {
			case "en0":
				return 6, nil
			case "en7":
				return 18, nil
			}
			return 0, errors.New("no such interface")
		},
	}
}

func TestDarwinExitEnableDisable(t *testing.T) {
	f, mem := &fakeDarwin{}, newMemFiles()
	r := newTestDarwinExit(f, mem)
	bind := &markBindRecorder{}
	exit := trust.Device{Name: "home", IPv4: netip.MustParseAddr("100.80.0.2")}
	if err := r.Enable(exit, nil, "utun4", bind); err != nil {
		t.Fatal(err)
	}
	if got := bind.list(); !reflect.DeepEqual(got, []uint32{6}) {
		t.Fatalf("marks = %v, want the physical interface index", got)
	}
	for _, want := range []string{
		"/sbin/route -q -n add -inet 0.0.0.0/1 -interface utun4",
		"/sbin/route -q -n add -inet 128.0.0.0/1 -interface utun4",
		"/sbin/route -q -n add -inet6 ::/1 -interface utun4",
		"/sbin/route -q -n add -inet6 8000::/1 -interface utun4",
		"/usr/sbin/networksetup -setdnsservers Wi-Fi 100.80.0.2",
		"/usr/sbin/networksetup -setdnsservers USB 10/100/1000 LAN 100.80.0.2",
	} {
		if f.index(want) < 0 {
			t.Errorf("missing %q in\n%s", want, strings.Join(f.callList(), "\n"))
		}
	}
	if f.index("/usr/sbin/networksetup -setdnsservers Bluetooth") >= 0 {
		t.Error("disabled service changed")
	}
	// The servers are saved before they are changed.
	if save, set := f.index("/usr/sbin/networksetup -getdnsservers USB"), f.index("/usr/sbin/networksetup -setdnsservers"); save < 0 || set < save {
		t.Error("DNS changed before it was saved")
	}
	if !mem.has("/var/db/openscale/exit-dns.json") {
		t.Fatal("DNS state not saved")
	}
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
	if err := r.Disable(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"/sbin/route -q -n delete -inet 0.0.0.0/1 -interface utun4",
		"/sbin/route -q -n delete -inet6 8000::/1 -interface utun4",
		"/usr/sbin/networksetup -setdnsservers Wi-Fi Empty",
		"/usr/sbin/networksetup -setdnsservers USB 10/100/1000 LAN 1.1.1.1 9.9.9.9",
	} {
		if f.index(want) < 0 {
			t.Errorf("missing %q in\n%s", want, strings.Join(f.callList(), "\n"))
		}
	}
	if got := bind.list(); got[len(got)-1] != 0 {
		t.Fatalf("socket binding not removed: %v", got)
	}
	if mem.has("/var/db/openscale/exit-dns.json") {
		t.Fatal("DNS state kept after restore")
	}
	if err := r.Disable(); err != nil {
		t.Fatalf("second Disable: %v", err)
	}
}

func TestDarwinExitFailsClosedAndRecovers(t *testing.T) {
	f, mem := &fakeDarwin{}, newMemFiles()
	r := newTestDarwinExit(f, mem)
	exit := trust.Device{Name: "home", IPv4: netip.MustParseAddr("100.80.0.2")}
	if err := r.Enable(exit, nil, "OpenScale", &markBindRecorder{}); err == nil {
		t.Fatal("non-utun interface accepted")
	}
	if err := r.Enable(exit, nil, "utun4", &markBindRecorder{fail: true}); err == nil {
		t.Fatal("unbound sockets accepted")
	}
	if f.index("/sbin/route -q -n add -inet 0.0.0.0/1") >= 0 {
		t.Fatal("routes added although sockets could not be bound (would loop)")
	}
	// A setdnsservers failure undoes the routes and the DNS already set.
	f.set("/usr/sbin/networksetup -setdnsservers USB 10/100/1000 LAN 100.80.0.2", "error", errors.New("exit status 1"))
	if err := r.Enable(exit, nil, "utun4", &markBindRecorder{}); err == nil {
		t.Fatal("DNS failure ignored")
	}
	if f.index("/sbin/route -q -n delete -inet 0.0.0.0/1 -interface utun4") < 0 || f.index("/usr/sbin/networksetup -setdnsservers Wi-Fi Empty") < 0 {
		t.Fatalf("not cleaned up:\n%s", strings.Join(f.callList(), "\n"))
	}
	// Crash recovery restores DNS saved by a run that never got to Disable.
	_ = mem.write("/var/db/openscale/exit-dns.json", []byte(`{"interface":"utun9","services":[{"service":"Wi-Fi","servers":["192.168.1.1"]},{"service":"bad\nname"}]}`))
	f2 := &fakeDarwin{}
	r.run = f2.run
	if err := r.recoverClient(context.Background(), "utun9"); err != nil {
		t.Fatal(err)
	}
	if f2.index("/sbin/route -q -n delete -inet 128.0.0.0/1 -interface utun9") < 0 || f2.index("/usr/sbin/networksetup -setdnsservers Wi-Fi 192.168.1.1") < 0 {
		t.Fatalf("recover:\n%s", strings.Join(f2.callList(), "\n"))
	}
	for _, c := range f2.callList() {
		if strings.Contains(c, "bad") {
			t.Fatalf("invalid service name used: %q", c)
		}
	}
	if mem.has("/var/db/openscale/exit-dns.json") {
		t.Fatal("state kept after recovery")
	}
}

func TestParseNetworkServicesAndDNS(t *testing.T) {
	got := parseNetworkServices([]byte("An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Thunderbolt Bridge\n\nEthernet\n"))
	if !reflect.DeepEqual(got, []string{"Wi-Fi", "Ethernet"}) {
		t.Fatalf("services = %v", got)
	}
	if s := parseDNSServers([]byte("There aren't any DNS Servers set on Wi-Fi.\n")); len(s) != 0 {
		t.Fatalf("servers = %v", s)
	}
	if s := parseDNSServers([]byte("1.1.1.1\n2606:4700:4700::1111\n")); !reflect.DeepEqual(s, []string{"1.1.1.1", "2606:4700:4700::1111"}) {
		t.Fatalf("servers = %v", s)
	}
}

func TestPFKillSwitchRules(t *testing.T) {
	rules, err := pfKillSwitchRules(KillSwitchConfig{Interface: "utun4"})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(rules), "\n")
	idx := func(s string) int {
		for i, l := range lines {
			if strings.HasPrefix(l, s) {
				return i
			}
		}
		return -1
	}
	for _, must := range []string{
		"pass quick on lo0 all",
		"pass quick on utun4 all",
		"pass out quick inet proto udp from any port 68 to any port 67",
		"pass out quick inet6 proto udp from any port 546 to any port 547",
		"pass quick inet6 proto icmp6 icmp6-type",
		"block drop out quick proto { tcp, udp } from any to any port { 53, 853 }",
		"pass out quick proto udp from any to any user root",
		"pass out quick proto tcp from any to any port { 80, 443 } user root",
	} {
		if idx(must) < 0 {
			t.Errorf("missing %q in\n%s", must, rules)
		}
	}
	// The STUN sub-anchor (#625) is evaluated after OpenScale's own
	// exceptions and before the final block.
	if i := idx(`anchor "stun"`); i < 0 || i < idx("pass out quick proto tcp from any to any port { 80, 443 } user root") || i > len(lines)-2 {
		t.Fatalf("STUN sub-anchor missing or misplaced:\n%s", rules)
	}
	if !strings.HasSuffix(stunAnchor, "/"+pfSTUNSubAnchor) || !strings.HasPrefix(stunAnchor, strings.Trim(strings.TrimPrefix(pfAnchorLine, "anchor "), `"`)+"/") {
		t.Fatalf("STUN plan anchor %q is not the kill switch's sub-anchor", stunAnchor)
	}
	if lines[len(lines)-1] != "block drop quick all" {
		t.Fatalf("last rule = %q, want the default block", lines[len(lines)-1])
	}
	// DNS outside the tunnel is blocked before OpenScale's own exception,
	// and the tunnel permit comes before both.
	if !(idx("pass quick on utun4") < idx("block drop out quick proto { tcp, udp } from any to any port") &&
		idx("block drop out quick proto { tcp, udp } from any to any port") < idx("pass out quick proto udp from any to any user root")) {
		t.Fatalf("rule order wrong:\n%s", rules)
	}
	if strings.Contains(rules, "10.0.0.0/8") {
		t.Fatal("LAN allowed without AllowLAN")
	}
	lan, _ := pfKillSwitchRules(KillSwitchConfig{AllowLAN: true})
	if !strings.Contains(lan, "pass out quick inet from any to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255/32 }") ||
		!strings.Contains(lan, "pass out quick inet6 from any to { fe80::/10, fc00::/7, ff00::/8 }") {
		t.Fatalf("LAN rules:\n%s", lan)
	}
	if strings.Index(lan, "port { 53, 853 }") > strings.Index(lan, "10.0.0.0/8") {
		t.Fatal("LAN permit before the DNS block: local DNS would leak")
	}
	if strings.Contains(lan, "pass quick on utun") {
		t.Fatal("tunnel permit without an interface")
	}
	for _, bad := range []string{"en0", "utun4; pass all", "OpenScale", "utun"} {
		if _, err := pfKillSwitchRules(KillSwitchConfig{Interface: bad}); err == nil {
			t.Errorf("interface %q accepted", bad)
		}
	}
}

func TestPFMainRulesetAndParsers(t *testing.T) {
	conf := []byte("scrub-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\nload anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"")
	main := pfMainRuleset(conf)
	if !strings.HasPrefix(string(main), string(conf)+"\n") || !pfReferencesAnchor(main) {
		t.Fatalf("main ruleset:\n%s", main)
	}
	if again := pfMainRuleset(main); string(again) != string(main) {
		t.Fatal("anchor line added twice")
	}
	if pfReferencesAnchor([]byte("anchor \"com.openscale.evil\" all\n")) {
		t.Fatal("other anchor matched")
	}
	if !pfReferencesAnchor([]byte("anchor \"com.apple/*\" all\nanchor \"com.openscale\" all\n")) {
		t.Fatal("pfctl -sr form not matched")
	}
	if tok, ok := parsePFToken([]byte("No ALTQ support in kernel\npf enabled\nToken : 18446744071234567890\n")); !ok || tok != "18446744071234567890" {
		t.Fatalf("token = %q %v", tok, ok)
	}
	if _, ok := parsePFToken([]byte("pf already enabled\n")); ok {
		t.Fatal("token without a token line")
	}
	if !pfEnabled([]byte("No ALTQ support in kernel\nStatus: Enabled for 0 days 00:01:02           Debug: Urgent\n")) || pfEnabled([]byte("Status: Disabled\n")) {
		t.Fatal("pf status parse")
	}
}

func newTestPF(f *fakeDarwin, mem *memFiles, dir string) *pfKillSwitch {
	return &pfKillSwitch{
		run:         f.run,
		stateDir:    "/var/db/openscale",
		launchDir:   dir,
		pfConf:      "/etc/pf.conf",
		write:       mem.write,
		writePublic: func(p string, data []byte) error { return os.WriteFile(p, data, 0o644) },
		read: func(p string, limit int64) ([]byte, error) {
			if strings.HasPrefix(p, dir) {
				return os.ReadFile(p)
			}
			return mem.read(p, limit)
		},
		remove: func(p string) error {
			if strings.HasPrefix(p, dir) {
				return os.Remove(p)
			}
			return mem.remove(p)
		},
		exists: func(p string) bool {
			if p == darwinPfctl || p == darwinLaunchctl {
				return true
			}
			_, err := os.Stat(p)
			return err == nil
		},
	}
}

func TestPFKillSwitchInstallRemove(t *testing.T) {
	f, mem := &fakeDarwin{}, newMemFiles()
	k := newTestPF(f, mem, t.TempDir())
	_ = mem.write("/etc/pf.conf", []byte("anchor \"com.apple/*\"\n"))
	f.set("/sbin/pfctl -E", "pf enabled\nToken : 4242\n", nil)
	if err := k.install(KillSwitchConfig{Interface: "utun4", AllowLAN: true}); err != nil {
		t.Fatal(err)
	}
	calls := f.callList()
	load, main, enable := f.index("/sbin/pfctl -a com.openscale -f -"), f.index("/sbin/pfctl -f -"), f.index("/sbin/pfctl -E")
	if load < 0 || main < 0 || enable < 0 || !(load < main && main < enable) {
		t.Fatalf("order (anchor, main ruleset, enable):\n%s", strings.Join(calls, "\n"))
	}
	if !strings.Contains(f.stdin["/sbin/pfctl -a com.openscale -f -"], "pass quick on utun4 all") {
		t.Fatal("anchor rules not fed on stdin")
	}
	if !pfReferencesAnchor([]byte(f.stdin["/sbin/pfctl -f -"])) || !strings.HasPrefix(f.stdin["/sbin/pfctl -f -"], "anchor \"com.apple/*\"\n") {
		t.Fatalf("main ruleset = %q", f.stdin["/sbin/pfctl -f -"])
	}
	saved, ok, err := k.loadSaved()
	if err != nil || !ok || saved.Token != "4242" || saved.Interface != "utun4" || !saved.AllowLAN {
		t.Fatalf("saved = %+v %v %v", saved, ok, err)
	}

	// Installed: anchor rules, main reference and pf enabled.
	f.set("/sbin/pfctl -a com.openscale -s rules", "pass quick on lo0 all flags S/SA keep state\nblock drop quick all\n", nil)
	f.set("/sbin/pfctl -s rules", "anchor \"com.apple/*\" all\nanchor \"com.openscale\" all\n", nil)
	f.set("/sbin/pfctl -s info", "Status: Enabled for 0 days\n", nil)
	if on, err := k.installed(); err != nil || !on {
		t.Fatalf("installed = %v, %v", on, err)
	}
	f.set("/sbin/pfctl -s info", "Status: Disabled\n", nil)
	if on, _ := k.installed(); on {
		t.Fatal("installed with pf disabled")
	}

	// A second install (main ruleset already hooked) does not reload it and
	// releases the earlier reference.
	f2 := &fakeDarwin{}
	f2.set("/sbin/pfctl -s rules", "anchor \"com.openscale\" all\n", nil)
	f2.set("/sbin/pfctl -E", "Token : 5151\n", nil)
	k.run = f2.run
	if ok, err := k.restore(); err != nil || !ok {
		t.Fatalf("restore = %v %v", ok, err)
	}
	if f2.index("/sbin/pfctl -f -") >= 0 {
		t.Fatal("main ruleset reloaded although it already references the anchor")
	}
	if f2.index("/sbin/pfctl -X 4242") < 0 {
		t.Fatal("earlier pf reference not released")
	}

	f3 := &fakeDarwin{}
	f3.set("/sbin/pfctl -s rules", "anchor \"com.openscale\" all\n", nil)
	k.run = f3.run
	if err := k.removeAll(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/sbin/pfctl -a com.openscale -F all",
		"/sbin/pfctl -s rules",
		"/sbin/pfctl -f /etc/pf.conf",
		"/sbin/pfctl -X 5151",
	}
	if got := f3.callList(); !reflect.DeepEqual(got, want) {
		t.Fatalf("remove:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if _, ok, _ := k.loadSaved(); ok {
		t.Fatal("saved configuration kept")
	}
	if ok, err := k.restore(); ok || err != nil {
		t.Fatalf("restore without saved = %v %v", ok, err)
	}
}

func TestPFKillSwitchFailsClosed(t *testing.T) {
	f, mem := &fakeDarwin{}, newMemFiles()
	k := newTestPF(f, mem, t.TempDir())
	if err := k.install(KillSwitchConfig{Interface: "en0"}); err == nil {
		t.Fatal("bad interface accepted")
	}
	f.set("/sbin/pfctl -a com.openscale -f -", "syntax error", errors.New("exit status 1"))
	if err := k.install(KillSwitchConfig{}); err == nil {
		t.Fatal("load failure ignored")
	}
	if f.index("/sbin/pfctl -E") >= 0 {
		t.Fatal("pf enabled without the anchor")
	}
	f2 := &fakeDarwin{}
	f2.set("/sbin/pfctl -E", "pf enabled\n", nil)
	k.run = f2.run
	_ = mem.write("/etc/pf.conf", []byte(""))
	if err := k.install(KillSwitchConfig{}); err == nil {
		t.Fatal("missing token accepted")
	}
	_ = mem.write("/var/db/openscale/killswitch.json", []byte(`{"interface":"utun1; pass all"}`))
	if _, _, err := k.loadSaved(); err == nil {
		t.Fatal("bad saved interface accepted")
	}
}

func TestPFBootDaemon(t *testing.T) {
	dir := t.TempDir()
	f, mem := &fakeDarwin{}, newMemFiles()
	k := newTestPF(f, mem, dir)
	if err := k.enableBoot("relative/openscale"); err == nil {
		t.Fatal("relative program accepted")
	}
	if err := k.enableBoot("/usr/local/bin/open scale"); err == nil {
		t.Fatal("program with a space accepted")
	}
	if err := k.enableBoot("/usr/local/bin/openscale"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "com.openscale.killswitch.plist"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<string>com.openscale.killswitch</string>", "<string>/usr/local/bin/openscale</string>", "<string>killswitch</string>", "<string>restore</string>", "<key>RunAtLoad</key>\n\t<true/>"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("plist lacks %q:\n%s", want, data)
		}
	}
	if !launchd.HasMarker(data, pfBootMarker) {
		t.Fatal("marker missing")
	}
	if on, _ := k.bootEnabled(); !on {
		t.Fatal("boot daemon not reported")
	}
	if err := k.disableBoot(); err != nil {
		t.Fatal(err)
	}
	if on, _ := k.bootEnabled(); on {
		t.Fatal("boot daemon kept")
	}
	// A hand-written file of the same name is left alone.
	p := filepath.Join(dir, "com.openscale.killswitch.plist")
	if err := os.WriteFile(p, []byte("<plist/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := k.disableBoot(); err == nil {
		t.Fatal("foreign plist removed")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
}

func TestDeployMacOSKillSwitchPlistMatches(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "macos", "com.openscale.killswitch.plist"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := launchd.Plist(bootJob("/usr/local/bin/openscale"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.ReplaceAll(string(data), "\r\n", "\n"); got != string(want) {
		t.Fatalf("deploy/macos/com.openscale.killswitch.plist differs from what killswitch boot on writes:\n%s", want)
	}
}
