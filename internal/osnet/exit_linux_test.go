//go:build linux

package osnet

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"

	"github.com/openscale/openscale/internal/trust"
)

const (
	testIPv6Routes = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00450003     eth0\n" +
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n" +
		"20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n" +
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00450003     wlan0\n"
	testIPv4Routes = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
)

// fakeSys records commands instead of running them. sysctl -w writes
// into files, so reads after a write see the new value.
type fakeSys struct {
	mu    sync.Mutex
	files map[string]string
	have  map[string]bool
	cmds  []string
	stdin []string
	fail  func(cmd string) bool
}

func newFakeSys() *fakeSys {
	return &fakeSys{
		files: map[string]string{
			"/proc/sys/net/ipv4/ip_forward":                  "0\n",
			"/proc/sys/net/ipv6/conf/all/forwarding":         "0\n",
			"/proc/sys/net/ipv6/conf/eth0/accept_ra":         "1\n",
			"/proc/sys/net/ipv6/conf/wlan0/accept_ra":        "0\n",
			"/proc/sys/net/ipv4/conf/all/rp_filter":          "2\n",
			"/proc/sys/net/ipv4/conf/eth0/rp_filter":         "0\n",
			"/proc/sys/net/ipv4/conf/all/src_valid_mark":     "0\n",
			"/proc/net/ipv6_route":                           testIPv6Routes,
			"/proc/net/route":                                testIPv4Routes,
			"/proc/net/if_inet6":                             "00000000000000000000000000000001 01 80 10 80       lo\n",
			"/proc/sys/net/ipv6/conf/OpenScale/accept_ra":    "0\n",
			"/proc/sys/net/ipv4/conf/OpenScale/rp_filter":    "0\n",
			"/proc/sys/net/ipv6/conf/default/accept_ra":      "1\n",
			"/proc/sys/net/ipv4/conf/default/src_valid_mark": "0\n",
		},
		have: map[string]bool{"nft": true, "sysctl": true, "ip": true, "resolvectl": true},
	}
}

func (f *fakeSys) ops() sysOps {
	return sysOps{
		run: func(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			cmd := strings.Join(append([]string{name}, args...), " ")
			f.cmds = append(f.cmds, cmd)
			if stdin != nil {
				f.stdin = append(f.stdin, string(stdin))
			}
			if f.fail != nil && f.fail(cmd) {
				return []byte("failed"), errors.New("failed: " + cmd)
			}
			if name == "sysctl" && len(args) == 2 && args[0] == "-w" {
				key, value, _ := strings.Cut(args[1], "=")
				f.files[sysctlPath(key)] = value + "\n"
			}
			return nil, nil
		},
		read: func(path string) ([]byte, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			v, ok := f.files[path]
			if !ok {
				return nil, fs.ErrNotExist
			}
			return []byte(v), nil
		},
		lookPath: func(file string) (string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.have[file] {
				return "/usr/sbin/" + file, nil
			}
			return "", errors.New("not found")
		},
	}
}

func (f *fakeSys) value(key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.TrimSpace(f.files[sysctlPath(key)])
}

func (f *fakeSys) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.cmds)
}

func (f *fakeSys) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds, f.stdin = nil, nil
}

func indexOf(t *testing.T, cmds []string, want string) int {
	t.Helper()
	i := slices.Index(cmds, want)
	if i < 0 {
		t.Fatalf("command %q not run; got:\n%s", want, strings.Join(cmds, "\n"))
	}
	return i
}

var testExitNAT = ExitNAT{
	Interface: "OpenScale",
	IPv4:      netip.MustParsePrefix("100.80.0.0/16"),
	IPv6:      netip.MustParsePrefix("fd7a:1:2::/48"),
}

func TestIPv6DefaultInterfaces(t *testing.T) {
	f := newFakeSys()
	got := f.ops().ipv6DefaultInterfaces("wlan0")
	if !slices.Equal(got, []string{"eth0"}) {
		t.Fatalf("default IPv6 interfaces = %v", got)
	}
	if got := f.ops().ipv4DefaultInterfaces(); !slices.Equal(got, []string{"eth0"}) {
		t.Fatalf("default IPv4 interfaces = %v", got)
	}
	delete(f.files, "/proc/net/ipv6_route")
	if got := f.ops().ipv6DefaultInterfaces(""); got != nil {
		t.Fatalf("no IPv6: %v", got)
	}
	for _, bad := range []string{"", "a/b", "..", "x=1", "a b", "abcdefghijklmnop"} {
		if validSysctlName(bad) {
			t.Errorf("accepted interface name %q", bad)
		}
	}
	if !validSysctlName("eth0.100") {
		t.Error("VLAN interface rejected")
	}
}

func TestExitNATAcceptRAAndRestore(t *testing.T) {
	f := newFakeSys()
	s := &exitNATState{mode: NetfilterAuto}
	ctx := context.Background()
	if err := s.enable(ctx, f.ops(), testExitNAT); err != nil {
		t.Fatal(err)
	}
	cmds := f.commands()
	ra := indexOf(t, cmds, "sysctl -w net/ipv6/conf/eth0/accept_ra=2")
	fwd6 := indexOf(t, cmds, "sysctl -w net/ipv6/conf/all/forwarding=1")
	indexOf(t, cmds, "sysctl -w net/ipv4/ip_forward=1")
	if ra > fwd6 {
		t.Fatal("accept_ra must be raised before IPv6 forwarding is turned on")
	}
	nft := indexOf(t, cmds, "nft -f -")
	if nft < fwd6 {
		t.Fatal("rules installed before forwarding")
	}
	if slices.Contains(cmds, "sysctl -w net/ipv6/conf/wlan0/accept_ra=2") {
		t.Fatal("accept_ra=0 must stay 0")
	}
	if len(f.stdin) != 1 || !strings.Contains(f.stdin[0], `oifname != "OpenScale" ip saddr 100.80.0.0/16 masquerade`) ||
		!strings.Contains(f.stdin[0], "192.168.0.0/16") || !strings.Contains(f.stdin[0], "fc00::/7") {
		t.Fatalf("nft script:\n%v", f.stdin)
	}
	if f.value("net/ipv6/conf/eth0/accept_ra") != "2" || f.value("net/ipv4/ip_forward") != "1" {
		t.Fatal("sysctls not applied")
	}

	// A second enable (exit role re-applied) keeps the original values.
	if err := s.enable(ctx, f.ops(), testExitNAT); err != nil {
		t.Fatal(err)
	}
	f.reset()
	if err := s.disable(ctx, f.ops()); err != nil {
		t.Fatal(err)
	}
	cmds = f.commands()
	indexOf(t, cmds, "nft delete table inet openscale_exit")
	back6 := indexOf(t, cmds, "sysctl -w net/ipv6/conf/all/forwarding=0")
	backRA := indexOf(t, cmds, "sysctl -w net/ipv6/conf/eth0/accept_ra=1")
	if backRA < back6 {
		t.Fatal("accept_ra restored before forwarding was turned off")
	}
	for key, want := range map[string]string{
		"net/ipv4/ip_forward": "0", "net/ipv6/conf/all/forwarding": "0", "net/ipv6/conf/eth0/accept_ra": "1",
	} {
		if got := f.value(key); got != want {
			t.Errorf("%s = %s, want %s", key, got, want)
		}
	}
	// Disabling again changes nothing.
	f.reset()
	if err := s.disable(ctx, f.ops()); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.commands() {
		if strings.HasPrefix(c, "sysctl") {
			t.Fatalf("second disable touched sysctls: %s", c)
		}
	}
}

func TestExitNATKeepsForeignChanges(t *testing.T) {
	f := newFakeSys()
	f.files["/proc/sys/net/ipv4/ip_forward"] = "1\n" // already on: not ours to turn off
	s := &exitNATState{mode: NetfilterAuto}
	ctx := context.Background()
	if err := s.enable(ctx, f.ops(), testExitNAT); err != nil {
		t.Fatal(err)
	}
	// Someone else lowers accept_ra while the exit node runs.
	f.files["/proc/sys/net/ipv6/conf/eth0/accept_ra"] = "0\n"
	if err := s.disable(ctx, f.ops()); err != nil {
		t.Fatal(err)
	}
	if f.value("net/ipv4/ip_forward") != "1" {
		t.Fatal("forwarding that was on before was turned off")
	}
	if f.value("net/ipv6/conf/eth0/accept_ra") != "0" {
		t.Fatal("a value changed by someone else was overwritten")
	}
}

func TestExitNATRollsBackOnRuleFailure(t *testing.T) {
	f := newFakeSys()
	f.fail = func(cmd string) bool { return cmd == "nft -f -" }
	s := &exitNATState{mode: NetfilterAuto}
	if err := s.enable(context.Background(), f.ops(), testExitNAT); err == nil {
		t.Fatal("enable succeeded although nft failed")
	}
	if f.value("net/ipv4/ip_forward") != "0" || f.value("net/ipv6/conf/all/forwarding") != "0" || f.value("net/ipv6/conf/eth0/accept_ra") != "1" {
		t.Fatal("sysctls not rolled back")
	}
	if s.saved != nil {
		t.Fatal("saved values kept after rollback")
	}
}

func TestExitNATIPTablesFallback(t *testing.T) {
	f := newFakeSys()
	f.have["nft"] = false
	f.have["iptables"], f.have["ip6tables"] = true, true
	// The FORWARD jump already exists for IPv6 only.
	f.fail = func(cmd string) bool {
		return strings.Contains(cmd, " -C ") && !strings.HasPrefix(cmd, "ip6tables -w 5 -t filter -C FORWARD")
	}
	s := &exitNATState{mode: NetfilterAuto}
	ctx := context.Background()
	if err := s.enable(ctx, f.ops(), testExitNAT); err != nil {
		t.Fatal(err)
	}
	cmds := f.commands()
	indexOf(t, cmds, "iptables -w 5 -t filter -A OPENSCALE-EXIT -i OpenScale -d 192.168.0.0/16 -j DROP")
	indexOf(t, cmds, "iptables -w 5 -t filter -A OPENSCALE-EXIT -i OpenScale ! -s 100.80.0.0/16 -j DROP")
	indexOf(t, cmds, "iptables -w 5 -t filter -I FORWARD 1 -j OPENSCALE-EXIT")
	indexOf(t, cmds, "iptables -w 5 -t nat -A OPENSCALE-EXIT-NAT ! -o OpenScale -s 100.80.0.0/16 -j MASQUERADE")
	indexOf(t, cmds, "ip6tables -w 5 -t filter -A OPENSCALE-EXIT -i OpenScale -d fc00::/7 -j DROP")
	indexOf(t, cmds, "ip6tables -w 5 -t nat -A OPENSCALE-EXIT-NAT ! -o OpenScale -s fd7a:1:2::/48 -j MASQUERADE")
	if slices.Contains(cmds, "ip6tables -w 5 -t filter -I FORWARD 1 -j OPENSCALE-EXIT") {
		t.Fatal("existing jump inserted twice")
	}
	for _, c := range cmds {
		if strings.HasPrefix(c, "nft") {
			t.Fatalf("nft used although missing: %s", c)
		}
	}

	f.reset()
	f.fail = func(cmd string) bool { return strings.Contains(cmd, " -D ") } // no jumps left
	if err := s.disable(ctx, f.ops()); err != nil {
		t.Fatal(err)
	}
	cmds = f.commands()
	indexOf(t, cmds, "iptables -w 5 -t filter -X OPENSCALE-EXIT")
	indexOf(t, cmds, "ip6tables -w 5 -t nat -X OPENSCALE-EXIT-NAT")
}

func TestNetfilterMode(t *testing.T) {
	f := newFakeSys()
	f.have["iptables"], f.have["ip6tables"] = true, true
	if b, err := chooseBackend(f.ops(), NetfilterIPTables); err != nil || b != NetfilterIPTables {
		t.Fatalf("iptables mode: %v %v", b, err)
	}
	f.have["nft"] = false
	if _, err := chooseBackend(f.ops(), NetfilterNFTables); err == nil {
		t.Fatal("nftables mode without nft accepted")
	}
	f.have["iptables"] = false
	if _, err := chooseBackend(f.ops(), NetfilterAuto); err == nil {
		t.Fatal("auto mode without any backend accepted")
	}
	if err := SetNetfilterMode("pf"); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if err := SetNetfilterMode(NetfilterAuto); err != nil {
		t.Fatal(err)
	}
}

// markBind records SetMark calls.
type markBind struct {
	conn.Bind
	mu    sync.Mutex
	marks []uint32
}

func (b *markBind) SetMark(m uint32) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.marks = append(b.marks, m)
	return nil
}

func (b *markBind) last() uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.marks) == 0 {
		return 0
	}
	return b.marks[len(b.marks)-1]
}

func testExitDoc() (*trust.Document, trust.Device) {
	doc := &trust.Document{DNSDomain: "openscale.internal", IPv4Prefix: netip.MustParsePrefix("100.80.0.0/16")}
	return doc, trust.Device{Name: "vps", IPv4: netip.MustParseAddr("100.80.0.7")}
}

func TestLinuxExitRouter(t *testing.T) {
	f := newFakeSys()
	r := &linuxExitRouter{ops: f.ops()}
	bind := &markBind{Bind: bindtest.NewChannelBinds()[0]}
	doc, exit := testExitDoc()
	if err := r.Enable(exit, doc, "OpenScale", bind); err != nil {
		t.Fatal(err)
	}
	if bind.last() != exitFwMark {
		t.Fatal("WireGuard sockets not marked")
	}
	cmds := f.commands()
	for _, want := range []string{
		"ip -4 route replace 0.0.0.0/1 dev OpenScale table 20307",
		"ip -4 route replace 128.0.0.0/1 dev OpenScale table 20307",
		"ip -6 route replace ::/1 dev OpenScale table 20307",
		"ip -6 route replace 8000::/1 dev OpenScale table 20307",
		"ip -4 rule add priority 5270 table main suppress_prefixlength 0",
		"ip -4 rule add priority 5271 not fwmark 20307 table 20307",
		"ip -6 rule add priority 5271 not fwmark 20307 table 20307",
		"resolvectl dns OpenScale 100.80.0.7",
		"resolvectl domain OpenScale ~. ~openscale.internal ~80.100.in-addr.arpa",
	} {
		indexOf(t, cmds, want)
	}
	for _, s := range f.stdin {
		if strings.Contains(s, exitClientTable) {
			t.Fatal("connmark rules installed although rp_filter is loose")
		}
	}
	if len(f.stdin) != 1 || !strings.Contains(f.stdin[0], "table inet "+leakGuardTable) {
		t.Fatalf("DNS/IPv6 leak guard not installed: %v", f.stdin)
	}
	f.reset()
	if err := r.Disable(); err != nil {
		t.Fatal(err)
	}
	if bind.last() != 0 {
		t.Fatal("socket mark not cleared")
	}
	cmds = f.commands()
	for _, want := range []string{
		"ip -4 rule del priority 5271",
		"ip -4 rule del priority 5270",
		"ip -6 route flush table 20307",
		"resolvectl dns OpenScale 100.80.255.254",
		"resolvectl domain OpenScale ~openscale.internal ~80.100.in-addr.arpa",
	} {
		indexOf(t, cmds, want)
	}
	f.reset()
	if err := r.Disable(); err != nil || len(f.commands()) != 0 {
		t.Fatalf("second disable ran %v (%v)", f.commands(), err)
	}
}

func TestLinuxExitRouterStrictRPFilter(t *testing.T) {
	f := newFakeSys()
	f.files["/proc/sys/net/ipv4/conf/eth0/rp_filter"] = "1\n"
	f.files["/proc/sys/net/ipv4/conf/all/rp_filter"] = "0\n"
	delete(f.files, "/proc/net/if_inet6") // IPv6 disabled
	r := &linuxExitRouter{ops: f.ops()}
	bind := &markBind{Bind: bindtest.NewChannelBinds()[0]}
	doc, exit := testExitDoc()
	if err := r.Enable(exit, doc, "OpenScale", bind); err != nil {
		t.Fatal(err)
	}
	cmds := f.commands()
	indexOf(t, cmds, "sysctl -w net/ipv4/conf/all/src_valid_mark=1")
	indexOf(t, cmds, "nft -f -")
	for _, c := range cmds {
		if strings.HasPrefix(c, "ip -6") {
			t.Fatalf("IPv6 command without IPv6: %s", c)
		}
	}
	if err := r.Disable(); err != nil {
		t.Fatal(err)
	}
	indexOf(t, f.commands(), "nft delete table inet openscale_client")
	if f.value("net/ipv4/conf/all/src_valid_mark") != "0" {
		t.Fatal("src_valid_mark not restored")
	}
}

func TestLinuxExitRouterFailsClosed(t *testing.T) {
	f := newFakeSys()
	f.have["resolvectl"] = false
	r := &linuxExitRouter{ops: f.ops()}
	bind := &markBind{Bind: bindtest.NewChannelBinds()[0]}
	doc, exit := testExitDoc()
	if err := r.Enable(exit, doc, "OpenScale", bind); err == nil {
		t.Fatal("enabled without resolvectl: DNS would leak")
	}
	if len(f.commands()) != 0 || bind.last() != 0 {
		t.Fatal("system changed although enable was refused")
	}

	f.have["resolvectl"] = true
	f.fail = func(cmd string) bool { return strings.HasPrefix(cmd, "ip -4 rule add priority 5271") }
	if err := r.Enable(exit, doc, "OpenScale", bind); err == nil {
		t.Fatal("enable succeeded although a rule failed")
	}
	cmds := f.commands()
	indexOf(t, cmds, "ip -4 route flush table 20307")
	if bind.last() != 0 {
		t.Fatal("mark left after a failed enable")
	}
	if err := r.Enable(exit, doc, "bad name", bind); err == nil {
		t.Fatal("invalid interface accepted")
	}
}

func TestReverseZones(t *testing.T) {
	cases := map[string][]string{
		"100.80.0.0/16": {"80.100.in-addr.arpa"},
		"10.0.0.0/8":    {"10.in-addr.arpa"},
		"100.80.0.0/15": {"80.100.in-addr.arpa", "81.100.in-addr.arpa"},
		"192.0.2.7/32":  {"7.2.0.192.in-addr.arpa"},
		"fd7a:1:2::/48": {"2.0.0.0.1.0.0.0.a.7.d.f.ip6.arpa"},
		"fd7a:1:2::/47": {"2.0.0.0.1.0.0.0.a.7.d.f.ip6.arpa", "3.0.0.0.1.0.0.0.a.7.d.f.ip6.arpa"},
	}
	for p, want := range cases {
		if got := reverseZones(netip.MustParsePrefix(p)); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", p, got, want)
		}
	}
	if got := reverseZones(netip.MustParsePrefix("100.64.0.0/10")); len(got) != 64 || got[0] != "64.100.in-addr.arpa" || got[63] != "127.100.in-addr.arpa" {
		t.Errorf("CGNAT zones %v", got)
	}
	if got := reverseZones(netip.MustParsePrefix("100.0.0.0/1")); !slices.Equal(got, []string{"in-addr.arpa"}) {
		t.Errorf("too many sub-zones must fall back to the enclosing zone: %v", got)
	}
	if reverseZones(netip.Prefix{}) != nil {
		t.Error("invalid prefix")
	}
}
