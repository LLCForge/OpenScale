//go:build linux

package osnet

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// Linux subnet router with the fake system (ADR-0133); nothing touches the
// host.

func routerCfg() RouteConfig {
	return RouteConfig{Interface: "OpenScale",
		Own:      []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("fd12::/48")},
		Overlay4: netip.MustParsePrefix("100.80.0.0/16"), Overlay6: netip.MustParsePrefix("fd00:1::/48")}
}

func TestSubnetRouterNFT(t *testing.T) {
	f := newFakeSys()
	r := &SubnetRouter{ops: f.ops(), fwd: &exitNATState{mode: NetfilterAuto, shared: true}}
	if err := r.Apply(routerCfg()); err != nil {
		t.Fatal(err)
	}
	if len(f.stdin) != 1 {
		t.Fatalf("nft scripts: %v", f.stdin)
	}
	s := f.stdin[0]
	for _, want := range []string{
		`iifname "OpenScale" ip saddr 100.80.0.0/16 ip daddr { 192.168.1.0/24 } meta mark set 0x4f55 accept`,
		`oifname "OpenScale" ip6 saddr { fd12::/48 } ip6 daddr fd00:1::/48 meta mark set 0x4f55 accept`,
		`iifname "OpenScale" drop`,
		`oifname != "OpenScale" ip saddr 100.80.0.0/16 ip daddr { 192.168.1.0/24 } masquerade`,
		"maxseg size set rt mtu",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("script lacks %q:\n%s", want, s)
		}
	}
	if f.files["/proc/sys/net/ipv4/ip_forward"] != "1\n" || f.files["/proc/sys/net/ipv6/conf/eth0/accept_ra"] != "2\n" {
		t.Fatal("forwarding and accept_ra must be raised")
	}
	// Same configuration: nothing reinstalled.
	f.cmds, f.stdin = nil, nil
	if err := r.Apply(routerCfg()); err != nil || len(f.cmds) != 0 {
		t.Fatalf("reapply: %v %v", err, f.cmds)
	}
	// Exit role: no blanket drop.
	cfg := routerCfg()
	cfg.ExitRole, cfg.NoMasquerade = true, true
	if err := r.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if s := f.stdin[len(f.stdin)-1]; strings.Contains(s, `iifname "OpenScale" drop`) || strings.Contains(s, "masquerade") {
		t.Fatalf("exit role / no masquerade script:\n%s", s)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.cmds, "nft delete table inet "+subnetTable) || f.files["/proc/sys/net/ipv4/ip_forward"] != "0\n" ||
		f.files["/proc/sys/net/ipv6/conf/eth0/accept_ra"] != "1\n" {
		t.Fatalf("close must remove the table and restore sysctls: %v", f.cmds)
	}
}

func TestSubnetRouterIPTables(t *testing.T) {
	f := newFakeSys()
	f.have = map[string]bool{"iptables": true, "ip6tables": true, "sysctl": true, "ip": true}
	r := &SubnetRouter{ops: f.ops(), fwd: &exitNATState{mode: NetfilterAuto}}
	if err := r.Apply(routerCfg()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"iptables -w 5 -t filter -A OPENSCALE-SUBNET -i OpenScale -s 100.80.0.0/16 -d 192.168.1.0/24 -j ACCEPT",
		"iptables -w 5 -t filter -I FORWARD 1 -j OPENSCALE-SUBNET",
		"ip6tables -w 5 -t filter -A OPENSCALE-SUBNET -i OpenScale -j DROP",
		"iptables -w 5 -t nat -A OPENSCALE-SUBNET-NAT ! -o OpenScale -s 100.80.0.0/16 -d 192.168.1.0/24 -j MASQUERADE",
	} {
		if !slices.Contains(f.cmds, want) {
			t.Fatalf("missing %q in\n%s", want, strings.Join(f.cmds, "\n"))
		}
	}
}

func TestSubnetClientRoutesAndExceptions(t *testing.T) {
	f := newFakeSys()
	r := &SubnetRouter{ops: f.ops(), fwd: &exitNATState{}}
	cfg := RouteConfig{Interface: "OpenScale", Client: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		ExitActive: true, ExitExcept: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}
	if err := r.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip -4 route replace 192.168.1.0/24 dev OpenScale proto static",
		"ip -4 rule add priority 5269 to 203.0.113.0/24 lookup main",
	} {
		if !slices.Contains(f.cmds, want) {
			t.Fatalf("missing %q in %v", want, f.cmds)
		}
	}
	f.cmds = nil
	cfg.ExitActive = false
	if err := r.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if len(f.cmds) != 1 || f.cmds[0] != "ip -4 rule del priority 5269 to 203.0.113.0/24 lookup main" {
		t.Fatalf("exception removal: %v", f.cmds)
	}
	f.cmds = nil
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if len(f.cmds) != 1 || f.cmds[0] != "ip -4 route del 192.168.1.0/24 dev OpenScale" {
		t.Fatalf("close: %v", f.cmds)
	}
}

// The exit node and the subnet router share forwarding: whichever stops
// first leaves it on, the last one restores the original value.
func TestForwardingSharedWithExit(t *testing.T) {
	f := newFakeSys()
	exit := &exitNATState{mode: NetfilterAuto, shared: true}
	r := &SubnetRouter{ops: f.ops(), fwd: &exitNATState{mode: NetfilterAuto, shared: true}}
	ctx := context.Background()
	nat := ExitNAT{Interface: "OpenScale", IPv4: netip.MustParsePrefix("100.80.0.0/16"), IPv6: netip.MustParsePrefix("fd00:1::/48")}
	if err := exit.enable(ctx, f.ops(), nat); err != nil {
		t.Fatal(err)
	}
	if err := r.Apply(routerCfg()); err != nil {
		t.Fatal(err)
	}
	if err := exit.disable(ctx, f.ops()); err != nil {
		t.Fatal(err)
	}
	if f.files["/proc/sys/net/ipv4/ip_forward"] != "1\n" {
		t.Fatal("the router still needs forwarding")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if f.files["/proc/sys/net/ipv4/ip_forward"] != "0\n" || f.files["/proc/sys/net/ipv6/conf/eth0/accept_ra"] != "1\n" {
		t.Fatal("the last user must restore the original values")
	}
}

func TestExitRateLimitRules(t *testing.T) {
	c := ExitNAT{Interface: "OpenScale", IPv4: netip.MustParsePrefix("100.80.0.0/16"), IPv6: netip.MustParsePrefix("fd00:1::/48")}
	plain, err := nftExitScript(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "@up4") || !strings.Contains(string(plain), "meta mark 0x4f55 accept") {
		t.Fatalf("no limit:\n%s", plain)
	}
	c.RateLimit = 2 * 1024 * 1024
	limited, err := nftExitScript(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"set up4 { type ipv4_addr; flags dynamic,timeout; timeout 5m; }",
		`iifname "OpenScale" update @up4 { ip saddr limit rate over 2097152 bytes/second burst 524288 bytes } drop`,
		`oifname "OpenScale" update @down6 { ip6 daddr limit rate over 2097152 bytes/second burst 524288 bytes } drop`} {
		if !strings.Contains(string(limited), want) {
			t.Fatalf("limit script lacks %q:\n%s", want, limited)
		}
	}
	steps := iptablesExitSteps(c)
	found := false
	for _, s := range steps {
		found = found || slices.Contains(s.args, "--hashlimit-above")
	}
	if !found {
		t.Fatal("iptables hashlimit missing")
	}
	if ValidateExitRateLimit(1000) == nil || ValidateExitRateLimit(0) != nil {
		t.Fatal("rate limit bounds")
	}
}

func TestCurrentNetworksLinux(t *testing.T) {
	f := newFakeSys()
	f.have["nmcli"] = true
	ops := f.ops()
	run := ops.run
	ops.run = func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
		if name == "nmcli" {
			return []byte("wifi:connected:Ev\n"), nil
		}
		return run(ctx, stdin, name, args...)
	}
	nets, err := currentNetworks(ops)
	if err != nil || len(nets) != 1 || nets[0].Name != "Ev" {
		t.Fatalf("nets %v %v", nets, err)
	}
	// Without nmcli: the default route interface is wired.
	delete(f.have, "nmcli")
	nets, err = currentNetworks(f.ops())
	if err != nil || len(nets) != 1 || nets[0].Kind != NetworkWired {
		t.Fatalf("fallback nets %v %v", nets, err)
	}
}

func TestSplitTunnelLinux(t *testing.T) {
	f := newFakeSys()
	old := splitFS
	defer func() { splitFS = old }()
	var made, wrote []string
	splitFS.stat = func(string) error { return nil }
	splitFS.mkdir = func(p string) error { made = append(made, p); return nil }
	splitFS.writeFile = func(p string, d []byte) error { wrote = append(wrote, p+"="+string(d)); return nil }
	if err := enableSplitTunnel(context.Background(), f.ops()); err != nil {
		t.Fatal(err)
	}
	if len(made) != 1 || made[0] != "/sys/fs/cgroup/openscale-bypass" || len(f.stdin) != 1 ||
		!strings.Contains(f.stdin[0], `socket cgroupv2 level 1 "openscale-bypass" meta mark set 0x4f53`) {
		t.Fatalf("enable: %v %v", made, f.stdin)
	}
	if err := JoinBypassGroup(42); err != nil || len(wrote) != 1 || wrote[0] != "/sys/fs/cgroup/openscale-bypass/cgroup.procs=42" {
		t.Fatalf("join: %v %v", err, wrote)
	}
	if JoinBypassGroup(0) == nil {
		t.Fatal("pid 0 must be refused")
	}
	if err := disableSplitTunnel(context.Background(), f.ops()); err != nil || !slices.Contains(f.cmds, "nft delete table inet openscale_split") {
		t.Fatalf("disable: %v %v", err, f.cmds)
	}
}
