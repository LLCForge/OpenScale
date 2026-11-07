//go:build linux

package osnet

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn/bindtest"
)

// fakeKS is a ksLinux whose files live in memory and whose commands are
// only recorded: no test touches nftables or systemd.
type fakeKS struct {
	*ksLinux
	sys   *fakeSys
	mu    sync.Mutex
	files map[string]string
	table bool
}

func newFakeKS() *fakeKS {
	f := &fakeKS{sys: newFakeSys(), files: map[string]string{}}
	f.sys.have["systemctl"] = true
	ops := f.sys.ops()
	run := ops.run
	ops.run = func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
		out, err := run(ctx, stdin, name, args...)
		if err != nil {
			return out, err
		}
		cmd := strings.Join(append([]string{name}, args...), " ")
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case cmd == "nft -f -" && strings.Contains(string(stdin), "table inet "+killSwitchTable+" {"):
			f.table = true
		case cmd == "nft delete table inet "+killSwitchTable, cmd == "nft list table inet "+killSwitchTable,
			strings.HasPrefix(cmd, "nft add element inet "+killSwitchTable), cmd == "nft flush set inet "+killSwitchTable+" "+captiveSet:
			if !f.table {
				return nil, errors.New("Error: No such file or directory")
			}
			if strings.HasPrefix(cmd, "nft delete") {
				f.table = false
			}
		}
		return nil, nil
	}
	ops.read = func(path string) ([]byte, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		v, ok := f.files[path]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return []byte(v), nil
	}
	f.ksLinux = &ksLinux{
		ops: ops, stateDir: "/var/lib/openscale", unitDir: "/etc/systemd/system",
		write: func(path string, data []byte) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.files[path] = string(data)
			return nil
		},
		readFile: func(path string, _ int64) ([]byte, error) { return ops.read(path) },
		remove: func(path string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			if _, ok := f.files[path]; !ok {
				return fs.ErrNotExist
			}
			delete(f.files, path)
			return nil
		},
	}
	return f
}

func TestLinuxKillSwitchLifecycle(t *testing.T) {
	f := newFakeKS()
	if on, err := f.installed(); err != nil || on {
		t.Fatalf("installed before install: %v %v", on, err)
	}
	if err := f.install(KillSwitchConfig{Interface: "OpenScale", AllowLAN: true}); err != nil {
		t.Fatal(err)
	}
	cmds := f.sys.commands()
	indexOf(t, cmds, "nft -f -")
	if len(f.sys.stdin) != 1 || !strings.Contains(f.sys.stdin[0], `oifname "OpenScale" accept`) {
		t.Fatalf("script: %v", f.sys.stdin)
	}
	var saved ksSaved
	if err := json.Unmarshal([]byte(f.files["/var/lib/openscale/killswitch.json"]), &saved); err != nil ||
		saved != (ksSaved{Interface: "OpenScale", AllowLAN: true}) {
		t.Fatalf("saved config %q (%v)", f.files["/var/lib/openscale/killswitch.json"], err)
	}
	if on, err := f.installed(); err != nil || !on {
		t.Fatalf("installed after install: %v %v", on, err)
	}

	// A reboot clears the kernel's tables; restore puts the same rules back.
	f.table = false
	f.sys.reset()
	if ok, err := f.restore(); err != nil || !ok {
		t.Fatalf("restore: %v %v", ok, err)
	}
	if len(f.sys.stdin) != 1 || !strings.Contains(f.sys.stdin[0], "255.255.255.255/32 } accept") {
		t.Fatalf("restored script lost the saved options: %v", f.sys.stdin)
	}

	if err := f.removeAll(); err != nil {
		t.Fatal(err)
	}
	if f.table || f.files["/var/lib/openscale/killswitch.json"] != "" {
		t.Fatal("table or saved config left after off")
	}
	// Removing twice is fine (crash cleanup, "killswitch off" by hand).
	if err := f.removeAll(); err != nil {
		t.Fatal(err)
	}
	if ok, err := f.restore(); err != nil || ok {
		t.Fatalf("restore without saved config: %v %v", ok, err)
	}
}

func TestLinuxKillSwitchNeedsNft(t *testing.T) {
	f := newFakeKS()
	f.sys.have["nft"] = false
	if err := f.install(KillSwitchConfig{}); err == nil {
		t.Fatal("installed without nft")
	}
	if len(f.files) != 0 {
		t.Fatal("config saved although nothing was installed")
	}
	if err := f.removeAll(); err != nil {
		t.Fatal(err)
	}
	f.files["/var/lib/openscale/killswitch.json"] = `{"interface":"a\"b"}`
	f.sys.have["nft"] = true
	if _, err := f.restore(); err == nil {
		t.Fatal("tampered saved interface accepted")
	}
}

func TestLinuxKillSwitchBootUnit(t *testing.T) {
	f := newFakeKS()
	if err := f.enableBoot("relative/openscale"); err == nil {
		t.Fatal("relative program path accepted")
	}
	if err := f.enableBoot("/usr/bin/open scale"); err == nil {
		t.Fatal("path with a space accepted")
	}
	if err := f.enableBoot("/usr/bin/openscale"); err != nil {
		t.Fatal(err)
	}
	unit := f.files["/etc/systemd/system/openscale-killswitch.service"]
	for _, want := range []string{"Before=network-pre.target", "DefaultDependencies=no", "ExecStart=/usr/bin/openscale killswitch restore", "WantedBy=sysinit.target", "ConditionPathExists=/var/lib/openscale/killswitch.json"} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit lacks %q:\n%s", want, unit)
		}
	}
	cmds := f.sys.commands()
	if indexOf(t, cmds, "systemctl daemon-reload") > indexOf(t, cmds, "systemctl enable openscale-killswitch.service") {
		t.Fatal("enabled before daemon-reload")
	}
	if on, err := f.bootEnabled(); err != nil || !on {
		t.Fatalf("boot enabled: %v %v", on, err)
	}
	if err := f.disableBoot(); err != nil {
		t.Fatal(err)
	}
	indexOf(t, f.sys.commands(), "systemctl disable openscale-killswitch.service")
	if on, _ := f.bootEnabled(); on {
		t.Fatal("unit left after disable")
	}
}

func TestLinuxCaptiveException(t *testing.T) {
	f := newFakeKS()
	gw := []netip.Addr{netip.MustParseAddr("192.168.1.1")}
	if err := f.allowCaptive(gw, time.Minute); !errors.Is(err, ErrKillSwitchNotInstalled) {
		t.Fatalf("exception without kill switch: %v", err)
	}
	if err := f.install(KillSwitchConfig{Interface: "OpenScale"}); err != nil {
		t.Fatal(err)
	}
	f.sys.reset()
	if err := f.allowCaptive([]netip.Addr{netip.MustParseAddr("1.1.1.1")}, time.Minute); err == nil {
		t.Fatal("public address accepted")
	}
	if err := f.allowCaptive(gw, 20*time.Minute); err == nil {
		t.Fatal("too long exception accepted")
	}
	if err := f.allowCaptive(gw, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	indexOf(t, f.sys.commands(), "nft add element inet openscale_killswitch captive4 { 192.168.1.1 timeout 120s }")
	if err := f.revokeCaptive(); err != nil {
		t.Fatal(err)
	}
	indexOf(t, f.sys.commands(), "nft flush set inet openscale_killswitch captive4")
	f.table = false
	if err := f.revokeCaptive(); err != nil {
		t.Fatalf("revoke without table: %v", err)
	}
}

func TestLinuxExitRouterLeakGuard(t *testing.T) {
	f := newFakeSys()
	r := &linuxExitRouter{ops: f.ops()}
	bind := &markBind{Bind: bindtest.NewChannelBinds()[0]}
	doc, exit := testExitDoc()
	if err := r.Enable(exit, doc, "OpenScale", bind); err != nil {
		t.Fatal(err)
	}
	if !LeakGuardActive() {
		t.Fatal("leak guard not reported active")
	}
	if err := r.Disable(); err != nil {
		t.Fatal(err)
	}
	indexOf(t, f.commands(), "nft delete table inet openscale_leakguard")
	if LeakGuardActive() {
		t.Fatal("leak guard reported after disable")
	}

	// Without nft the exit node still works, but the guard is missing.
	f = newFakeSys()
	f.have["nft"] = false
	r = &linuxExitRouter{ops: f.ops()}
	if err := r.Enable(exit, doc, "OpenScale", bind); err != nil {
		t.Fatal(err)
	}
	if LeakGuardActive() {
		t.Fatal("leak guard reported without nft")
	}
	_ = r.Disable()

	// nft present but failing: refuse instead of running unguarded.
	f = newFakeSys()
	f.fail = func(cmd string) bool { return cmd == "nft -f -" }
	r = &linuxExitRouter{ops: f.ops()}
	if err := r.Enable(exit, doc, "OpenScale", bind); err == nil {
		t.Fatal("exit node enabled although the leak guard failed")
	}
	indexOf(t, f.commands(), "ip -4 route flush table 20307")
}

func TestLinuxHostFirewall(t *testing.T) {
	f := newFakeSys()
	f.have["firewall-cmd"] = true
	f.have["ufw"] = true
	ops := f.ops()
	run := ops.run
	ops.run = func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
		_, _ = run(ctx, stdin, name, args...)
		switch strings.Join(append([]string{name}, args...), " ") {
		case "firewall-cmd --state":
			return []byte("running\n"), nil
		case "firewall-cmd --get-zone-of-interface=OpenScale":
			return []byte("no zone\n"), errors.New("exit status 2")
		case "ufw status verbose":
			return []byte("Status: active\nDefault: deny (incoming), allow (outgoing)\n"), nil
		}
		return nil, nil
	}
	got, err := checkHostFirewall(context.Background(), ops, "OpenScale", HostFirewallAuto)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Tool != "firewalld" || !got[0].Fixed || got[1].Tool != "ufw" || got[1].Fixed || got[1].Fix != "sudo ufw allow in on OpenScale" {
		t.Fatalf("findings %+v", got)
	}
	cmds := f.commands()
	indexOf(t, cmds, "firewall-cmd --zone=trusted --change-interface=OpenScale")
	for _, c := range cmds {
		if strings.Contains(c, "--permanent") || strings.HasPrefix(c, "ufw allow") || strings.HasPrefix(c, "nft") {
			t.Fatalf("persistent firewall change or nft parse while managed: %s", c)
		}
	}

	f.reset()
	got, err = checkHostFirewall(context.Background(), ops, "OpenScale", HostFirewallWarn)
	if err != nil || len(got) != 2 || got[0].Fixed {
		t.Fatalf("warn mode changed something: %+v %v", got, err)
	}
	for _, c := range f.commands() {
		if strings.Contains(c, "--change-interface") {
			t.Fatal("warn mode changed the zone")
		}
	}
	if got, err := checkHostFirewall(context.Background(), ops, "OpenScale", HostFirewallOff); err != nil || got != nil {
		t.Fatalf("off mode: %+v %v", got, err)
	}
}

func TestLinuxHostFirewallTailscale(t *testing.T) {
	f := newFakeSys()
	f.have["iptables"] = true
	ops := f.ops()
	run := ops.run
	ops.run = func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
		_, _ = run(ctx, stdin, name, args...)
		if strings.Join(append([]string{name}, args...), " ") == "iptables -S ts-input" {
			return []byte(tsInput), nil
		}
		return nil, nil
	}
	got, err := checkHostFirewall(context.Background(), ops, "OpenScale", HostFirewallAuto)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Tool != "tailscale" || got[0].Fixed || got[0].Fix != "sudo iptables -I ts-input 1 -i OpenScale -j ACCEPT" {
		t.Fatalf("findings %+v", got)
	}
	for _, c := range f.commands() {
		if strings.HasPrefix(c, "iptables -I") || strings.HasPrefix(c, "iptables -A") {
			t.Fatalf("Tailscale's chain was changed: %s", c)
		}
	}
}
