package srvaudit

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestLUKSRemoteUnlock(t *testing.T) {
	base := func() fstest.MapFS {
		return fstest.MapFS{
			"proc/mounts":                file("sysfs /sys sysfs rw 0 0\n/dev/mapper/vg-root / ext4 rw 0 0\n"),
			"sys/block/dm-1/dm/name":     file("vg-root\n"),
			"sys/block/dm-1/dm/uuid":     file("LVM-abc\n"),
			"sys/block/dm-1/slaves/dm-0": &fstest.MapFile{Mode: 0o755 | 1<<31},
			"sys/block/dm-0/dm/name":     file("cryptroot\n"),
			"sys/block/dm-0/dm/uuid":     file("CRYPT-LUKS2-1234-cryptroot\n"),
		}
	}
	fsys := base()
	if c := checkLUKSRemoteUnlock(fsys); c.Status != Warn || !strings.Contains(c.Detail, "dropbear") {
		t.Fatalf("no dropbear: %+v", c)
	}
	fsys["etc/dropbear/initramfs/dropbear.conf"] = file(`DROPBEAR_OPTIONS="-p 2222"` + "\n")
	fsys["etc/dropbear/initramfs/authorized_keys"] = file("ssh-ed25519 AAAA x\n")
	if c := checkLUKSRemoteUnlock(fsys); c.Status != Warn || !strings.Contains(c.Detail, "-s") || !strings.Contains(c.Detail, "WireGuard") {
		t.Fatalf("weak dropbear: %+v", c)
	}
	fsys["etc/dropbear/initramfs/dropbear.conf"] = file(`DROPBEAR_OPTIONS="-sjk -p 100.64.0.9:2222 -c cryptroot-unlock"` + "\n")
	if c := checkLUKSRemoteUnlock(fsys); c.Status != Pass {
		t.Fatalf("good dropbear: %+v", c)
	}
	plain := fstest.MapFS{"proc/mounts": file("/dev/vda1 / ext4 rw 0 0\n")}
	if c := checkLUKSRemoteUnlock(plain); c.Status != Fail {
		t.Fatalf("plain disk: %+v", c)
	}
	if c := checkLUKSRemoteUnlock(fstest.MapFS{}); c.Status != Unknown {
		t.Fatalf("no proc: %+v", c)
	}
	if !hasFlag("-s -j -k", "-k") || hasFlag("-p 22 -c cryptroot-unlock", "-s") || !hasFlag("-sjk", "-j") {
		t.Fatal("flag parsing")
	}
}

func TestCoreDumpsAndNoMetadata(t *testing.T) {
	fsys := fstest.MapFS{"etc/systemd/system/openscale-coordinator.service": file("[Service]\nUser=openscale\n")}
	if c := checkCoreDumps(fsys, RoleCoordinator); c.Status != Warn {
		t.Fatalf("no LimitCORE: %+v", c)
	}
	fsys["etc/systemd/coredump.conf.d/50-openscale.conf"] = file("[Coredump]\nStorage=none\n")
	if c := checkCoreDumps(fsys, RoleCoordinator); c.Status != Pass {
		t.Fatalf("storage none: %+v", c)
	}
	if c := checkNoMetadata(fstest.MapFS{}); c.Status != Unknown {
		t.Fatalf("no file: %+v", c)
	}
	nm := fstest.MapFS{CoordinatorStateDir + "/coordinator-hardening.json": file(`{"schema":1,"no_metadata":true}`)}
	nm["var/log/journal/x"] = file("")
	nm[CoordinatorStateDir+"/relay-usage.json"] = file("{}")
	if c := checkNoMetadata(nm); c.Status != Fail || !strings.Contains(c.Detail, "relay-usage") || !strings.Contains(c.Detail, "journald") {
		t.Fatalf("leaky: %+v", c)
	}
	delete(nm, CoordinatorStateDir+"/relay-usage.json")
	nm["etc/systemd/journald.conf.d/50-openscale.conf"] = file("[Journal]\nStorage=volatile\n")
	if c := checkNoMetadata(nm); c.Status != Pass {
		t.Fatalf("clean: %+v", c)
	}
}

// fakeSSH records what the change does.
type fakeSSH struct {
	addrs     []netip.Addr
	session   string
	listeners []Listener
	after     []Listener // listeners after the reload
	files     map[string]string
	ran       []string
	fail      map[string]bool
	reloaded  bool
}

func (f *fakeSSH) WriteFile(name string, data []byte) error {
	f.files[name] = string(data)
	return nil
}
func (f *fakeSSH) Remove(name string) error { delete(f.files, name); return nil }
func (f *fakeSSH) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.ran = append(f.ran, cmd)
	for k := range f.fail {
		if strings.HasPrefix(cmd, k) {
			return []byte("hata"), errors.New("failed")
		}
	}
	if strings.HasPrefix(cmd, "systemctl reload") {
		f.reloaded = true
	}
	return nil, nil
}
func (f *fakeSSH) HostAddrs() ([]netip.Addr, error) { return f.addrs, nil }
func (f *fakeSSH) SessionSource() (netip.Addr, bool) {
	if f.session == "" {
		return netip.Addr{}, false
	}
	return netip.MustParseAddr(f.session), true
}
func (f *fakeSSH) Listeners() []Listener {
	if f.reloaded {
		return f.after
	}
	return f.listeners
}
func (f *fakeSSH) Sleep(time.Duration) {}

func sshFS() fstest.MapFS {
	return fstest.MapFS{
		"etc/ssh/sshd_config":                     file("Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n"),
		"lib/systemd/system/ssh.service":          file("[Service]\n"),
		"etc/ssh/sshd_config.d/10-openscale.conf": file("PermitRootLogin no\n"),
	}
}

func TestSSHTunnelOnlyPlanAndApply(t *testing.T) {
	tunnel := []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
	tip := netip.MustParseAddr("100.64.0.9")
	sys := &fakeSSH{addrs: []netip.Addr{netip.MustParseAddr("203.0.113.5"), tip}, session: "198.51.100.1",
		listeners: []Listener{{Proto: "tcp", Addr: netip.IPv4Unspecified(), Port: 22}},
		after:     []Listener{{Proto: "tcp", Addr: tip, Port: 22}}, files: map[string]string{}}
	fsys := sshFS()
	// A session from the internet is refused: the tunnel path is unproven.
	p := PlanSSHTunnelOnly(fsys, sys, tunnel, false)
	if p.Ready() || p.Session != "public" || len(p.Public) != 1 {
		t.Fatalf("public session plan: %+v", p)
	}
	sys.session = "100.64.0.20"
	p = PlanSSHTunnelOnly(fsys, sys, tunnel, false)
	if !p.Ready() || p.Service != "ssh" || !strings.Contains(p.Content, "ListenAddress 100.64.0.9") || strings.Contains(p.Content, "203.0.113.5") {
		t.Fatalf("plan: %+v", p)
	}
	if err := ApplySSHTunnelOnly(context.Background(), sys, p, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, ok := sys.files[SSHTunnelDropIn]; !ok {
		t.Fatal("drop-in not written")
	}
	// Order: test, arm the timer, then reload.
	idx := func(prefix string) int {
		for i, c := range sys.ran {
			if strings.HasPrefix(c, prefix) {
				return i
			}
		}
		return -1
	}
	if !(idx("/usr/sbin/sshd -t") < idx("systemd-run") && idx("systemd-run") < idx("systemctl reload ssh")) || idx("/usr/sbin/sshd -t") < 0 {
		t.Fatalf("order: %v", sys.ran)
	}
	if !strings.Contains(sys.ran[idx("systemd-run")], "--on-active=120") {
		t.Fatalf("rollback delay: %v", sys.ran)
	}
	// Confirmation from the tunnel stops the timer; from outside it is refused.
	sys.session = "203.0.113.77"
	if err := ConfirmSSHTunnelOnly(context.Background(), sys, tunnel); err == nil {
		t.Fatal("confirmed from outside the tunnel")
	}
	sys.session = "100.64.0.21"
	if err := ConfirmSSHTunnelOnly(context.Background(), sys, tunnel); err != nil {
		t.Fatal(err)
	}
}

func TestSSHTunnelOnlyFailsSafe(t *testing.T) {
	tunnel := []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
	tip := netip.MustParseAddr("100.64.0.9")
	mk := func() *fakeSSH {
		return &fakeSSH{addrs: []netip.Addr{tip}, session: "100.64.0.20", files: map[string]string{}, fail: map[string]bool{},
			listeners: []Listener{{Proto: "tcp", Addr: netip.IPv4Unspecified(), Port: 22}}, after: []Listener{{Proto: "tcp", Addr: tip, Port: 22}}}
	}
	fsys := sshFS()
	// sshd -t fails: drop-in removed, no reload.
	sys := mk()
	sys.fail["/usr/sbin/sshd -t"] = true
	p := PlanSSHTunnelOnly(fsys, sys, tunnel, false)
	if err := ApplySSHTunnelOnly(context.Background(), sys, p, time.Minute); err == nil || len(sys.files) != 0 || sys.reloaded {
		t.Fatalf("sshd -t failure: files %v reloaded %v", sys.files, sys.reloaded)
	}
	// The timer cannot be armed: nothing changes.
	sys = mk()
	sys.fail["systemd-run"] = true
	if err := ApplySSHTunnelOnly(context.Background(), sys, p, time.Minute); err == nil || len(sys.files) != 0 || sys.reloaded {
		t.Fatal("applied without a rollback timer")
	}
	// sshd keeps a public listener: error, the timer will restore.
	sys = mk()
	sys.after = append(sys.after, Listener{Proto: "tcp", Addr: netip.IPv4Unspecified(), Port: 22})
	if err := ApplySSHTunnelOnly(context.Background(), sys, p, time.Minute); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("public listener not reported: %v", err)
	}
	// Blockers: another ListenAddress, socket activation, no tunnel address.
	bad := sshFS()
	bad["etc/ssh/sshd_config.d/20-x.conf"] = file("ListenAddress 0.0.0.0\n")
	bad["etc/systemd/system/sockets.target.wants/ssh.socket"] = file("")
	sys = mk()
	sys.addrs = []netip.Addr{netip.MustParseAddr("203.0.113.5")}
	p = PlanSSHTunnelOnly(bad, sys, tunnel, false)
	if len(p.Blockers) != 3 {
		t.Fatalf("blockers: %v", p.Blockers)
	}
	if err := ApplySSHTunnelOnly(context.Background(), sys, p, time.Minute); err == nil {
		t.Fatal("applied a blocked plan")
	}
	// Our own earlier drop-in is not a foreign ListenAddress.
	again := sshFS()
	again[SSHTunnelDropIn] = file("ListenAddress 100.64.0.9\n")
	if p := PlanSSHTunnelOnly(again, mk(), tunnel, false); !p.Ready() {
		t.Fatalf("second run blocked: %v", p.Blockers)
	}
	if _, ok := sessionFromEnv("100.64.0.20 51234 100.64.0.9 22"); !ok {
		t.Fatal("SSH_CONNECTION not parsed")
	}
}

func utmpRecord(typ uint16, line, user string, sec uint32) []byte {
	r := make([]byte, utmpSize)
	binary.LittleEndian.PutUint16(r[0:2], typ)
	copy(r[utmpLineOff:], line)
	copy(r[utmpUserOff:], user)
	binary.LittleEndian.PutUint32(r[utmpTimeOff:], sec)
	return r
}

func TestProviderTraces(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	fsys := fstest.MapFS{
		"proc/sys/kernel/random/boot_id": file("aaaa\n"),
		"proc/sys/kernel/osrelease":      file("6.1.0-20-amd64\n"),
		"proc/cmdline":                   file("root=/dev/vda1 console=ttyS0,115200\n"),
		"var/lib/cloud/data/instance-id": file("i-1\n"),
	}
	first := CurrentBoot(fsys, now)
	ev := ProviderTraces(fsys, nil, first)
	if len(ev) != 2 || ev[0].Kind != EventFirstCheck || ev[1].Kind != EventSerialGetty {
		t.Fatalf("first: %+v", ev)
	}
	// Reboot with another kernel, command line and cloud-init instance, a
	// serial console login and the guest agent.
	fsys["proc/sys/kernel/random/boot_id"] = file("bbbb\n")
	fsys["proc/sys/kernel/osrelease"] = file("6.1.0-21-amd64\n")
	fsys["proc/cmdline"] = file("root=/dev/vda1 init=/bin/sh console=ttyS0\n")
	fsys["var/lib/cloud/data/instance-id"] = file("i-2\n")
	wtmp := append(utmpRecord(7, "pts/0", "owner", 1), utmpRecord(7, "ttyS0", "root", 2)...)
	wtmp = append(wtmp, utmpRecord(8, "ttyS0", "", 3)...)
	fsys["var/log/wtmp"] = &fstest.MapFile{Data: wtmp, Mode: 0o644}
	fsys["etc/systemd/system/multi-user.target.wants/qemu-guest-agent.service"] = file("")
	cur := CurrentBoot(fsys, now.Add(time.Hour))
	kinds := map[string]bool{}
	for _, e := range ProviderTraces(fsys, &first, cur) {
		kinds[e.Kind] = true
	}
	for _, k := range []string{EventReboot, EventKernelChanged, EventCmdlineChanged, EventCloudInit, EventConsoleLogin, EventGuestAgent} {
		if !kinds[k] {
			t.Errorf("missing %s in %v", k, kinds)
		}
	}
	if len(cur.ConsoleLogins) != 1 || !strings.HasPrefix(cur.ConsoleLogins[0], "ttyS0 root") {
		t.Fatalf("logins %v", cur.ConsoleLogins)
	}
	// Same boot again: only static findings.
	for _, e := range ProviderTraces(fsys, &cur, CurrentBoot(fsys, now.Add(2*time.Hour))) {
		if e.Kind != EventGuestAgent && e.Kind != EventSerialGetty {
			t.Fatalf("unexpected %+v", e)
		}
	}
	if _, err := ParseBootState([]byte(`{"schema":1,"extra":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if strings.Contains(cur.CmdlineSHA256, "init") {
		t.Fatal("command line stored in clear")
	}
}
