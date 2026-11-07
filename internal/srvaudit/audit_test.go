package srvaudit

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/posture"
)

func file(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s), Mode: 0o644} }

const hardenedUnit = `[Unit]
Description=x
[Service]
User=openscale
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateDevices=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
SystemCallFilter=@system-service
RestrictAddressFamilies=AF_INET AF_INET6
MemoryMax=512M
TasksMax=256
LimitNOFILE=4096
LimitCORE=0
`

func goodSystem() fstest.MapFS {
	return fstest.MapFS{
		"etc/ssh/sshd_config":                              file("Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n"),
		"etc/ssh/sshd_config.d/10-openscale.conf":          file("PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n"),
		"usr/bin/apt-get":                                  file(""),
		"usr/bin/unattended-upgrade":                       file(""),
		"etc/apt/apt.conf.d/20auto-upgrades":               file("APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"),
		"run/systemd/timesync/synchronized":                file(""),
		"etc/systemd/system/openscale-coordinator.service": file(hardenedUnit),
		"etc/default/openscale-coordinator":                file("OPENSCALE_TCP_LISTEN=:443\n"),
	}
}

func goodFacts() Facts {
	return Facts{DiskEncryption: posture.On, Firewall: posture.On, Listeners: []Listener{
		{Proto: "udp", Port: 41820}, {Proto: "tcp", Port: 22}, {Proto: "tcp", Port: 443},
	}}
}

func statusOf(r Report, id string) Status {
	for _, c := range r.Checks {
		if c.ID == id {
			return c.Status
		}
	}
	return ""
}

func TestAuditHardenedServer(t *testing.T) {
	r := Run(goodSystem(), goodFacts(), Options{})
	if r.Score != 100 {
		for _, c := range r.Checks {
			t.Logf("%s %s %s", c.ID, c.Status, c.Detail)
		}
		t.Fatalf("score = %d", r.Score)
	}
}

func TestAuditFindsProblems(t *testing.T) {
	fsys := goodSystem()
	// The first value wins: an include placed after the main setting does
	// not turn passwords off.
	fsys["etc/ssh/sshd_config"] = file("PasswordAuthentication yes\nPermitRootLogin yes\nInclude sshd_config.d/*.conf\n")
	delete(fsys, "etc/apt/apt.conf.d/20auto-upgrades")
	delete(fsys, "run/systemd/timesync/synchronized")
	fsys["etc/systemd/system/openscale-coordinator.service.d/override.conf"] = file("[Service]\nUser=root\nMemoryMax=\nTasksMax=\n")
	facts := goodFacts()
	facts.Listeners = append(facts.Listeners, Listener{Proto: "tcp", Port: 6379})
	facts.DiskEncryption = posture.Unknown
	r := Run(fsys, facts, Options{})
	want := map[string]Status{"ssh-password": Fail, "ssh-root": Fail, "ports": Warn, "updates": Warn, "disk": Unknown, "time": Fail, "unit": Fail, "firewall": Pass}
	for id, s := range want {
		if got := statusOf(r, id); got != s {
			t.Errorf("%s = %s, want %s", id, got, s)
		}
	}
	if r.Score >= 50 {
		t.Fatalf("score = %d", r.Score)
	}
}

func TestAuditMatchBlockIgnored(t *testing.T) {
	fsys := goodSystem()
	fsys["etc/ssh/sshd_config"] = file("Match User x\nPasswordAuthentication no\n")
	delete(fsys, "etc/ssh/sshd_config.d/10-openscale.conf")
	if s := statusOf(Run(fsys, goodFacts(), Options{}), "ssh-password"); s != Fail {
		t.Fatalf("match block counted: %s", s)
	}
	// No sshd at all is fine.
	delete(fsys, "etc/ssh/sshd_config")
	if s := statusOf(Run(fsys, goodFacts(), Options{}), "ssh-password"); s != Pass {
		t.Fatalf("no sshd: %s", s)
	}
}

func TestAuditExitRole(t *testing.T) {
	fsys := goodSystem()
	fsys["lib/systemd/system/openscale-device.service"] = file("[Service]\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\nSystemCallFilter=@system-service\n")
	facts := goodFacts()
	facts.Listeners = []Listener{{Proto: "udp", Port: 41821}, {Proto: "tcp", Port: 22}}
	r := Run(fsys, facts, Options{Role: RoleExit})
	if statusOf(r, "unit") != Pass || statusOf(r, "ports") != Pass {
		t.Fatalf("exit role: %+v", r.Checks)
	}
}

func TestParseProcNet(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0
   1: 0100007F:0019 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0 100 0 0 10 0
   2: 0F02000A:0016 0202000A:C350 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0 100 0 0 10 0
`
	ls := parseProcNet(tcp, "tcp")
	if len(ls) != 1 || ls[0].Port != 22 || !ls[0].Addr.IsUnspecified() {
		t.Fatalf("tcp: %+v", ls)
	}
	udp6 := `  sl  local_address                         remote_address                        st
  0: 00000000000000000000000000000000:A2DC 00000000000000000000000000000000:0000 07 0
  1: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 07 0
`
	ls = parseProcNet(udp6, "udp")
	if len(ls) != 1 || ls[0].Port != 41692 {
		t.Fatalf("udp6: %+v", ls)
	}
	a, p, ok := parseHexAddr("0F02000A:0016")
	if !ok || a != netip.MustParseAddr("10.0.2.15") || p != 22 {
		t.Fatalf("hex addr: %v %d %v", a, p, ok)
	}
	// From a directory, the way the server reads it.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "proc", "net"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "proc", "net", "tcp"), []byte(tcp), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ReadListeners(os.DirFS(dir)); len(got) != 1 {
		t.Fatalf("ReadListeners: %+v", got)
	}
	if ReadListeners(os.DirFS(t.TempDir())) != nil {
		t.Fatal("no tables must give nil")
	}
}

// fakeCoordinator answers who-am-I on 127.0.0.1 and, when echo is set,
// every other packet too.
func fakeCoordinator(t *testing.T, echo bool) string {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			switch {
			case control.IsWhoAmI(buf[:n], control.WhoAmIRequest):
				_, _ = c.WriteToUDPAddrPort(control.WhoAmIAnswer(buf[:n], from), from)
			case echo:
				_, _ = c.WriteToUDPAddrPort(buf[:n], from)
			}
		}
	}()
	return c.LocalAddr().String()
}

func TestProbeSurface(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	open := uint16(ln.Addr().(*net.TCPAddr).Port)
	closedLn, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := uint16(closedLn.Addr().(*net.TCPAddr).Port)
	closedLn.Close()

	ctx := context.Background()
	res, err := Probe(ctx, SurfaceOptions{Endpoint: fakeCoordinator(t, false), TCPPorts: []uint16{open, closed}, Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if res.Checks[0].Status != Pass || res.Checks[1].Status != Pass || res.Checks[2].Status != Warn || len(res.Unexpected) != 1 || res.Unexpected[0] != open {
		t.Fatalf("probe: %+v", res)
	}
	res, _ = Probe(ctx, SurfaceOptions{Endpoint: fakeCoordinator(t, false), TCPPorts: []uint16{open}, AllowTCP: []uint16{open}, Timeout: 300 * time.Millisecond})
	if res.Score != 100 {
		t.Fatalf("allowed port: %+v", res)
	}
	// Something that echoes junk is not a silent WireGuard port.
	res, _ = Probe(ctx, SurfaceOptions{Endpoint: fakeCoordinator(t, true), TCPPorts: []uint16{}, Timeout: 300 * time.Millisecond})
	if res.Checks[1].Status != Fail {
		t.Fatalf("echo: %+v", res.Checks[1])
	}
	// Nothing listening: the port is reported closed.
	dead, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	addr := dead.LocalAddr().String()
	dead.Close()
	res, _ = Probe(ctx, SurfaceOptions{Endpoint: addr, TCPPorts: []uint16{}, Timeout: 200 * time.Millisecond})
	if res.Checks[0].Status != Fail {
		t.Fatalf("closed port: %+v", res.Checks[0])
	}
	if _, err := Probe(ctx, SurfaceOptions{Endpoint: "no-port"}); err == nil {
		t.Fatal("bad endpoint accepted")
	}
}

func FuzzParseProcNet(f *testing.F) {
	f.Add("sl local\n 0: 00000000:0016 00000000:0000 0A x\n", "tcp")
	f.Add("x\n 0: 00000000000000000000000000000000:A2DC 00000000000000000000000000000000:0000 07\n", "udp")
	f.Fuzz(func(t *testing.T, text, proto string) {
		for _, l := range parseProcNet(text, proto) {
			if l.Port == 0 || l.Addr.IsLoopback() {
				t.Fatalf("bad listener %+v", l)
			}
		}
	})
}

func FuzzSSHD(f *testing.F) {
	f.Add("PasswordAuthentication no\nInclude a/*.conf\nMatch all\n", "PermitRootLogin=no")
	f.Fuzz(func(t *testing.T, main, inc string) {
		fsys := fstest.MapFS{"etc/ssh/sshd_config": file(main), "etc/ssh/a/x.conf": file(inc), "etc/ssh/a/y.conf": file("Include /etc/ssh/a/*.conf\n")}
		c := readSSHD(fsys)
		if c == nil {
			t.Fatal("nil config")
		}
		_ = checkSSHPassword(c)
		_ = checkSSHRoot(c)
	})
}

func FuzzParseUnit(f *testing.F) {
	f.Add(hardenedUnit)
	f.Fuzz(func(t *testing.T, text string) {
		vals := map[string]string{}
		parseUnit(text, vals)
		for k, v := range vals {
			if v == "" {
				t.Fatalf("empty value for %q", k)
			}
		}
	})
}
