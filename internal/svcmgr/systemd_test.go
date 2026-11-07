package svcmgr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeSystem struct {
	root  string
	cmds  []string
	euid  int
	owned map[string][2]int
}

func newFakeSystem(t *testing.T) (*fakeSystem, sysOps) {
	t.Helper()
	f := &fakeSystem{root: t.TempDir(), owned: map[string][2]int{}}
	exe := filepath.Join(t.TempDir(), "openscale")
	if err := os.WriteFile(exe, []byte("program"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := sysOps{
		root: f.root,
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			f.cmds = append(f.cmds, name+" "+strings.Join(args, " "))
			return nil, nil
		},
		executable: func() (string, error) { return exe, nil },
		euid:       func() int { return f.euid },
		ensureUser: func(context.Context) (int, int, error) { return 990, 990, nil },
		chown: func(p string, uid, gid int) error {
			f.owned[p] = [2]int{uid, gid}
			return nil
		},
		trusted: func(string) error { return nil },
	}
	return f, s
}

func (f *fakeSystem) read(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.root, filepath.FromSlash(p)))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestInstallDeviceNotJoined(t *testing.T) {
	f, s := newFakeSystem(t)
	if err := os.MkdirAll(filepath.Join(f.root, "usr", "lib", "systemd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.root, "usr", "lib", "systemd", "systemd-networkd"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.root, "etc", "NetworkManager"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := installLinux(context.Background(), s, Options{Role: RoleDevice, ListenPort: 41641, Interface: "os0"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Started || res.Binary != localBinary {
		t.Fatalf("result = %+v", res)
	}
	if got := f.read(t, localBinary); got != "program" {
		t.Fatalf("binary not copied: %q", got)
	}
	unit := f.read(t, etcUnitDir+"/openscale-device.service")
	if !strings.HasPrefix(unit, installMarker+"\n") || !strings.Contains(unit, "Type=notify") {
		t.Fatalf("unit:\n%s", unit)
	}
	drop := f.read(t, unitDropIn("openscale-device.service"))
	if !strings.Contains(drop, "ExecStart=\nExecStart=/usr/local/bin/openscale up --config /etc/openscale/device.json\n") ||
		!strings.Contains(drop, "ReadWritePaths="+DefaultDeviceStateDir) {
		t.Fatalf("drop-in:\n%s", drop)
	}
	var params map[string]any
	if err := json.Unmarshal([]byte(f.read(t, "/etc/openscale/device.json")), &params); err != nil {
		t.Fatal(err)
	}
	if params["listen-port"] != float64(41641) || params["interface"] != "os0" || params["state-dir"] != DefaultDeviceStateDir {
		t.Fatalf("params = %v", params)
	}
	if nw := f.read(t, networkdNetDir+"/50-openscale.network"); !strings.Contains(nw, "Name=os0") || !strings.Contains(nw, "Unmanaged=yes") {
		t.Fatalf("networkd file:\n%s", nw)
	}
	if nm := f.read(t, nmConfDir+"/50-openscale.conf"); !strings.Contains(nm, "interface-name:os0") {
		t.Fatalf("NetworkManager file:\n%s", nm)
	}
	if !strings.Contains(f.read(t, unitDropIn(waitOnlineUnit)), "wait --state-dir "+DefaultDeviceStateDir) {
		t.Fatal("wait-online drop-in missing")
	}
	// Unjoined: daemon-reload only, never enabled or started.
	if len(f.cmds) != 1 || f.cmds[0] != "systemctl daemon-reload" {
		t.Fatalf("commands = %q", f.cmds)
	}
	if len(res.Notes) == 0 || !strings.Contains(strings.Join(res.Notes, "\n"), "katılmamış") {
		t.Fatalf("notes = %q", res.Notes)
	}
}

func TestInstallKeepsPackageUnitAndBinary(t *testing.T) {
	f, s := newFakeSystem(t)
	for _, p := range []string{packageBinary, pkgUnitDir + "/openscale-coordinator.service"} {
		full := filepath.Join(f.root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("package"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := installLinux(context.Background(), s, Options{Role: RoleCoordinator, TCPListen: ":443"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Binary != packageBinary {
		t.Fatalf("binary = %s", res.Binary)
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc", "systemd", "system", "openscale-coordinator.service")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a unit was written over the package's unit")
	}
	drop := f.read(t, unitDropIn("openscale-coordinator.service"))
	if !strings.Contains(drop, "ExecStart=/usr/bin/openscale coordinator run --config /etc/openscale/coordinator.json") ||
		!strings.Contains(drop, "AmbientCapabilities=CAP_NET_BIND_SERVICE") {
		t.Fatalf("drop-in:\n%s", drop)
	}
	if !strings.Contains(f.read(t, "/etc/openscale/coordinator.json"), `"tcp-listen": ":443"`) {
		t.Fatal("tcp-listen not saved")
	}
	dir := filepath.Join(f.root, filepath.FromSlash(DefaultCoordinatorStateDir))
	if f.owned[dir] != [2]int{990, 990} {
		t.Fatalf("state dir not given to the service user: %v", f.owned)
	}
}

func TestInstallNeedsRootAndValidOptions(t *testing.T) {
	f, s := newFakeSystem(t)
	f.euid = 1000
	if _, err := installLinux(context.Background(), s, Options{}); !errors.Is(err, ErrNeedsRoot) {
		t.Fatalf("non-root install: %v", err)
	}
	f.euid = 0
	for _, o := range []Options{
		{StateDir: "relative/dir"},
		{StateDir: "/var/lib/a b"},
		{Interface: "this-name-is-too-long"},
		{ListenPort: 70000},
		{Role: RoleDevice, TCPListen: ":443"},
		{Role: RoleCoordinator, Interface: "x"},
	} {
		if _, err := installLinux(context.Background(), s, o); err == nil {
			t.Errorf("options %+v accepted", o)
		}
	}
}

func TestUninstallRemovesOnlyOwnFiles(t *testing.T) {
	f, s := newFakeSystem(t)
	if _, err := installLinux(context.Background(), s, Options{}); err != nil {
		t.Fatal(err)
	}
	// A file the administrator wrote by hand stays.
	foreign := filepath.Join(f.root, "etc", "systemd", "system", "60-mine.conf")
	if err := os.WriteFile(foreign, []byte("[Match]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.cmds = nil
	if _, err := uninstallLinux(context.Background(), s, RoleDevice); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{etcUnitDir + "/openscale-device.service", unitDropIn("openscale-device.service")} {
		if _, err := os.Stat(filepath.Join(f.root, filepath.FromSlash(p))); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s not removed", p)
		}
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Error("foreign file removed")
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc", "openscale", "device.json")); err != nil {
		t.Error("parameters removed")
	}
	if !strings.Contains(strings.Join(f.cmds, "\n"), "systemctl disable --now openscale-device.service") {
		t.Fatalf("commands = %q", f.cmds)
	}
}

func TestStatusParsesSystemctlShow(t *testing.T) {
	_, s := newFakeSystem(t)
	s.run = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nMainPID=4242\nStatusText=Bağlı: OpenScale\nFragmentPath=/etc/systemd/system/openscale-device.service\n"), nil
	}
	st, err := statusLinux(context.Background(), s, RoleDevice)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Installed || !st.Running || !st.Enabled || st.PID != 4242 || st.Detail != "Bağlı: OpenScale" || st.State != "active (running)" {
		t.Fatalf("status = %+v", st)
	}
	s.run = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("LoadState=not-found\nActiveState=inactive\n"), nil
	}
	if st, _ := statusLinux(context.Background(), s, RoleDevice); st.Installed || st.State != "kurulu değil" {
		t.Fatalf("missing unit = %+v", st)
	}
}

// The embedded units must match deploy/linux, which the packages and the
// manual install scripts use.
func TestEmbeddedUnitsMatchDeploy(t *testing.T) {
	entries, err := unitFiles.ReadDir("units")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		embedded, _ := unitFiles.ReadFile("units/" + e.Name())
		deployed, err := os.ReadFile(filepath.Join("..", "..", "deploy", "linux", e.Name()))
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		norm := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }
		if !bytes.Equal(norm(embedded), norm(deployed)) {
			t.Errorf("internal/svcmgr/units/%s differs from deploy/linux/%s; copy it over", e.Name(), e.Name())
		}
	}
}

func TestParseRole(t *testing.T) {
	if r, err := ParseRole(""); err != nil || r != RoleDevice {
		t.Fatal("default role")
	}
	if r, err := ParseRole("coordinator"); err != nil || r.Unit() != "openscale-coordinator.service" {
		t.Fatal("coordinator role")
	}
	if _, err := ParseRole("exit"); err == nil {
		t.Fatal("bad role accepted")
	}
}
