//go:build linux

package osnet

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// fakeDNSHost is an in-memory system for the Linux DNS backends: files,
// symlinks, installed programs and a resolvectl that remembers the link.
type fakeDNSHost struct {
	files    map[string][]byte
	links    map[string]string
	programs map[string]bool
	cmds     [][]string
	stdin    map[string][]byte
	servers  []string
	domains  []string
}

func newFakeDNSHost(t *testing.T, programs ...string) *fakeDNSHost {
	t.Helper()
	h := &fakeDNSHost{files: map[string][]byte{}, links: map[string]string{}, programs: map[string]bool{}, stdin: map[string][]byte{}}
	for _, p := range programs {
		h.programs[p] = true
	}
	prev := linuxDNS
	linuxDNS = &linuxDNSState{backends: map[string]DNSBackend{}, sys: dnsSys{
		run: func(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
			h.cmds = append(h.cmds, append([]string{name}, args...))
			if stdin != nil {
				h.stdin[name] = stdin
			}
			if name == "resolvectl" && len(args) >= 2 {
				switch {
				case args[0] == "dns" && len(args) == 2:
					return []byte("Link 7 (" + args[1] + "): " + strings.Join(h.servers, " ") + "\n"), nil
				case args[0] == "domain" && len(args) == 2:
					return []byte("Link 7 (" + args[1] + "): " + strings.Join(h.domains, " ") + "\n"), nil
				case args[0] == "dns":
					h.servers = slices.Clone(args[2:])
				case args[0] == "domain":
					h.domains = slices.Clone(args[2:])
				}
			}
			return nil, nil
		},
		read: func(path string) ([]byte, error) {
			if target, ok := h.links[path]; ok {
				path = target
			}
			if b, ok := h.files[path]; ok {
				return slices.Clone(b), nil
			}
			return nil, fs.ErrNotExist
		},
		readlink: func(path string) (string, error) {
			if l, ok := h.links[path]; ok {
				return l, nil
			}
			return "", errors.New("not a link")
		},
		write: func(path string, data []byte) error {
			delete(h.links, path)
			h.files[path] = slices.Clone(data)
			return nil
		},
		symlink: func(target, path string) error {
			delete(h.files, path)
			h.links[path] = target
			return nil
		},
		remove: func(path string) error { delete(h.files, path); delete(h.links, path); return nil },
		lookPath: func(file string) (string, error) {
			if h.programs[file] {
				return "/usr/bin/" + file, nil
			}
			return "", errors.New("not found")
		},
	}}
	t.Cleanup(func() { linuxDNS = prev })
	return h
}

var testSplit = NetworkDNS{
	Split:   []SplitDomain{{Domain: "ev.lan", Nameservers: []netip.Addr{netip.MustParseAddr("100.80.0.5")}}},
	Search:  []string{"openscale.internal"},
	Overlay: testOverlay,
}

// With systemd-resolved the link keeps MagicDNS as its only server, so
// MagicDNS names can never fail over to another resolver; split domains
// are routed to the link and forwarded by MagicDNS (ADR-0034).
func TestLinuxResolvedBackend(t *testing.T) {
	h := newFakeDNSHost(t, "resolvectl")
	h.links[resolvConfPath] = "/run/systemd/resolve/stub-resolv.conf"
	h.files["/run/systemd/resolve/stub-resolv.conf"] = []byte("nameserver 127.0.0.53\n")
	ctx := context.Background()
	if err := ConfigureDNS(ctx, testMagic); err != nil {
		t.Fatal(err)
	}
	if err := ConfigureNetworkDNS(ctx, testMagic, testSplit); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h.servers, []string{"100.80.255.254"}) {
		t.Fatalf("link servers %v", h.servers)
	}
	if !slices.Contains(h.domains, "~ev.lan") || !slices.Contains(h.domains, "openscale.internal") || slices.Contains(h.domains, "~.") {
		t.Fatalf("link domains %v", h.domains)
	}
	if err := VerifyNetworkDNS(ctx, testMagic, testSplit); err != nil {
		t.Fatalf("verify intact: %v", err)
	}
	// NetworkManager resets the link: noticed.
	h.domains = []string{"~openscale.internal"}
	if err := VerifyNetworkDNS(ctx, testMagic, testSplit); !errors.Is(err, ErrDNSOverwritten) {
		t.Fatalf("verify changed: %v", err)
	}
	if SystemDNSStatus(testMagic.Interface).Backend != BackendResolved {
		t.Fatal("backend not reported")
	}
	if err := RemoveDNS(ctx, testMagic); err != nil {
		t.Fatal(err)
	}
	if last := h.cmds[len(h.cmds)-1]; !slices.Equal(last, []string{"resolvectl", "revert", "OpenScale"}) {
		t.Fatalf("last command %v", last)
	}
	if _, ok := h.files[resolvConfPath]; ok {
		t.Fatal("resolv.conf written with systemd-resolved")
	}
}

func TestLinuxFileBackend(t *testing.T) {
	h := newFakeDNSHost(t)
	orig := []byte("nameserver 192.168.1.1\nsearch home.arpa\n")
	h.files[resolvConfPath] = orig
	ctx := context.Background()
	if err := ConfigureDNS(ctx, testMagic); err != nil {
		t.Fatal(err)
	}
	if string(h.files[resolvConfBackup]) != string(orig) {
		t.Fatal("original not saved")
	}
	if err := ConfigureNetworkDNS(ctx, testMagic, testSplit); err != nil {
		t.Fatal(err)
	}
	rc := parseResolvConfFile(h.files[resolvConfPath])
	if !rc.managed || rc.nameservers[0] != testMagic.Server || rc.nameservers[1] != netip.MustParseAddr("192.168.1.1") || rc.search[0] != "openscale.internal" {
		t.Fatalf("managed file %s", h.files[resolvConfPath])
	}
	// The backup still holds the original, not OpenScale's file.
	if string(h.files[resolvConfBackup]) != string(orig) {
		t.Fatal("backup overwritten by the managed file")
	}
	if err := VerifyNetworkDNS(ctx, testMagic, testSplit); err != nil {
		t.Fatal(err)
	}
	h.files[resolvConfPath] = []byte("# Generated by NetworkManager\nnameserver 192.168.1.1\n")
	if err := VerifyNetworkDNS(ctx, testMagic, testSplit); !errors.Is(err, ErrDNSOverwritten) {
		t.Fatalf("overwrite not noticed: %v", err)
	}
	// Repair, then restore at the end.
	if err := ConfigureNetworkDNS(ctx, testMagic, testSplit); err != nil {
		t.Fatal(err)
	}
	if err := RemoveDNS(ctx, testMagic); err != nil {
		t.Fatal(err)
	}
	if got := string(h.files[resolvConfPath]); !strings.Contains(got, "NetworkManager") {
		t.Fatalf("restored %q", got)
	}
	if _, ok := h.files[resolvConfBackup]; ok {
		t.Fatal("backup left behind")
	}
}

func TestLinuxFileBackendRestoresSymlink(t *testing.T) {
	h := newFakeDNSHost(t)
	h.links[resolvConfPath] = "/run/NetworkManager/resolv.conf"
	h.files["/run/NetworkManager/resolv.conf"] = []byte("# Generated by NetworkManager\nnameserver 10.0.0.1\n")
	ctx := context.Background()
	if err := ConfigureDNS(ctx, testMagic); err != nil {
		t.Fatal(err)
	}
	if linuxDNS.backendFor(testMagic.Interface) != BackendNetworkManager {
		t.Fatal("NetworkManager file not detected")
	}
	if _, ok := h.links[resolvConfPath]; ok {
		t.Fatal("symlink kept: its target would have been changed")
	}
	// After a crash the managed file is recognised and the saved original
	// decides the backend.
	linuxDNS.backends = map[string]DNSBackend{}
	if linuxDNS.backendFor(testMagic.Interface) != BackendNetworkManager {
		t.Fatal("backend after restart")
	}
	if err := RemoveDNS(ctx, testMagic); err != nil {
		t.Fatal(err)
	}
	if h.links[resolvConfPath] != "/run/NetworkManager/resolv.conf" {
		t.Fatalf("symlink not restored: %v", h.links)
	}
}

func TestLinuxResolvconfBackend(t *testing.T) {
	h := newFakeDNSHost(t, "resolvconf")
	h.links[resolvConfPath] = "/run/resolvconf/resolv.conf"
	h.files["/run/resolvconf/resolv.conf"] = []byte("nameserver 10.0.0.1\n")
	ctx := context.Background()
	if err := ConfigureNetworkDNS(ctx, testMagic, testSplit); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(h.stdin["resolvconf"]), "nameserver 100.80.255.254") {
		t.Fatalf("record %q", h.stdin["resolvconf"])
	}
	if err := VerifyNetworkDNS(ctx, testMagic, testSplit); !errors.Is(err, ErrDNSOverwritten) {
		t.Fatalf("missing server: %v", err)
	}
	h.files["/run/resolvconf/resolv.conf"] = []byte("nameserver 127.0.0.1\nnameserver 100.80.255.254\n")
	if err := VerifyNetworkDNS(ctx, testMagic, testSplit); err == nil || errors.Is(err, ErrDNSOverwritten) {
		t.Fatalf("second place: %v", err)
	}
}
