//go:build linux

package osnet

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
)

// Linux DNS (ADR-0016, ADR-0024, ADR-0034, F-060, F-061). The manager in
// use is detected once per tunnel:
//
//   - systemd-resolved: the tunnel link gets MagicDNS as its only server
//     and the network's routing domains; split domains and, with
//     network-wide resolvers or an exit node, "~." are routed there too and
//     MagicDNS forwards them through the tunnel. MagicDNS names never reach
//     another server.
//   - resolvconf / openresolv: an interface record that puts MagicDNS
//     first.
//   - NetworkManager's own file and a plain /etc/resolv.conf: the file is
//     backed up and rewritten with MagicDNS first, and restored at the end.
//
// Without resolved, MagicDNS answers its own names and refuses the rest,
// so the C library asks the next server; split domains and network-wide
// resolvers are forwarded by MagicDNS.

// dnsSys is how the DNS backends touch the system; tests replace it with
// a fake, so no test changes the host.
type dnsSys struct {
	run      func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)
	read     func(path string) ([]byte, error)
	readlink func(path string) (string, error)
	// write replaces path atomically (temporary file and rename), which
	// also replaces a symlink rather than its target.
	write    func(path string, data []byte) error
	symlink  func(target, path string) error
	remove   func(path string) error
	lookPath func(file string) (string, error)
}

var hostDNSSys = dnsSys{
	run: runCommand, read: os.ReadFile, readlink: os.Readlink, write: atomicWrite,
	symlink: replaceWithSymlink, remove: os.Remove, lookPath: exec.LookPath,
}

func atomicWrite(path string, data []byte) error {
	tmp := path + ".openscale-tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil { //nolint:gosec // resolv.conf is world-readable by design
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func replaceWithSymlink(target, path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.Symlink(target, path)
}

// linuxDNSState remembers the backend chosen for each tunnel interface.
type linuxDNSState struct {
	mu       sync.Mutex
	sys      dnsSys
	backends map[string]DNSBackend
}

var linuxDNS = &linuxDNSState{sys: hostDNSSys, backends: map[string]DNSBackend{}}

func (s *linuxDNSState) has(program string) bool {
	_, err := s.sys.lookPath(program)
	return err == nil
}

// env reads what detection needs. After a crash /etc/resolv.conf may
// still be OpenScale's own file; the saved original is examined instead.
func (s *linuxDNSState) env() dnsEnv {
	env := dnsEnv{hasResolvectl: s.has("resolvectl"), hasResolvconf: s.has("resolvconf")}
	env.resolvConf, _ = s.sys.read(resolvConfPath)
	env.resolvConfLink, _ = s.sys.readlink(resolvConfPath)
	if parseResolvConfFile(env.resolvConf).managed {
		env.resolvConf, _ = s.sys.read(resolvConfBackup)
		link, _ := s.sys.read(resolvConfLinkBackup)
		env.resolvConfLink = strings.TrimSpace(string(link))
	}
	env.nsswitch, _ = s.sys.read("/etc/nsswitch.conf")
	return env
}

// backendFor returns the backend used for iface, detecting it if needed.
func (s *linuxDNSState) backendFor(iface string) DNSBackend {
	s.mu.Lock()
	b, ok := s.backends[iface]
	s.mu.Unlock()
	if ok {
		return b
	}
	return detectBackend(s.env())
}

func (s *linuxDNSState) openresolv(ctx context.Context) bool {
	out, _ := s.sys.run(ctx, nil, "resolvconf", "--version")
	return strings.Contains(strings.ToLower(string(out)), "openresolv")
}

// configureDNS detects the DNS manager and puts MagicDNS in place for the
// network domain.
func configureDNS(ctx context.Context, c DNSConfig) error {
	b := detectBackend(linuxDNS.env())
	linuxDNS.mu.Lock()
	linuxDNS.backends[c.Interface] = b
	linuxDNS.mu.Unlock()
	if b == BackendResolved {
		// The routing domains of the network come with ConfigureReverseDNS
		// and ConfigureNetworkDNS; until then only the network domain.
		return linuxDNS.applyResolved(ctx, c, linkState{servers: []string{c.Server.String()}, domains: []string{"~" + c.Domain}})
	}
	return linuxDNS.apply(ctx, c, NetworkDNS{})
}

// configureNetworkDNS applies MagicDNS with the network's DNS settings,
// replacing what OpenScale applied before.
func configureNetworkDNS(ctx context.Context, magic DNSConfig, n NetworkDNS) error {
	return linuxDNS.apply(ctx, magic, n)
}

func (s *linuxDNSState) apply(ctx context.Context, magic DNSConfig, n NetworkDNS) error {
	switch b := s.backendFor(magic.Interface); b {
	case BackendResolved:
		return s.applyResolved(ctx, magic, resolvedLinkPlan(magic, n))
	case BackendResolvconf:
		args := []string{"-a", resolvconfRecord}
		if s.openresolv(ctx) {
			args = []string{"-m", "0", "-a", resolvconfRecord}
		}
		_, err := s.sys.run(ctx, resolvconfRecordData(magic.Server, n.Search), "resolvconf", args...)
		return err
	default:
		return s.writeResolvConf(magic.Server, n.Search)
	}
}

// applyResolved sets the link's servers and domains. DNSSEC and DNS over
// TLS are turned off for this link only: MagicDNS answers unsigned
// private names on port 53.
func (s *linuxDNSState) applyResolved(ctx context.Context, magic DNSConfig, plan linkState) error {
	if !s.has("resolvectl") {
		return errors.New("systemd-resolved (resolvectl) bulunamadı; MagicDNS adları bu sistemde çözülmeyecek")
	}
	if _, err := s.sys.run(ctx, nil, "resolvectl", append([]string{"dns", magic.Interface}, plan.servers...)...); err != nil {
		return err
	}
	if _, err := s.sys.run(ctx, nil, "resolvectl", append([]string{"domain", magic.Interface}, plan.domains...)...); err != nil {
		return err
	}
	// Older resolved versions lack these; the defaults then apply.
	_, _ = s.sys.run(ctx, nil, "resolvectl", "dnssec", magic.Interface, "no")
	_, _ = s.sys.run(ctx, nil, "resolvectl", "dnsovertls", magic.Interface, "no")
	_, _ = s.sys.run(ctx, nil, "resolvectl", "flush-caches")
	return nil
}

// writeResolvConf saves the original resolv.conf (once) and writes the
// managed one.
func (s *linuxDNSState) writeResolvConf(server netip.Addr, search []string) error {
	cur, err := s.sys.read(resolvConfPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	orig := cur
	if parseResolvConfFile(cur).managed {
		if saved, err := s.sys.read(resolvConfBackup); err == nil {
			orig = saved
		}
	} else {
		if err := s.sys.write(resolvConfBackup, cur); err != nil {
			return fmt.Errorf("resolv.conf yedeklenemedi: %w", err)
		}
		if link, err := s.sys.readlink(resolvConfPath); err == nil && link != "" {
			if err := s.sys.write(resolvConfLinkBackup, []byte(link+"\n")); err != nil {
				return fmt.Errorf("resolv.conf bağlantısı yedeklenemedi: %w", err)
			}
		} else {
			_ = s.sys.remove(resolvConfLinkBackup)
		}
	}
	return s.sys.write(resolvConfPath, managedResolvConf(orig, server, search))
}

// restoreResolvConf puts the original back. A file another program wrote
// in the meantime is left alone.
func (s *linuxDNSState) restoreResolvConf() error {
	cur, _ := s.sys.read(resolvConfPath)
	defer func() {
		_ = s.sys.remove(resolvConfBackup)
		_ = s.sys.remove(resolvConfLinkBackup)
	}()
	if !parseResolvConfFile(cur).managed {
		return nil
	}
	if link, err := s.sys.read(resolvConfLinkBackup); err == nil && strings.TrimSpace(string(link)) != "" {
		return s.sys.symlink(strings.TrimSpace(string(link)), resolvConfPath)
	}
	orig, err := s.sys.read(resolvConfBackup)
	if err != nil {
		return fmt.Errorf("resolv.conf yedeği okunamadı: %w", err)
	}
	return s.sys.write(resolvConfPath, orig)
}

func removeDNS(ctx context.Context, c DNSConfig) error {
	s := linuxDNS
	b := s.backendFor(c.Interface)
	s.mu.Lock()
	delete(s.backends, c.Interface)
	s.mu.Unlock()
	switch b {
	case BackendResolved:
		if !s.has("resolvectl") {
			return nil
		}
		_, err := s.sys.run(ctx, nil, "resolvectl", "revert", c.Interface)
		return err
	case BackendResolvconf:
		_, err := s.sys.run(ctx, nil, "resolvconf", "-d", resolvconfRecord)
		return err
	default:
		return s.restoreResolvConf()
	}
}

// verifyNetworkDNS compares the system with what apply wrote (F-061).
func verifyNetworkDNS(ctx context.Context, magic DNSConfig, n NetworkDNS) error {
	s := linuxDNS
	switch s.backendFor(magic.Interface) {
	case BackendResolved:
		dnsOut, err1 := s.sys.run(ctx, nil, "resolvectl", "dns", magic.Interface)
		domOut, err2 := s.sys.run(ctx, nil, "resolvectl", "domain", magic.Interface)
		if err1 != nil || err2 != nil {
			return nil // cannot tell; the link may be going away
		}
		want := resolvedLinkPlan(magic, n)
		if !sameSet(parseResolvectlList(dnsOut), want.servers) || !sameSet(parseResolvectlList(domOut), want.domains) {
			return ErrDNSOverwritten
		}
		return nil
	case BackendResolvconf:
		cur, err := s.sys.read(resolvConfPath)
		if err != nil {
			return nil
		}
		rc := parseResolvConfFile(cur)
		switch {
		case !slices.Contains(rc.nameservers, magic.Server):
			return ErrDNSOverwritten
		case rc.nameservers[0] != magic.Server:
			return errors.New("resolvconf MagicDNS çözücüsünü ilk sıraya koymadı; cihaz adları başka bir çözücüye gidebilir")
		}
		return nil
	default:
		cur, err := s.sys.read(resolvConfPath)
		if err != nil {
			return ErrDNSOverwritten
		}
		rc := parseResolvConfFile(cur)
		if !rc.managed || len(rc.nameservers) == 0 || rc.nameservers[0] != magic.Server {
			return ErrDNSOverwritten
		}
		for _, d := range n.Search {
			if !slices.Contains(rc.search, d) {
				return ErrDNSOverwritten
			}
		}
		return nil
	}
}

func systemDNSStatus(iface string) DNSSystemStatus {
	return DNSSystemStatus{Backend: linuxDNS.backendFor(iface)}
}
