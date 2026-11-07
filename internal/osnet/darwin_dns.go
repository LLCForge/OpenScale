package osnet

// macOS MagicDNS and split DNS (ADR-0100, ADR-0016, ADR-0024). macOS reads
// per-domain resolvers from /etc/resolver/<domain> (resolver(5)); the
// system resolver (mDNSResponder) then sends names under that domain to
// the listed servers and everything else along its normal path. Every
// file OpenScale writes starts with darwinResolverMarker, and only such
// files are ever replaced or removed. Untagged so the tests run on every
// platform; dns_darwin.go wires it to the real system.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	darwinResolverDir = "/etc/resolver"
	// darwinResolverMarker is the first line of every resolver file
	// OpenScale owns.
	darwinResolverMarker  = "# OpenScale: managed while the tunnel runs (ADR-0100)"
	maxDarwinResolverFile = 4 << 10
)

// BackendResolverDir is the macOS DNS backend: per-domain files in
// /etc/resolver read by mDNSResponder.
const BackendResolverDir DNSBackend = "macos-resolver"

// darwinDNS holds the paths and tools the macOS DNS code uses; tests
// point dir at a temporary folder and run at a recorder.
type darwinDNS struct {
	dir string
	run darwinRunner
}

// darwinResolverFile returns the content of one resolver file.
func darwinResolverFile(servers []netip.Addr) []byte {
	var b strings.Builder
	b.WriteString(darwinResolverMarker + "\n")
	for _, s := range servers {
		b.WriteString("nameserver " + s.String() + "\n")
	}
	return []byte(b.String())
}

// darwinResolverPlan is every OpenScale resolver file for the MagicDNS
// domain and the split domains, by domain.
func darwinResolverPlan(magic DNSConfig, n NetworkDNS) map[string][]byte {
	plan := map[string][]byte{magic.Domain: darwinResolverFile([]netip.Addr{magic.Server})}
	for _, s := range n.Split {
		plan[s.Domain] = darwinResolverFile(s.Nameservers)
	}
	return plan
}

// owned reports whether the resolver file of domain was written by
// OpenScale. A missing file is not owned.
func (d darwinDNS) owned(domain string) (bool, error) {
	f, err := os.Open(filepath.Join(d.dir, domain))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	line, _ := bufio.NewReader(io.LimitReader(f, maxDarwinResolverFile)).ReadString('\n')
	return strings.TrimRight(line, "\r\n") == darwinResolverMarker, nil
}

// ownedDomains lists the domains whose resolver file OpenScale wrote.
func (d darwinDNS) ownedDomains() ([]string, error) {
	entries, err := os.ReadDir(d.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.Type().IsRegular() || !validDomain(e.Name()) {
			continue
		}
		if ok, err := d.owned(e.Name()); err == nil && ok {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// write replaces the resolver file of domain atomically. The file must be
// world-readable: mDNSResponder does not run as root. A file of the same
// name that OpenScale did not write is never touched.
func (d darwinDNS) write(domain string, data []byte) error {
	if !validDomain(domain) {
		return fmt.Errorf("geçersiz DNS alanı %q", domain)
	}
	p := filepath.Join(d.dir, domain)
	if _, err := os.Lstat(p); err == nil {
		ok, err := d.owned(domain)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%s OpenScale'e ait değil; dokunulmadı", p)
		}
	}
	if err := os.MkdirAll(d.dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(d.dir, ".openscale-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, p); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// remove deletes the resolver file of domain if OpenScale wrote it.
func (d darwinDNS) remove(domain string) error {
	ok, err := d.owned(domain)
	if err != nil || !ok {
		return err
	}
	if err := os.Remove(filepath.Join(d.dir, domain)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// flush makes mDNSResponder forget cached answers and re-read
// /etc/resolver. Best effort: the files work without it after a moment.
func (d darwinDNS) flush(ctx context.Context) {
	if d.run == nil {
		return
	}
	_, _ = d.run(ctx, nil, darwinDscacheutil, "-flushcache")
	_, _ = d.run(ctx, nil, darwinKillall, "-HUP", "mDNSResponder")
}

// apply writes the planned files and removes OpenScale files of domains
// no longer planned (a split domain taken out of the document).
func (d darwinDNS) apply(ctx context.Context, plan map[string][]byte) error {
	var errs []error
	have, err := d.ownedDomains()
	if err != nil {
		return err
	}
	for _, domain := range have {
		if _, keep := plan[domain]; !keep {
			errs = append(errs, d.remove(domain))
		}
	}
	domains := make([]string, 0, len(plan))
	for domain := range plan {
		domains = append(domains, domain)
	}
	slices.Sort(domains)
	for _, domain := range domains {
		errs = append(errs, d.write(domain, plan[domain]))
	}
	d.flush(ctx)
	return errors.Join(errs...)
}

// configure sends the MagicDNS domain to the resolver.
func (d darwinDNS) configure(ctx context.Context, magic DNSConfig) error {
	return d.apply(ctx, darwinResolverPlan(magic, NetworkDNS{}))
}

// configureNetwork applies MagicDNS and the split domains. Network-wide
// resolvers have no per-domain form on macOS: the default resolver is
// per network service (networksetup), which only the exit node takes
// over. They are reported as unsupported after the split domains are in
// place; MagicDNS keeps working either way.
func (d darwinDNS) configureNetwork(ctx context.Context, magic DNSConfig, n NetworkDNS) error {
	if err := d.apply(ctx, darwinResolverPlan(magic, n)); err != nil {
		return err
	}
	if len(n.Nameservers) > 0 && !n.ExitActive {
		return fmt.Errorf("%w: macOS'ta ağ geneli çözücü yalnızca çıkış düğümüyle uygulanır", ErrNetworkDNSUnsupported)
	}
	return nil
}

// removeAll removes every OpenScale resolver file.
func (d darwinDNS) removeAll(ctx context.Context) error {
	have, err := d.ownedDomains()
	if err != nil {
		return err
	}
	var errs []error
	for _, domain := range have {
		errs = append(errs, d.remove(domain))
	}
	d.flush(ctx)
	return errors.Join(errs...)
}

// verify reports ErrDNSOverwritten when a planned file is missing or was
// changed.
func (d darwinDNS) verify(magic DNSConfig, n NetworkDNS) error {
	for domain, want := range darwinResolverPlan(magic, n) {
		got, err := os.ReadFile(filepath.Join(d.dir, domain))
		if err != nil || !bytes.Equal(got, want) {
			return ErrDNSOverwritten
		}
	}
	return nil
}
