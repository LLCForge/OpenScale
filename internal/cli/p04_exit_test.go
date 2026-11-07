package cli

import (
	"bytes"
	"flag"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/trust"
)

func TestP04FlagDefaults(t *testing.T) {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	f := addUpP04Flags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	o, err := f.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if len(o.ports) != 1 || o.ports[0] != (osnet.ExitPort{Proto: "tcp", Port: 25}) || o.quota() || o.doh != nil || o.sources != nil {
		t.Fatalf("defaults: %+v", o)
	}
	fs = flag.NewFlagSet("up", flag.ContinueOnError)
	f = addUpP04Flags(fs)
	list := filepath.Join(t.TempDir(), "doh.txt")
	if err := os.WriteFile(list, []byte("1.1.1.1\n9.9.9.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse([]string{"--exit-block-ports", "none", "--exit-block-doh", list, "--exit-quota-member", "100GB", "--exit-quota-warn", "90"}); err != nil {
		t.Fatal(err)
	}
	if o, err = f.resolve(); err != nil {
		t.Fatal(err)
	}
	if o.ports != nil || len(o.doh) != 2 || o.quotaMember != 100<<30 || o.quotaWarn != 90 || !o.quota() {
		t.Fatalf("parsed: %+v", o)
	}
}

func TestParseQuotaSize(t *testing.T) {
	for in, want := range map[string]uint64{"": 0, "0": 0, "100GB": 100 << 30, "2tb": 2 << 40, "1.5G": 3 << 29, "1048576": 1 << 20} {
		got, err := parseQuotaSize(in)
		if err != nil || got != want {
			t.Errorf("%q: %d %v, want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"-1", "x", "10KB", "2000TB", "GB"} {
		if _, err := parseQuotaSize(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestParseExitSources(t *testing.T) {
	local := func() ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("203.0.113.6"), netip.MustParseAddr("2001:db8::5")}, nil
	}
	got, err := parseExitSources("203.0.113.5, laptop=203.0.113.6,2001:db8::5", local)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[1].member != "laptop" || got[0].member != "" {
		t.Fatalf("got %+v", got)
	}
	for _, bad := range []string{"198.51.100.1", "=203.0.113.5", "laptop=x", "fe80::1%eth0"} {
		if _, err := parseExitSources(bad, local); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestApplyExitNATResolvesNames(t *testing.T) {
	doc := &trust.Document{IPv4Prefix: netip.MustParsePrefix("100.80.0.0/16"), IPv6Prefix: netip.MustParsePrefix("fd7a:1:2::/48")}
	var d trust.Device
	d.Name, d.IPv4, d.IPv6 = "laptop", netip.MustParseAddr("100.80.0.7"), netip.MustParseAddr("fd7a:1:2::7")
	doc.Devices = []trust.Device{d}
	o := upP04Options{sources: []exitSourceSpec{
		{source: netip.MustParseAddr("203.0.113.5")},
		{member: "laptop", source: netip.MustParseAddr("203.0.113.6")},
		{member: "ghost", source: netip.MustParseAddr("203.0.113.6")},
	}, quotaTotal: 1 << 30}
	var stderr bytes.Buffer
	env := &Env{Stdout: io.Discard, Stderr: &stderr}
	c := osnet.ExitNAT{Interface: "OpenScale", IPv4: doc.IPv4Prefix, IPv6: doc.IPv6Prefix}
	o.applyExitNAT(env, &c, doc)
	if len(c.Sources) != 2 || c.Sources[1].Member != d.IPv4 || !c.Quota {
		t.Fatalf("exit NAT: %+v", c)
	}
	if !strings.Contains(stderr.String(), "ghost") {
		t.Fatalf("unknown name not reported: %q", stderr.String())
	}
}
