package netprofile

import (
	"crypto/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/trust"
)

func joinWith(t *testing.T, dir, domain string, v4 netip.Prefix) {
	t.Helper()
	opts := admin.Options{Argon2: trust.Argon2Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 1}, Random: rand.Reader}
	n, err := admin.Init(t.TempDir(), admin.InitOptions{DNSDomain: domain, IPv4Prefix: v4, Validity: trust.DefaultValidity}, []byte("doğru at pil zımba 9"), opts, testNow)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := n.JoinBundle()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Join(dir, bundle, n.RootFingerprint(), testNow); err != nil {
		t.Fatal(err)
	}
}

func TestCheckConcurrent(t *testing.T) {
	base := t.TempDir()
	for _, p := range []struct{ name, domain, v4 string }{
		{"default", "ev.internal", "100.80.0.0/16"},
		{"aile", "aile.internal", "100.81.0.0/16"},
		{"is", "ev.internal", "100.80.128.0/17"},
	} {
		dir, err := Resolve(base, p.name, true)
		if err != nil {
			t.Fatal(err)
		}
		joinWith(t, dir, p.domain, netip.MustParsePrefix(p.v4))
	}
	plan, err := CheckConcurrent(base, []string{"default", "aile"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range plan.Conflicts {
		if strings.Contains(c, "IPv4") || strings.Contains(c, "DNS") {
			t.Fatalf("unexpected conflict: %s", c)
		}
	}
	if len(plan.Profiles) != 2 || plan.Profiles[0].Interface != PrimaryInterface || !plan.Profiles[0].Primary ||
		plan.Profiles[1].Interface != "os-aile" || plan.Profiles[1].Primary {
		t.Fatalf("plan %+v", plan.Profiles)
	}
	plan, err = CheckConcurrent(base, []string{"default", "is"})
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(plan.Conflicts, "\n")
	if plan.OK() || !strings.Contains(text, "IPv4") || !strings.Contains(text, "DNS") {
		t.Fatalf("overlap not found: %v", plan.Conflicts)
	}
	for _, bad := range [][]string{{"default"}, {"default", "default"}, {"default", "yok"}, {"a", "b", "c", "d", "e"}} {
		if _, err := CheckConcurrent(base, bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestConcurrentHelpers(t *testing.T) {
	if got := ConcurrentInterface("cok-uzun-bir-profil-adi"); len(got) > 15 || !strings.HasPrefix(got, "os-") || strings.HasSuffix(got, "-") {
		t.Fatalf("interface %q", got)
	}
	for _, c := range []struct {
		a, b string
		want bool
	}{{"a.internal", "a.internal", true}, {"x.a.internal", "a.internal", true}, {"a.internal", "b.internal", false}, {"", "a", false}} {
		if domainsOverlap(c.a, c.b) != c.want {
			t.Errorf("%q %q", c.a, c.b)
		}
	}
}
