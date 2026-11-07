package errcode

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/trust"
)

// issued is every code ever published. A code may be added here, never
// removed or renumbered (ADR-0165). This list is the stability promise.
var issued = []string{
	"OS-1001", "OS-1002", "OS-1003", "OS-1004", "OS-1005", "OS-1006", "OS-1007", "OS-1008", "OS-1009", "OS-1010", "OS-1011", "OS-1012",
	"OS-2001", "OS-2002", "OS-2003", "OS-2004", "OS-2005", "OS-2006", "OS-2007", "OS-2008",
	"OS-3001", "OS-3002", "OS-3003", "OS-3004", "OS-3005", "OS-3006",
	"OS-4001", "OS-4002", "OS-4003", "OS-4004",
	"OS-5001", "OS-5002", "OS-5003", "OS-5004", "OS-5005", "OS-5006",
	"OS-6001", "OS-6002", "OS-6003", "OS-6004", "OS-6005",
	"OS-7001", "OS-7002", "OS-7003",
}

func TestIssuedCodesStayInCatalog(t *testing.T) {
	for _, c := range issued {
		if _, ok := Lookup(c); !ok {
			t.Errorf("issued code %s missing from the catalog; codes are never removed", c)
		}
	}
	if len(All()) < len(issued) {
		t.Fatalf("catalog shrank: %d < %d", len(All()), len(issued))
	}
}

func TestCatalogWellFormed(t *testing.T) {
	areaOf := map[byte]string{'1': AreaDocument, '2': AreaMembership, '3': AreaConnection, '4': AreaDNS, '5': AreaKillSwitch, '6': AreaSystem, '7': AreaPanel}
	seen := map[string]bool{}
	known := map[string]bool{}
	for _, c := range issued {
		known[c] = true
	}
	for _, e := range catalog {
		if !Valid(e.Code) {
			t.Errorf("bad code %q", e.Code)
		}
		if seen[e.Code] {
			t.Errorf("duplicate code %s", e.Code)
		}
		seen[e.Code] = true
		if !known[e.Code] {
			t.Errorf("%s is not in the issued list; add it there", e.Code)
		}
		if areaOf[e.Code[3]] != e.Area {
			t.Errorf("%s: area %q does not match its number", e.Code, e.Area)
		}
		if e.Title == "" || e.Cause == "" || len(e.Steps) == 0 {
			t.Errorf("%s: title, cause and steps are required", e.Code)
		}
		if e.Doc != "sorun-giderme.md#"+strings.ToLower(e.Code) {
			t.Errorf("%s: doc %q", e.Code, e.Doc)
		}
		if e.Since < 1 || e.Since > CatalogVersion {
			t.Errorf("%s: since %d", e.Code, e.Since)
		}
	}
	for _, m := range append(append([]sentinel(nil), sentinelMatchers...), lateMatchers...) {
		if !seen[m.code] {
			t.Errorf("matcher points to unknown code %s", m.code)
		}
	}
	for _, m := range textMatchers {
		if !seen[m.code] || m.text != strings.ToLower(m.text) {
			t.Errorf("text matcher %q -> %s", m.text, m.code)
		}
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"OS-3001": "OS-3001", "os-3001": "OS-3001", "os3001": "OS-3001", "3001": "OS-3001", " 3001 ": "OS-3001",
		"OS-8001": "", "OS-0001": "", "abc": "", "": "", "OS-30011": "", strings.Repeat("1", 40): "",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{errors.New("something else"), ""},
		{fmt.Errorf("open: %w", trust.ErrWrongPassphrase), "OS-1001"},
		{fmt.Errorf("sync: %w", trust.ErrRollback), "OS-1004"},
		{admin.ErrConcurrentChange, "OS-1009"},
		{member.ErrNotJoined, "OS-2001"},
		{fmt.Errorf("x: %w", node.ErrNotMember), "OS-2002"},
		{node.ErrInviteGone, "OS-2005"},
		{node.ErrNoReply, "OS-3001"},
		{osnet.ErrDNSOverwritten, "OS-4001"},
		{osnet.ErrKillSwitchNotInstalled, "OS-5002"},
		{&os.PathError{Op: "open", Path: "x", Err: fs.ErrPermission}, "OS-6001"},
		{&os.SyscallError{Syscall: "bind", Err: syscall.EADDRINUSE}, "OS-6002"},
		{errors.New("listen udp :41641: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted."), "OS-6002"},
		{&os.PathError{Op: "open", Path: "x", Err: fs.ErrNotExist}, "OS-6003"},
		{errors.New("tünelin yerel API'sine ulaşılamadı: connection refused"), "OS-7001"},
		{errors.New("resolv.conf yedeklenemedi: read-only file system"), "OS-4003"},
	}
	for _, c := range cases {
		if got := Classify(c.err); got != c.want {
			t.Errorf("Classify(%v) = %q, want %q", c.err, got, c.want)
		}
	}
	// A specific text wins over the general "not found".
	err := fmt.Errorf("resolv.conf yedeği okunamadı: %w", fs.ErrNotExist)
	if got := Classify(err); got != "OS-4003" {
		t.Fatalf("specific before general: %q", got)
	}
}

func TestLookupAndSearch(t *testing.T) {
	e, ok := Lookup("3002")
	if !ok || e.Code != "OS-3002" || e.Area != AreaConnection {
		t.Fatalf("lookup: %+v %v", e, ok)
	}
	// The returned entry is a copy.
	e.Steps[0] = "changed"
	if again, _ := Lookup("OS-3002"); again.Steps[0] == "changed" {
		t.Fatal("Lookup leaks the catalog")
	}
	if _, ok := Lookup("OS-7999"); ok {
		t.Fatal("unknown code found")
	}
	got := Search("guvenlik duvari windows")
	if len(got) == 0 || got[0].Code != "OS-5004" {
		t.Fatalf("search: %+v", got)
	}
	if len(Search("")) != 0 {
		t.Fatal("empty search matched")
	}
	if Suffix("") != "" || !strings.Contains(Suffix("OS-1001"), "openscale explain OS-1001") {
		t.Fatal("suffix")
	}
}

// TestGuideCoversEveryCode keeps docs/sorun-giderme.md (#583) in step
// with the catalog: every code has a heading whose anchor is the code.
func TestGuideCoversEveryCode(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "sorun-giderme.md"))
	if os.IsNotExist(err) {
		t.Skip("troubleshooting guide is not part of this checkout")
	}
	if err != nil {
		t.Fatalf("troubleshooting guide: %v", err)
	}
	text := string(data)
	for _, e := range All() {
		if !strings.Contains(text, "### "+e.Code+" ") {
			t.Errorf("guide has no heading for %s", e.Code)
		}
		if !strings.Contains(text, `<a id="`+strings.ToLower(e.Code)+`"></a>`) {
			t.Errorf("guide has no anchor for %s", e.Code)
		}
	}
}
