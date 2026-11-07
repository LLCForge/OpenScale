package desktop

import (
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/peercred"
)

func TestTrayGateForwards(t *testing.T) {
	var seen []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = append(seen, r.Method+" "+r.URL.RequestURI()+" auth="+r.Header.Get("Authorization")+" cookie="+r.Header.Get("Cookie")+" body="+string(body))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "x=y")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	g := newTrayGate(upstream.URL, func() (string, error) { return "secret", nil }, slog.New(slog.NewTextHandler(io.Discard, nil)))

	req := httptest.NewRequest(http.MethodPost, "/api/app/tray/connect", strings.NewReader(`{"connected":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer forged")
	req.Header.Set("Cookie", "session=stolen")
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != `{"ok":true}` || rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("reply %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
	if len(seen) != 1 || seen[0] != `POST /api/app/tray/connect auth=Bearer secret cookie= body={"connected":true}` {
		t.Fatalf("upstream saw %q", seen)
	}

	rec = httptest.NewRecorder()
	g.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/local/events/poll?since=3&wait=25", nil))
	if rec.Code != http.StatusOK || seen[1] != "GET /api/local/events/poll?since=3&wait=25 auth=Bearer secret cookie= body=" {
		t.Fatalf("poll: %d %q", rec.Code, seen)
	}
}

func TestTrayGateRefuses(t *testing.T) {
	called := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called++ }))
	defer upstream.Close()
	g := newTrayGate(upstream.URL, func() (string, error) { return "secret", nil }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, c := range []struct {
		method, target, ctype, body string
		want                        int
	}{
		{http.MethodGet, "/api/app/settings", "", "", http.StatusNotFound},
		{http.MethodPost, "/api/app/tray", "", "", http.StatusNotFound},
		{http.MethodGet, "/api/app/tray/../ticket", "", "", http.StatusNotFound},
		{http.MethodPost, "/api/app/tray/release-on-stop", "", "", http.StatusNotFound},
		{http.MethodGet, "/api/app/tray?x=1", "", "", http.StatusBadRequest},
		{http.MethodGet, "/api/local/events/poll?" + strings.Repeat("a", 100), "", "", http.StatusBadRequest},
		{http.MethodPost, "/api/app/tray/exit", "text/plain", "x", http.StatusUnsupportedMediaType},
		{http.MethodPost, "/api/app/tray/exit", "application/json", strings.Repeat("a", maxGateBody+1), http.StatusRequestEntityTooLarge},
	} {
		req := httptest.NewRequest(c.method, c.target, strings.NewReader(c.body))
		if c.ctype != "" {
			req.Header.Set("Content-Type", c.ctype)
		}
		rec := httptest.NewRecorder()
		g.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s %s: %d, want %d", c.method, c.target, rec.Code, c.want)
		}
	}
	if called != 0 {
		t.Fatalf("upstream called %d times", called)
	}
	noToken := newTrayGate(upstream.URL, func() (string, error) { return "", errors.New("missing") }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	rec := httptest.NewRecorder()
	noToken.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/app/tray", nil))
	if rec.Code != http.StatusServiceUnavailable || called != 0 {
		t.Fatalf("without token: %d", rec.Code)
	}
}

func TestGatePeerPolicy(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "openscale")
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(good, []byte("openscale program"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("something else"), 0o755); err != nil {
		t.Fatal(err)
	}
	hashes := &programHashes{}
	p := gatePeerPolicy{
		want: sha256.Sum256([]byte("openscale program")),
		image: func(pid int) (string, error) {
			switch pid {
			case 10:
				return good, nil
			case 11:
				return other, nil
			}
			return "", errors.New("gone")
		},
		hash: hashes.sum,
	}
	admin := peercred.Identity{PID: 10, UID: 501, Groups: []string{"20", "80"}}
	if err := p.check(admin); err != nil {
		t.Fatalf("admin running openscale: %v", err)
	}
	if err := p.check(peercred.Identity{PID: 10, UID: 0, Admin: true}); err != nil {
		t.Fatalf("root running openscale: %v", err)
	}
	for name, id := range map[string]peercred.Identity{
		"standard user":     {PID: 10, UID: 502, Groups: []string{"20"}},
		"admin, other exe":  {PID: 11, UID: 501, Groups: []string{"80"}},
		"admin, gone":       {PID: 12, UID: 501, Groups: []string{"80"}},
		"admin, no process": {PID: 0, UID: 501, Groups: []string{"80"}},
	} {
		if err := p.check(id); !errors.Is(err, errGatePeer) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A full kernel group list falls back to the directory service.
	full := peercred.Identity{PID: 10, UID: 503, Groups: []string{"20", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15"}}
	if err := p.check(full); !errors.Is(err, errGatePeer) {
		t.Fatalf("full list without lookup: %v", err)
	}
	p.inGroup = func(uid, gid int) bool { return uid == 503 && gid == adminGroupID }
	if err := p.check(full); err != nil {
		t.Fatalf("full list, directory says admin: %v", err)
	}
	if err := p.check(peercred.Identity{PID: 10, UID: 503, Groups: []string{"20"}}); !errors.Is(err, errGatePeer) {
		t.Fatalf("short list must not ask the directory: %v", err)
	}
	// The cache notices a replaced file.
	if err := os.WriteFile(good, []byte("replaced, longer program"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := p.check(admin); !errors.Is(err, errGatePeer) {
		t.Fatalf("replaced program accepted: %v", err)
	}
}

// TestGatePeerPolicyLinux checks the Linux rules (ADR-0234): the
// openscale group, always asked from the group database because
// SO_PEERCRED has the primary group only; without the group only root.
func TestGatePeerPolicyLinux(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "openscale")
	if err := os.WriteFile(good, []byte("openscale program"), 0o755); err != nil {
		t.Fatal(err)
	}
	hashes := &programHashes{}
	p := gatePeerPolicy{
		want:          sha256.Sum256([]byte("openscale program")),
		image:         func(int) (string, error) { return good, nil },
		hash:          hashes.sum,
		group:         997,
		partialGroups: true,
		inGroup:       func(uid, gid int) bool { return uid == 1000 && gid == 997 },
	}
	if err := p.check(peercred.Identity{PID: 5, UID: 1000, Groups: []string{"1000"}}); err != nil {
		t.Fatalf("group member: %v", err)
	}
	if err := p.check(peercred.Identity{PID: 5, UID: 1001, Groups: []string{"1001"}}); !errors.Is(err, errGatePeer) {
		t.Fatalf("non-member: %v", err)
	}
	// The macOS admin group means nothing here.
	if err := p.check(peercred.Identity{PID: 5, UID: 1002, Groups: []string{"80"}}); !errors.Is(err, errGatePeer) {
		t.Fatalf("gid 80: %v", err)
	}
	p.group = noGroup
	if err := p.check(peercred.Identity{PID: 5, UID: 1000, Groups: []string{"997"}}); !errors.Is(err, errGatePeer) {
		t.Fatalf("no group configured: %v", err)
	}
	if err := p.check(peercred.Identity{PID: 5, UID: 0, Admin: true}); err != nil {
		t.Fatalf("root: %v", err)
	}
}
