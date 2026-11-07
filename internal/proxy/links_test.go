package proxy

import (
	"io"
	"net/http"
	"testing"
)

type fakeLinks struct{ peers []string }

func (l *fakeLinks) ServeLink(w http.ResponseWriter, r *http.Request, peer string) {
	l.peers = append(l.peers, peer)
	_, _ = io.WriteString(w, "bağlantı "+r.URL.Path)
}

func TestSharedPortLinks(t *testing.T) {
	f := newFixture()
	links := &fakeLinks{}
	env := f.env()
	env.Links = links
	srv, err := New(Config{Schema: ConfigSchema}, env)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if !srv.HasShared() {
		t.Fatal("links do not open the shared port")
	}
	addr := serve(t, srv.ServeShared)
	host := "nas." + testDomain
	f.as("telefon")
	if resp, body := do(t, addr, "GET", host, "/l/abc", nil); resp.StatusCode != 200 || body != "bağlantı /l/abc" {
		t.Fatalf("link: %d %q", resp.StatusCode, body)
	}
	if len(links.peers) != 1 || links.peers[0] != "telefon" {
		t.Fatalf("peer %v", links.peers)
	}
	// Another Host is refused (DNS rebinding).
	if resp, _ := do(t, addr, "GET", "evil.example", "/l/abc", nil); resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("host: %d", resp.StatusCode)
	}
	if len(links.peers) != 1 {
		t.Fatalf("refused request reached the link server: %v", links.peers)
	}
	// A device without a serve rule to this one is not served (the
	// connection is refused when it is accepted).
	f.mu.Lock()
	f.doc.Rules = f.doc.Rules[1:]
	f.mu.Unlock()
	f.as("telefon")
	pi, ok := srv.identifyAddr(f.doc.Devices[2].IPv4)
	if !ok || pi.doc.AllowsServe("telefon", "nas") {
		t.Fatal("rule removal not seen")
	}
}
