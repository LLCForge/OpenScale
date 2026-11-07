package containers

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func sample() []apiContainer {
	return []apiContainer{
		{ID: "aaaaaaaaaaaaaaaa", Names: []string{"/jellyfin"}, Image: "jellyfin/jellyfin", Labels: map[string]string{LabelName: "medya"},
			Ports: []apiPort{{IP: "127.0.0.1", PrivatePort: 8096, PublicPort: 8096, Type: "tcp"}}},
		{ID: "b", Names: []string{"/oyun"}, Labels: map[string]string{LabelName: "oyun", LabelType: "tcp", LabelPort: "25565"},
			Ports: []apiPort{{IP: "0.0.0.0", PrivatePort: 25565, PublicPort: 25570, Type: "tcp"}, {PrivatePort: 25565, Type: "udp", PublicPort: 25570}}},
		{ID: "c", Names: []string{"/ic"}, Labels: map[string]string{LabelName: "ic"}, Ports: []apiPort{{PrivatePort: 80, Type: "tcp"}}},
		{ID: "d", Names: []string{"/iki"}, Labels: map[string]string{LabelName: "iki"},
			Ports: []apiPort{{PrivatePort: 80, PublicPort: 8080, Type: "tcp"}, {PrivatePort: 443, PublicPort: 8443, Type: "tcp"}}},
		{ID: "e", Names: []string{"/kotu"}, Labels: map[string]string{LabelName: "Kötü Ad"}},
		{ID: "f", Names: []string{"/etiketsiz"}},
	}
}

func TestSuggest(t *testing.T) {
	got := suggest(sample())
	if len(got) != 5 {
		t.Fatalf("suggestions %+v", got)
	}
	by := map[string]Suggestion{}
	for _, s := range got {
		by[s.Container] = s
	}
	if s := by["jellyfin"]; s.Target != "http://127.0.0.1:8096" || s.Problem != "" || s.Name != "medya" {
		t.Errorf("jellyfin %+v", s)
	}
	if s := by["oyun"]; s.Target != "127.0.0.1:25570" || s.Type != "tcp" {
		t.Errorf("oyun %+v", s)
	}
	for _, c := range []string{"ic", "iki", "kotu"} {
		if by[c].Problem == "" || by[c].Target != "" {
			t.Errorf("%s should have a problem: %+v", c, by[c])
		}
	}
}

func TestListOverUnixSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix socket not available: %v", err)
	}
	var method, path string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		_ = json.NewEncoder(w).Encode(sample())
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); _ = os.Remove(sock) })
	got, err := List(context.Background(), sock)
	if err != nil || len(got) != 5 {
		t.Fatalf("list: %+v %v", got, err)
	}
	if method != http.MethodGet || path != "/containers/json" {
		t.Fatalf("request %s %s", method, path)
	}
	if _, err := List(context.Background(), "goreli.sock"); err == nil {
		t.Fatal("relative socket accepted")
	}
	if _, err := List(context.Background(), filepath.Join(t.TempDir(), "yok.sock")); err == nil {
		t.Fatal("missing socket accepted")
	}
}
