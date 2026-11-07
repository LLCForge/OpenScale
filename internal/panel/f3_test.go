package panel

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/filesend"
	"github.com/openscale/openscale/internal/p2psend"
	"github.com/openscale/openscale/internal/rdesk"
	"github.com/openscale/openscale/internal/sftpclient/sftptest"
)

// f3App adds staging to the G6 test app.
type f3App struct {
	g6App
	stageDir string
}

func (a *f3App) E2EStage(name string, body io.Reader) (string, error) {
	clean, err := filesend.SanitizeName(name)
	if err != nil || clean != name {
		return "", ErrE2EStageName
	}
	p := filepath.Join(a.stageDir, clean)
	f, err := os.Create(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(f, body); err != nil {
		return "", err
	}
	return p, nil
}

func f3TestApp(t *testing.T) *f3App {
	q := p2psend.Quarantine{Dir: t.TempDir(), Inbox: filepath.Join(t.TempDir(), "gelen")}
	return &f3App{g6App: g6App{svc: &p2psend.Service{Approvals: p2psend.NewApprovals(time.Minute), Registry: p2psend.NewRegistry(), Q: q}}, stageDir: t.TempDir()}
}

func TestSFTPBrowser(t *testing.T) {
	remote := t.TempDir()
	if err := os.WriteFile(filepath.Join(remote, "rapor.txt"), []byte("uzak içerik"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := sftptest.StartSSH(t, remote, "ayse", "linux-parolasi")
	srv := newTestServer(t)
	app := f3TestApp(t)
	srv.app = app
	srv.SetSSHResolver(func(name string) (netip.Addr, bool) { return target.Addr.Addr(), name == "sunucu" })
	defer srv.closeAllSFTP()
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	read := func(r *http.Request) { r.AddCookie(cookie) }
	signed := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r); r.Header.Set("X-CSRF-Token", csrf) }
	port := int(target.Addr.Port())

	// Wrong password, then the right one.
	rec := do(t, h, http.MethodPost, "/api/sftp/open", map[string]any{"device": "sunucu", "port": port, "user": "ayse", "password": []byte("yanlış")}, signed)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "auth_failed") {
		t.Fatalf("wrong password: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/sftp/open", map[string]any{"device": "sunucu", "port": port, "user": "ayse", "password": []byte("linux-parolasi")}, read); rec.Code != http.StatusForbidden {
		t.Fatalf("open without CSRF: %d", rec.Code)
	}
	rec = do(t, h, http.MethodPost, "/api/sftp/open", map[string]any{"device": "sunucu", "port": port, "user": "ayse", "password": []byte("linux-parolasi")}, signed)
	if rec.Code != http.StatusOK {
		t.Fatalf("open: %d %s", rec.Code, rec.Body)
	}
	var opened struct {
		Handle string
		Home   string
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &opened); err != nil || opened.Handle == "" || opened.Home != "/" {
		t.Fatalf("open answer %s", rec.Body)
	}
	hq := url.QueryEscape(opened.Handle)

	rec = do(t, h, http.MethodGet, "/api/sftp/list?h="+hq+"&path=/", nil, read)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "rapor.txt") {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/sftp/list?h=baskasi&path=/", nil, read); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown handle: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/sftp/list?h="+hq+"&path=relative", nil, read); rec.Code != http.StatusBadRequest {
		t.Fatalf("relative path: %d", rec.Code)
	}

	// Folder names must be one element.
	for _, bad := range []string{"..", "a/b", "", "x\x00"} {
		if rec := do(t, h, http.MethodPost, "/api/sftp/mkdir", map[string]string{"h": opened.Handle, "dir": "/", "name": bad}, signed); rec.Code != http.StatusBadRequest {
			t.Fatalf("mkdir %q: %d", bad, rec.Code)
		}
	}
	if rec := do(t, h, http.MethodPost, "/api/sftp/mkdir", map[string]string{"h": opened.Handle, "dir": "/", "name": "yeni"}, signed); rec.Code != http.StatusOK {
		t.Fatalf("mkdir: %d %s", rec.Code, rec.Body)
	}
	if fi, err := os.Stat(filepath.Join(remote, "yeni")); err != nil || !fi.IsDir() {
		t.Fatalf("folder not created: %v", err)
	}

	upload := func(name string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://"+testHost+"/api/sftp/upload?h="+hq+"&dir=/yeni", bytes.NewReader(body))
		req.Host = testHost
		req.Header.Set(E2EFileNameHeader, url.PathEscape(name))
		req.Header.Set("Content-Type", "application/octet-stream")
		signed(req)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	if rec := upload("../kaçak.txt", []byte("x")); rec.Code != http.StatusBadRequest {
		t.Fatalf("traversal upload: %d", rec.Code)
	}
	if rec := upload("yüklenen.txt", []byte("yerel içerik")); rec.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body)
	}
	if b, err := os.ReadFile(filepath.Join(remote, "yeni", "yüklenen.txt")); err != nil || string(b) != "yerel içerik" {
		t.Fatalf("uploaded = %q, %v", b, err)
	}
	if rec := upload("yüklenen.txt", []byte("üzerine")); rec.Code == http.StatusOK {
		t.Fatal("upload replaced an existing file")
	}

	// Download lands in the quarantine with the mark.
	rec = do(t, h, http.MethodPost, "/api/sftp/download", map[string]string{"h": opened.Handle, "path": "/rapor.txt"}, signed)
	if rec.Code != http.StatusOK {
		t.Fatalf("download: %d %s", rec.Code, rec.Body)
	}
	var dl struct {
		Name string
		Size int64
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &dl)
	qdir := app.svc.Q.Dir
	if b, err := os.ReadFile(filepath.Join(qdir, dl.Name)); err != nil || string(b) != "uzak içerik" {
		t.Fatalf("quarantined = %q, %v", b, err)
	}
	if rec := do(t, h, http.MethodPost, "/api/sftp/download", map[string]string{"h": opened.Handle, "path": "/yeni"}, signed); rec.Code != http.StatusBadRequest {
		t.Fatalf("download of a folder: %d", rec.Code)
	}
	// A second download keeps the first file.
	rec = do(t, h, http.MethodPost, "/api/sftp/download", map[string]string{"h": opened.Handle, "path": "/rapor.txt"}, signed)
	var dl2 struct{ Name string }
	_ = json.Unmarshal(rec.Body.Bytes(), &dl2)
	if rec.Code != http.StatusOK || dl2.Name == dl.Name {
		t.Fatalf("second download: %d %q", rec.Code, dl2.Name)
	}

	// Remove: the kind must match, the root is refused.
	if rec := do(t, h, http.MethodPost, "/api/sftp/remove", map[string]any{"h": opened.Handle, "path": "/", "dir": true}, signed); rec.Code != http.StatusBadRequest {
		t.Fatalf("remove root: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/sftp/remove", map[string]any{"h": opened.Handle, "path": "/rapor.txt", "dir": true}, signed); rec.Code != http.StatusConflict {
		t.Fatalf("remove with the wrong kind: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/sftp/remove", map[string]any{"h": opened.Handle, "path": "/rapor.txt"}, signed); rec.Code != http.StatusOK {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(remote, "rapor.txt")); !os.IsNotExist(err) {
		t.Fatalf("file still there: %v", err)
	}

	if rec := do(t, h, http.MethodPost, "/api/sftp/close", map[string]string{"h": opened.Handle}, signed); rec.Code != http.StatusOK {
		t.Fatalf("close: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/sftp/list?h="+hq, nil, read); rec.Code != http.StatusNotFound {
		t.Fatalf("list after close: %d", rec.Code)
	}
}

func TestTrayE2ERoutes(t *testing.T) {
	srv := newTestServer(t)
	srv.token = strings.Repeat("t", 40)
	app := f3TestApp(t)
	srv.app = app
	h := srv.Handler()
	tok := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+srv.token) }

	if rec := do(t, h, http.MethodGet, "/api/app/tray/e2e", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("without token: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/app/tray/e2e", nil, func(r *http.Request) { tok(r); withOrigin(r) }); rec.Code != http.StatusForbidden {
		t.Fatalf("from a browser: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/app/tray/e2e", nil, tok); rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/tray/e2e/decide", E2EDecision{ID: "yok", Accept: true}, tok); rec.Code != http.StatusNotFound {
		t.Fatalf("decide unknown: %d", rec.Code)
	}
	outside := filepath.Join(t.TempDir(), "gizli.txt")
	if rec := do(t, h, http.MethodPost, "/api/app/tray/e2e/send", TrayE2ESend{Device: "masa", Path: outside}, tok); rec.Code != http.StatusForbidden {
		t.Fatalf("send of an unstaged path: %d", rec.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "http://"+testHost+"/api/app/tray/e2e/stage", strings.NewReader("belge"))
	req.Host = testHost
	req.Header.Set(E2EFileNameHeader, url.PathEscape("not.txt"))
	tok(req)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("stage: %d %s", rec.Code, rec.Body)
	}
	var staged E2EStaged
	_ = json.Unmarshal(rec.Body.Bytes(), &staged)
	if !srv.takeStaged(staged.Path) {
		t.Fatal("staged path not remembered")
	}
	srv.rememberStaged(staged.Path)
	// The staged path passes the check; the test service has no identity,
	// so the transfer itself is refused afterwards.
	if rec := do(t, h, http.MethodPost, "/api/app/tray/e2e/send", TrayE2ESend{Device: "masa", Path: staged.Path}, tok); rec.Code == http.StatusForbidden {
		t.Fatalf("staged send refused by the check: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/tray/e2e/send", TrayE2ESend{Device: "masa", Path: staged.Path}, tok); rec.Code != http.StatusForbidden {
		t.Fatalf("second send of one staged file: %d", rec.Code)
	}
}

func TestRDeskMonitorOption(t *testing.T) {
	cases := map[string]int{"": rdesk.MonitorPrimary, "primary": rdesk.MonitorPrimary, "all": rdesk.MonitorAll, "0": 0, "3": 3, "15": 15}
	for in, want := range cases {
		if got, ok := rdeskMonitorOption(in); !ok || got != want {
			t.Errorf("%q = %d, %v", in, got, ok)
		}
	}
	for _, in := range []string{"16", "-1", "01", "x", " 1"} {
		if _, ok := rdeskMonitorOption(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
}
