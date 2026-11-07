package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/release"
)

const artifact = "openscale-test-amd64"

// Programs in these tests are text files "openscale-program <version>
// <behaviour>"; fakeVersion plays "<exe> version --json" and fakeService
// plays a service manager that runs the installed file.

func program(version, behaviour string) []byte {
	return []byte("openscale-program " + version + " " + behaviour + "\n")
}

func parseProgram(path string) (version, behaviour string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	f := strings.Fields(string(data))
	if len(f) != 3 || f[0] != "openscale-program" {
		return "", "", errors.New("not a program")
	}
	return f[1], f[2], nil
}

func fakeVersion(_ context.Context, exe string) (string, error) {
	v, b, err := parseProgram(exe)
	if err != nil {
		return "", err
	}
	if b == "noversion" {
		return "", errors.New("exit status 2")
	}
	if b == "liar" {
		return "9.9.9", nil
	}
	return v, nil
}

type fakeService struct {
	mu       sync.Mutex
	exe      string
	running  bool
	pid      int
	polls    int
	starts   int
	stops    int
	stopFail bool
}

func (s *fakeService) Name() string { return "openscale-device" }

func (s *fakeService) Stop(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopFail {
		return errors.New("access denied")
	}
	s.running = false
	s.stops++
	return nil
}

func (s *fakeService) Start(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.starts++
	_, b, err := parseProgram(s.exe)
	if err != nil {
		return err
	}
	if b == "nostart" {
		return errors.New("service did not start")
	}
	s.running, s.pid = true, s.pid+1
	return nil
}

func (s *fakeService) Status(context.Context) (ServiceState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.polls++
	if s.running {
		if _, b, _ := parseProgram(s.exe); b == "crash" {
			s.pid++ // the service manager restarts a crashing process
		}
	}
	return ServiceState{Installed: true, Running: s.running, PID: s.pid}, nil
}

type fixture struct {
	t        *testing.T
	dir      string
	exe      string
	state    string
	root     release.PublicKey
	rootPriv ed25519.PrivateKey
	signPriv ed25519.PrivateKey
	certEnv  release.Envelope
	svc      *fakeService
	now      time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, dir: t.TempDir(), now: time.Now()}
	f.exe = filepath.Join(f.dir, "openscale")
	f.state = filepath.Join(f.dir, "data", "update")
	if err := os.WriteFile(f.exe, program("0.8.0", "ok"), 0o755); err != nil {
		t.Fatal(err)
	}
	var err error
	if f.root, f.rootPriv, err = release.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	signing, signPriv, err := release.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.signPriv = signPriv
	f.certEnv, _, err = release.IssueCertificate(f.rootPriv, release.CertificateRequest{
		SigningKey: signing, Serial: 1, NotBefore: f.now.Add(-time.Hour), Validity: release.DefaultCertificateValidity,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.svc = &fakeService{exe: f.exe, running: true, pid: 100}
	return f
}

// release writes a signed release of body into a new folder.
func (f *fixture) release(version string, body []byte) string {
	f.t.Helper()
	dir := filepath.Join(f.t.TempDir(), "surum-"+version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, artifact), body, 0o644); err != nil {
		f.t.Fatal(err)
	}
	a, err := release.HashArtifact(artifact, strings.NewReader(string(body)))
	if err != nil {
		f.t.Fatal(err)
	}
	m := release.NewManifest(version, "20261030.1200", f.now.Unix(), []release.Artifact{a})
	data, err := release.SignManifest(f.signPriv, f.certEnv, f.root, m, f.now)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openscale-"+version+".release.json"), data, 0o644); err != nil {
		f.t.Fatal(err)
	}
	return dir
}

func (f *fixture) opts() Options {
	return Options{
		Exe: f.exe, Artifact: artifact, Root: f.root, StateDir: f.state,
		Services:       []Service{f.svc},
		ProgramVersion: fakeVersion,
		HealthTimeout:  2 * time.Second, StableFor: 50 * time.Millisecond, PollEvery: 5 * time.Millisecond,
		Logf: func(format string, args ...any) { f.t.Logf(format, args...) },
	}
}

func (f *fixture) apply(o Options, dir string) (*Result, error) {
	src, err := LoadSource(context.Background(), dir, "", artifact, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return Apply(context.Background(), o, src)
}

func (f *fixture) installedVersion() string {
	v, _, err := parseProgram(f.exe)
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}

func TestApplyAndManualRollback(t *testing.T) {
	f := newFixture(t)
	res, err := f.apply(f.opts(), f.release("0.9.0", program("0.9.0", "ok")))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.From != "0.8.0" || res.To != "0.9.0" || !res.Restarted || res.RolledBack {
		t.Fatalf("result %+v", res)
	}
	if f.installedVersion() != "0.9.0" || f.svc.stops != 1 || f.svc.starts != 1 {
		t.Fatalf("installed %s, stops %d, starts %d", f.installedVersion(), f.svc.stops, f.svc.starts)
	}
	if v, _, _ := parseProgram(f.exe + PrevSuffix); v != "0.8.0" {
		t.Fatal("previous program not kept")
	}
	if j, err := ReadJournal(f.state); err != nil || j != nil {
		t.Fatalf("journal left: %+v %v", j, err)
	}
	if v, ok, err := CheckInstalled(f.state, f.exe, f.root, time.Now()); err != nil || !ok || v != "0.9.0" {
		t.Fatalf("CheckInstalled = %s %v %v", v, ok, err)
	}
	// A changed program fails the integrity check (#172).
	if err := os.WriteFile(f.exe, program("0.9.0", "tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := CheckInstalled(f.state, f.exe, f.root, time.Now()); ok || !errors.Is(err, release.ErrDigestMismatch) {
		t.Fatalf("tampered program: ok=%v err=%v", ok, err)
	}
	if err := os.WriteFile(f.exe, program("0.9.0", "ok"), 0o755); err != nil {
		t.Fatal(err)
	}

	res, err = Rollback(context.Background(), f.opts())
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if f.installedVersion() != "0.8.0" || !res.RolledBack || !f.svc.running {
		t.Fatalf("after rollback %s %+v running=%v", f.installedVersion(), res, f.svc.running)
	}
	if _, ok, _ := CheckInstalled(f.state, f.exe, f.root, time.Now()); ok {
		t.Fatal("manifest of the removed version kept")
	}
}

func TestAutomaticRollbackOnCrash(t *testing.T) {
	for _, behaviour := range []string{"crash", "nostart"} {
		t.Run(behaviour, func(t *testing.T) {
			f := newFixture(t)
			res, err := f.apply(f.opts(), f.release("0.9.0", program("0.9.0", behaviour)))
			if !errors.Is(err, ErrUnhealthy) {
				t.Fatalf("Apply = %v, want ErrUnhealthy", err)
			}
			if res == nil || !res.RolledBack {
				t.Fatalf("result %+v", res)
			}
			if f.installedVersion() != "0.8.0" || !f.svc.running {
				t.Fatalf("installed %s running %v", f.installedVersion(), f.svc.running)
			}
			if _, b, _ := parseProgram(f.exe + FailedSuffix); b != behaviour {
				t.Fatal("failed program not kept for diagnosis")
			}
			if j, _ := ReadJournal(f.state); j != nil {
				t.Fatalf("journal left after a successful rollback: %+v", j)
			}
		})
	}
}

func TestMarkerRequired(t *testing.T) {
	f := newFixture(t)
	o := f.opts()
	var marker Marker
	o.ReadMarker = func() (Marker, error) { return marker, nil }
	// The service runs but never reports the new version: rolled back.
	_, err := f.apply(o, f.release("0.9.0", program("0.9.0", "ok")))
	if !errors.Is(err, ErrUnhealthy) || f.installedVersion() != "0.8.0" {
		t.Fatalf("Apply = %v, installed %s", err, f.installedVersion())
	}
	marker = Marker{Version: "0.9.0", PID: 1, Started: time.Now().Add(time.Minute)}
	if _, err := f.apply(o, f.release("0.9.0", program("0.9.0", "ok"))); err != nil {
		t.Fatalf("Apply with marker: %v", err)
	}
}

func TestRefusals(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name string
		dir  func() string
		mod  func(*Options)
		want error
	}{
		{"downgrade", func() string { return f.release("0.7.0", program("0.7.0", "ok")) }, nil, release.ErrRollback},
		{"same version", func() string { return f.release("0.8.0", program("0.8.0", "ok")) }, nil, ErrAlreadyLatest},
		{"version lie", func() string { return f.release("0.9.0", program("0.9.0", "liar")) }, nil, ErrVersionDiffer},
		{"program does not run", func() string { return f.release("0.9.0", program("0.9.0", "noversion")) }, nil, nil},
		{"tampered program", func() string {
			dir := f.release("0.9.0", program("0.9.0", "ok"))
			if err := os.WriteFile(filepath.Join(dir, artifact), program("0.9.0", "evil"), 0o644); err != nil {
				t.Fatal(err)
			}
			return dir
		}, nil, release.ErrDigestMismatch},
		{"other root key", func() string { return f.release("0.9.0", program("0.9.0", "ok")) }, func(o *Options) {
			other, _, _ := release.GenerateKey(rand.Reader)
			o.Root = other
		}, nil},
		{"fingerprint", func() string { return f.release("0.9.0", program("0.9.0", "ok")) }, func(o *Options) { o.RootFingerprint = "AAAA" }, nil},
		{"stop fails", func() string { return f.release("0.9.0", program("0.9.0", "ok")) }, func(*Options) { f.svc.stopFail = true }, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f.svc.stopFail = false
			o := f.opts()
			if c.mod != nil {
				c.mod(&o)
			}
			_, err := f.apply(o, c.dir())
			if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("Apply = %v, want %v", err, c.want)
			}
			if f.installedVersion() != "0.8.0" {
				t.Fatal("installed program changed")
			}
			if j, _ := ReadJournal(f.state); j != nil {
				t.Fatalf("journal left: %+v", j)
			}
			entries, _ := os.ReadDir(f.dir)
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), ".openscale-update-") {
					t.Fatalf("staged file left: %s", e.Name())
				}
			}
		})
	}
	f.svc.stopFail = false
	// With the downgrade allowed the older release installs.
	o := f.opts()
	o.AllowDowngrade = true
	if _, err := f.apply(o, f.release("0.7.0", program("0.7.0", "ok"))); err != nil {
		t.Fatalf("allowed downgrade: %v", err)
	}
}

func TestPendingJournalBlocksAndStagedIsCleaned(t *testing.T) {
	f := newFixture(t)
	staged := filepath.Join(f.dir, ".openscale-update-0011223344556677.new")
	if err := os.WriteFile(staged, program("0.9.0", "ok"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeJournal(f.state, &Journal{State: StateStaged, Exe: f.exe, Staged: staged, From: "0.8.0", To: "0.9.0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.apply(f.opts(), f.release("0.9.0", program("0.9.0", "ok"))); !errors.Is(err, ErrPending) {
		t.Fatalf("Apply = %v, want ErrPending", err)
	}
	if _, err := Rollback(context.Background(), f.opts()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(staged); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("staged file not removed")
	}
	if _, err := f.apply(f.opts(), f.release("0.9.0", program("0.9.0", "ok"))); err != nil {
		t.Fatalf("Apply after cleanup: %v", err)
	}
}

func TestServiceNotRunning(t *testing.T) {
	f := newFixture(t)
	f.svc.running = false
	res, err := f.apply(f.opts(), f.release("0.9.0", program("0.9.0", "ok")))
	if err != nil || res.Restarted || len(res.Warnings) == 0 || f.svc.starts != 0 {
		t.Fatalf("res %+v err %v starts %d", res, err, f.svc.starts)
	}
	if f.installedVersion() != "0.9.0" {
		t.Fatal("not installed")
	}
}

func TestHTTPSSource(t *testing.T) {
	f := newFixture(t)
	dir := f.release("0.9.0", program("0.9.0", "ok"))
	srv := httptest.NewTLSServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()
	if !strings.HasPrefix(srv.URL, "https://127.0.0.1:") {
		t.Fatalf("test server not on loopback: %s", srv.URL)
	}
	src, err := LoadSource(context.Background(), srv.URL+"/openscale-0.9.0.release.json", "", artifact, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(src.Where, "/"+artifact) {
		t.Fatalf("program URL %s", src.Where)
	}
	if _, err := Apply(context.Background(), f.opts(), src); err != nil {
		t.Fatalf("Apply over HTTPS: %v", err)
	}
	for _, bad := range []string{"http://127.0.0.1/x.release.json", "https://user:pw@127.0.0.1/x.release.json"} {
		if _, err := LoadSource(context.Background(), bad, "", artifact, srv.Client()); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}

func TestParseVersionOutput(t *testing.T) {
	for in, want := range map[string]string{
		`{"schema":1,"version":"0.9.0 (20261030.0412)"}`: "0.9.0",
		`{"schema":1,"version":"0.0.0-dev"}`:             "0.0.0-dev",
	} {
		if got, err := ParseVersionOutput([]byte(in)); err != nil || got != want {
			t.Fatalf("%s: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"", "openscale 0.9.0", `{"version":"x y"}`} {
		if _, err := ParseVersionOutput([]byte(in)); err == nil {
			t.Fatalf("%q accepted", in)
		}
	}
}

func TestArtifactName(t *testing.T) {
	for _, c := range [][3]string{{"windows", "amd64", "openscale-windows-amd64.exe"}, {"linux", "arm", "openscale-linux-armv7"}, {"linux", "arm64", "openscale-linux-arm64"}} {
		if got, err := ArtifactName(c[0], c[1]); err != nil || got != c[2] {
			t.Fatalf("%v: %s %v", c, got, err)
		}
	}
	if _, err := ArtifactName("plan9", "386"); err == nil {
		t.Fatal("unknown platform accepted")
	}
}

func TestLimitedBuffer(t *testing.T) {
	b := limitedBuffer{max: 4}
	if n, _ := io.WriteString(&b, "abcdef"); n != 6 || b.String() != "abcd" {
		t.Fatal(fmt.Sprint(n, b.String()))
	}
}

// TestMain lets the test binary play an OpenScale program for RunVersion.
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "version" && os.Args[2] == "--json" {
		fmt.Println(`{"schema":1,"version":"0.9.1 (20261030.0412)"}`)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestRunVersionExecutesProgram(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	v, err := RunVersion(context.Background(), exe)
	if err != nil || v != "0.9.1" {
		t.Fatalf("RunVersion = %q, %v", v, err)
	}
	if _, err := RunVersion(context.Background(), filepath.Join(t.TempDir(), "yok")); err == nil {
		t.Fatal("missing program accepted")
	}
}
