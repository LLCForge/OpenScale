package autoupdate

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/updater"
)

const testArtifact = "openscale-windows-amd64.exe"

// keys is a release root key and a certified signing key.
type keys struct {
	root     release.PublicKey
	rootPriv ed25519.PrivateKey
	signing  release.PublicKey
	signPriv ed25519.PrivateKey
	cert     release.Envelope
}

func newKeys(t *testing.T) *keys {
	t.Helper()
	k := &keys{}
	var err error
	if k.root, k.rootPriv, err = release.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	if k.signing, k.signPriv, err = release.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	k.cert, _, err = release.IssueCertificate(k.rootPriv, release.CertificateRequest{
		SigningKey: k.signing, Serial: 1, NotBefore: time.Now().Add(-time.Hour), Validity: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// program is what the fake installed program "is": its version text.
func program(version string) []byte {
	return append([]byte("openscale "+version+"\n"), bytes.Repeat([]byte{0x5a}, 3000)...)
}

// dist writes a signed release of version with the Windows program, as
// scripts/release.sh would, and returns the folder.
func (k *keys) dist(t *testing.T, version string, prog []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, testArtifact), prog, 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := release.HashArtifact(testArtifact, bytes.NewReader(prog))
	if err != nil {
		t.Fatal(err)
	}
	m := release.NewManifest(version, "20261107.1200", time.Now().Unix(), []release.Artifact{a})
	signed, err := release.SignManifest(k.signPriv, k.cert, k.root, m, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openscale-"+version+".release.json"), signed, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func gz(t *testing.T, data []byte) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// fakeCoordinator serves a mirror folder with the coordinator's own code.
type fakeCoordinator struct {
	handle func(control.Message) control.Message
	reload func()
	chunks atomic.Int64
}

func newFakeCoordinator(mirror string) *fakeCoordinator {
	h, reload := coordinator.ReleaseMirrorHandler(mirror, nil)
	return &fakeCoordinator{handle: h, reload: reload}
}

func (f *fakeCoordinator) ReleaseCall(_ context.Context, req control.Message) (control.Message, error) {
	// Through the wire format, as the tunnel carries it.
	data, err := control.Encode(req)
	if err != nil {
		return control.Message{}, err
	}
	if req, err = control.Decode(data); err != nil {
		return control.Message{}, err
	}
	if req.T == control.TypeReleaseFile {
		f.chunks.Add(1)
	}
	resp := f.handle(req)
	resp.ID = req.ID
	out, err := control.Encode(resp)
	if err != nil {
		return control.Message{}, err
	}
	if resp, err = control.Decode(out); err != nil {
		return control.Message{}, err
	}
	if resp.T == control.TypeError {
		return resp, errors.New("coordinator: " + resp.Error)
	}
	return resp, nil
}

type world struct {
	t        *testing.T
	keys     *keys
	paths    Paths
	coordDir string
	mirror   string
	coord    *fakeCoordinator
	exe      string
	triggers atomic.Int64
}

func newWorld(t *testing.T, installed string) *world {
	t.Helper()
	base := t.TempDir()
	w := &world{t: t, keys: newKeys(t), coordDir: filepath.Join(base, "coordinator")}
	w.mirror = filepath.Join(w.coordDir, coordinator.ReleaseMirrorDir)
	upd := filepath.Join(base, "update")
	w.paths = Paths{Supported: true, Mode: ModeBinary, UpdaterState: upd, Settings: filepath.Join(upd, SettingsFile), Work: filepath.Join(upd, "auto")}
	if err := os.MkdirAll(w.coordDir, 0o700); err != nil {
		t.Fatal(err)
	}
	w.exe = filepath.Join(base, "program", "openscale.exe")
	if err := os.MkdirAll(filepath.Dir(w.exe), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.exe, program(installed), 0o700); err != nil {
		t.Fatal(err)
	}
	w.paths.Exe = w.exe
	w.coord = newFakeCoordinator(w.mirror)
	return w
}

func (w *world) publish(version string) {
	w.t.Helper()
	if _, err := Publish(PublishOptions{Dist: w.keys.dist(w.t, version, program(version)), StateDir: w.coordDir, Root: w.keys.root}); err != nil {
		w.t.Fatal(err)
	}
	w.coord.reload()
}

func (w *world) runner(installed string, root release.PublicKey) *Runner {
	return New(Config{
		Paths: w.paths, Fetcher: w.coord, Installed: installed, GOOS: "windows", GOARCH: "amd64",
		LoadRoot: func() (release.PublicKey, error) {
			if root.IsZero() {
				return root, errors.New("no key")
			}
			return root, nil
		},
		Trigger: func(context.Context) error { w.triggers.Add(1); return nil },
		Jitter:  func(time.Duration) time.Duration { return 0 },
		Rate:    -1,
	})
}

// fakeVersion reads the version from the fake program's first line.
func fakeVersion(_ context.Context, exe string) (string, error) {
	data, err := os.ReadFile(exe)
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(string(data), "\n")
	v, ok := strings.CutPrefix(line, "openscale ")
	if !ok {
		return "", errors.New("not a program")
	}
	return v, nil
}

func (w *world) install(installed string) (*updater.Result, error) {
	return Install(context.Background(), InstallOptions{
		Paths:    w.paths,
		LoadRoot: func() (release.PublicKey, error) { return w.keys.root, nil },
		GOOS:     "windows", GOARCH: "amd64",
		Binary: func() (updater.Options, error) {
			return updater.Options{
				Exe: w.exe, StateDir: w.paths.UpdaterState, Installed: installed, ProgramVersion: fakeVersion,
				HealthTimeout: time.Second, StableFor: time.Millisecond, PollEvery: time.Millisecond,
			}, nil
		},
	})
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

// TestEndToEnd: publish on the coordinator, the device verifies and
// downloads through the mirror protocol, the installer verifies again and
// the real updater.Apply replaces the (fake) program.
func TestEndToEnd(t *testing.T) {
	w := newWorld(t, "1.0.0")
	w.publish("1.0.1")
	r := w.runner("1.0.0", w.keys.root)
	st, _ := r.Check(context.Background())
	if st.State != StateInstalling || !st.LatestVerified || st.Latest != "1.0.1" || w.triggers.Load() != 1 {
		t.Fatalf("check: %+v triggers %d", st, w.triggers.Load())
	}
	if !exists(filepath.Join(w.paths.Work, RequestFile)) {
		t.Fatal("no request")
	}
	// A second check while the installer has not run does not download again.
	before := w.coord.chunks.Load()
	if st, _ := r.Check(context.Background()); st.State != StateInstalling || w.coord.chunks.Load() != before {
		t.Fatalf("second check: %+v", st)
	}
	res, err := w.install("1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if res.To != "1.0.1" {
		t.Fatalf("result %+v", res)
	}
	if v, _ := fakeVersion(context.Background(), w.exe); v != "1.0.1" {
		t.Fatalf("installed program reports %q", v)
	}
	if !exists(w.exe + updater.PrevSuffix) {
		t.Fatal("no previous program kept for rollback")
	}
	// The restarted service (new version) takes the report.
	r2 := w.runner("1.0.1", w.keys.root)
	st, _ = r2.Check(context.Background())
	if st.State != StateUpToDate || st.LastAttempt == nil || !st.LastAttempt.OK || st.LastAttempt.Version != "1.0.1" {
		t.Fatalf("after install: %+v %+v", st, st.LastAttempt)
	}
	if exists(filepath.Join(w.paths.Work, CacheDir)) || exists(filepath.Join(w.paths.Work, ResultFile)) {
		t.Fatal("work files left behind")
	}
	if saved, err := ReadStatus(w.paths.Work); err != nil || saved.State != StateUpToDate {
		t.Fatalf("saved status %+v %v", saved, err)
	}
}

// TestNoRootKeyInstallsNothing: the unsigned state of today.
func TestNoRootKeyInstallsNothing(t *testing.T) {
	w := newWorld(t, "1.0.0")
	w.publish("1.0.1")
	st, _ := w.runner("1.0.0", release.PublicKey{}).Check(context.Background())
	if st.State != StateWaitingKey || st.Action == "" || !strings.Contains(st.Message, "imzalama anahtarı") {
		t.Fatalf("status %+v", st)
	}
	if w.coord.chunks.Load() != 0 || w.triggers.Load() != 0 || exists(filepath.Join(w.paths.Work, RequestFile)) {
		t.Fatal("something was downloaded or requested without a root key")
	}
	// Installer refuses too, even with a request in place.
	if err := writeJSON(filepath.Join(w.paths.Work, RequestFile), Request{Format: requestFormat, Version: "1.0.1", Mode: ModeBinary, Manifest: "openscale-1.0.1.release.json", Payload: testArtifact + ".gz", Artifact: testArtifact, Compressed: true}); err != nil {
		t.Fatal(err)
	}
	_, err := Install(context.Background(), InstallOptions{Paths: w.paths, GOOS: "windows", GOARCH: "amd64",
		LoadRoot: func() (release.PublicKey, error) { return release.PublicKey{}, errors.New("no key") },
		Binary:   func() (updater.Options, error) { return updater.Options{Exe: w.exe}, nil }})
	if err == nil || !strings.Contains(err.Error(), "imzasız") {
		t.Fatalf("install without key: %v", err)
	}
	if v, _ := fakeVersion(context.Background(), w.exe); v != "1.0.0" {
		t.Fatal("program changed")
	}
}

// writeMirror puts files into the mirror as an untrusted coordinator might.
func (w *world) rawMirror(files map[string][]byte) {
	w.t.Helper()
	if err := os.MkdirAll(w.mirror, 0o700); err != nil {
		w.t.Fatal(err)
	}
	for n, d := range files {
		if err := os.WriteFile(filepath.Join(w.mirror, n), d, 0o600); err != nil {
			w.t.Fatal(err)
		}
	}
	w.coord.reload()
}

func readDist(t *testing.T, dir string) map[string][]byte {
	out := map[string][]byte{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if e.Name() == testArtifact {
			out[testArtifact+".gz"] = gz(t, data)
			continue
		}
		out[e.Name()] = data
	}
	return out
}

func expectRejected(t *testing.T, w *world, r *Runner, want string) {
	t.Helper()
	st, _ := r.Check(context.Background())
	if st.State != StateRejected || !strings.Contains(st.Message, want) {
		t.Fatalf("want rejection with %q, got %+v", want, st)
	}
	if w.triggers.Load() != 0 || exists(filepath.Join(w.paths.Work, RequestFile)) {
		t.Fatal("a rejected release reached the installer")
	}
	// Remembered: the next check does not fetch it again.
	before := w.coord.chunks.Load()
	if st, _ := r.Check(context.Background()); st.State != StateRejected || w.coord.chunks.Load() != before {
		t.Fatalf("second check: %+v", st)
	}
}

func TestRejections(t *testing.T) {
	t.Run("başka kökle imzalı", func(t *testing.T) {
		w := newWorld(t, "1.0.0")
		other := newKeys(t)
		w.rawMirror(readDist(t, other.dist(t, "1.0.1", program("1.0.1"))))
		expectRejected(t, w, w.runner("1.0.0", w.keys.root), "doğrulanamadı")
	})
	t.Run("iptal edilmiş imzalama anahtarı", func(t *testing.T) {
		w := newWorld(t, "1.0.0")
		w.publish("1.0.1")
		list, err := release.SignRevocations(w.keys.rootPriv, release.Revocations{Sequence: 1, Issued: time.Now(), Revoked: []release.RevokedKey{{SigningKey: w.keys.signing}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := updater.InstallRevocations(w.paths.UpdaterState, w.keys.root, list); err != nil {
			t.Fatal(err)
		}
		expectRejected(t, w, w.runner("1.0.0", w.keys.root), "revoked")
	})
	t.Run("koordinatör sürümü yanlış ilan ediyor (düşük sürüm)", func(t *testing.T) {
		w := newWorld(t, "1.0.1")
		files := readDist(t, w.keys.dist(t, "1.0.0", program("1.0.0")))
		manifest := files["openscale-1.0.0.release.json"]
		delete(files, "openscale-1.0.0.release.json")
		files["openscale-9.0.0.release.json"] = manifest
		w.rawMirror(files)
		expectRejected(t, w, w.runner("1.0.1", w.keys.root), "imzalı sürüm 1.0.0")
	})
	t.Run("eski sürüm ilanı kurulmaz", func(t *testing.T) {
		w := newWorld(t, "1.0.1")
		w.publish("1.0.0")
		if st, _ := w.runner("1.0.1", w.keys.root).Check(context.Background()); st.State != StateUpToDate || w.coord.chunks.Load() != 0 {
			t.Fatalf("%+v", st)
		}
	})
	t.Run("beta kararlı kanalda kurulmaz", func(t *testing.T) {
		w := newWorld(t, "1.0.0")
		w.publish("1.0.1-beta.1")
		expectRejected(t, w, w.runner("1.0.0", w.keys.root), "önsürüm")
	})
	t.Run("değiştirilmiş program", func(t *testing.T) {
		w := newWorld(t, "1.0.0")
		files := readDist(t, w.keys.dist(t, "1.0.1", program("1.0.1")))
		evil := program("1.0.1")
		evil[len(evil)-1] ^= 1
		files[testArtifact+".gz"] = gz(t, evil)
		w.rawMirror(files)
		expectRejected(t, w, w.runner("1.0.0", w.keys.root), "does not match")
	})
}

func TestBetaChannelInstallsBeta(t *testing.T) {
	w := newWorld(t, "1.0.0-beta.1")
	if err := updater.WriteChannel(w.paths.UpdaterState, updater.ChannelBeta); err != nil {
		t.Fatal(err)
	}
	w.publish("1.0.0-beta.2")
	if st, _ := w.runner("1.0.0-beta.1", w.keys.root).Check(context.Background()); st.State != StateInstalling {
		t.Fatalf("%+v", st)
	}
	if _, err := w.install("1.0.0-beta.1"); err != nil {
		t.Fatal(err)
	}
}

// TestInstallerVerifiesAgain: a cache changed after the device's check
// (the device process is not trusted by the installer) is refused.
func TestInstallerVerifiesAgain(t *testing.T) {
	w := newWorld(t, "1.0.0")
	w.publish("1.0.1")
	if st, _ := w.runner("1.0.0", w.keys.root).Check(context.Background()); st.State != StateInstalling {
		t.Fatalf("%+v", st)
	}
	evil := program("1.0.1")
	evil[100] ^= 1
	if err := os.WriteFile(filepath.Join(w.paths.Work, CacheDir, testArtifact+".gz"), gz(t, evil), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.install("1.0.0"); err == nil {
		t.Fatal("tampered cache installed")
	}
	if v, _ := fakeVersion(context.Background(), w.exe); v != "1.0.0" {
		t.Fatal("program changed")
	}
	res, err := readResult(w.paths.Work)
	if err != nil || res.OK {
		t.Fatalf("result %+v %v", res, err)
	}
	// The device remembers the failure and does not retry at once.
	if st, _ := w.runner("1.0.0", w.keys.root).Check(context.Background()); st.State != StateRejected || st.LastAttempt == nil || st.LastAttempt.OK {
		t.Fatalf("%+v", st)
	}
	if _, err := w.install("1.0.0"); !errors.Is(err, ErrNoRequest) {
		t.Fatalf("no request expected: %v", err)
	}
}

func TestSwitchAndUnsupported(t *testing.T) {
	w := newWorld(t, "1.0.0")
	w.publish("1.0.1")
	r := w.runner("1.0.0", w.keys.root)
	if st, err := r.SetEnabled(false); err != nil || st.Enabled || st.State != StateOff {
		t.Fatalf("%+v %v", st, err)
	}
	if st, _ := r.Check(context.Background()); st.State != StateOff || w.coord.chunks.Load() != 0 {
		t.Fatalf("%+v", st)
	}
	if s, err := ReadSettings(w.paths.Settings); err != nil || s.Enabled {
		t.Fatalf("%+v %v", s, err)
	}
	// Default on: no file.
	if s, err := ReadSettings(filepath.Join(t.TempDir(), SettingsFile)); err != nil || !s.Enabled {
		t.Fatalf("default %+v %v", s, err)
	}
	u := New(Config{Paths: Paths{Reason: "desteklenmiyor"}, Installed: "1.0.0"})
	if st, _ := u.Check(context.Background()); st.State != StateUnsupported {
		t.Fatalf("%+v", st)
	}
	if _, err := u.SetEnabled(true); err == nil {
		t.Fatal("unsupported switch")
	}
}

func TestPublishRefusesUnsignedAndBadSignature(t *testing.T) {
	k := newKeys(t)
	state := t.TempDir()
	unsigned := t.TempDir()
	if err := os.WriteFile(filepath.Join(unsigned, testArtifact), program("1.0.1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(PublishOptions{Dist: unsigned, StateDir: state, Root: k.root}); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("unsigned: %v", err)
	}
	if _, err := Publish(PublishOptions{Dist: newKeys(t).dist(t, "1.0.1", program("1.0.1")), StateDir: state, Root: k.root}); err == nil {
		t.Fatal("foreign signature published")
	}
	dir := k.dist(t, "1.0.1", program("1.0.1"))
	if err := os.WriteFile(filepath.Join(dir, testArtifact), program("1.0.2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(PublishOptions{Dist: dir, StateDir: state, Root: k.root}); err == nil {
		t.Fatal("changed program published")
	}
	if exists(filepath.Join(state, coordinator.ReleaseMirrorDir, "openscale-1.0.1.release.json")) {
		t.Fatal("manifest announced after a failed publication")
	}
}

func TestArtifactFor(t *testing.T) {
	cases := []struct{ mode, goos, goarch, want, mirror string }{
		{ModeBinary, "windows", "amd64", "openscale-windows-amd64.exe", "openscale-windows-amd64.exe.gz"},
		{ModeBinary, "linux", "arm", "openscale-linux-armv7", "openscale-linux-armv7.gz"},
		{ModeDeb, "linux", "amd64", "openscale_1.0.0~beta.2_amd64.deb", "openscale_1.0.0~beta.2_amd64.deb"},
		{ModeDeb, "linux", "arm", "openscale_1.0.0~beta.2_armhf.deb", "openscale_1.0.0~beta.2_armhf.deb"},
	}
	for _, c := range cases {
		a, m, _, err := ArtifactFor(c.mode, c.goos, c.goarch, "1.0.0-beta.2")
		if err != nil || a != c.want || m != c.mirror {
			t.Errorf("%v: %s %s %v", c, a, m, err)
		}
		if _, ok := coordinator.MirrorFileAllowed(m); !ok {
			t.Errorf("mirror does not serve %s", m)
		}
	}
	if _, _, _, err := ArtifactFor(ModeDeb, "windows", "amd64", "1.0.0"); err == nil {
		t.Error("deb on windows")
	}
}
