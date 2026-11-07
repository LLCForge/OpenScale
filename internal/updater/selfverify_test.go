package updater

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func sig(st SignatureState, err error) func(string) (SignatureState, error) {
	return func(string) (SignatureState, error) { return st, err }
}

func TestVerifySelfManifest(t *testing.T) {
	f := newFixture(t)
	dir := f.release("0.9.0", program("0.9.0", "ok"))
	if _, err := f.apply(f.opts(), dir); err != nil {
		t.Fatal(err)
	}
	cfg := SelfVerifyConfig{Exe: f.exe, StateDir: f.state, Root: &f.root, Now: f.now, Signature: sig(SignatureAbsent, nil)}
	v := VerifySelf(cfg)
	if v.Block || !v.ManifestChecked || v.Manifest != "0.9.0" || v.Err() != nil {
		t.Fatalf("matching program: %+v", v)
	}
	// A replaced program is blocked.
	if err := os.WriteFile(f.exe, program("0.9.0", "evil"), 0o755); err != nil {
		t.Fatal(err)
	}
	v = VerifySelf(cfg)
	if !v.Block || !errors.Is(v.Err(), ErrSelfVerify) {
		t.Fatalf("tampered program: %+v", v)
	}
	// A broken platform signature blocks even without a manifest.
	v = VerifySelf(SelfVerifyConfig{Exe: f.exe, Signature: sig(SignatureInvalid, errors.New("sertifika zinciri"))})
	if !v.Block {
		t.Fatalf("invalid signature: %+v", v)
	}
	// No manifest, unsigned: allowed (hand-installed development build).
	v = VerifySelf(SelfVerifyConfig{Exe: f.exe, StateDir: filepath.Join(f.dir, "yok"), Root: &f.root, Now: f.now, Signature: sig(SignatureAbsent, nil)})
	if v.Block || v.ManifestChecked {
		t.Fatalf("no manifest: %+v", v)
	}
	// A damaged saved manifest blocks.
	if err := os.WriteFile(filepath.Join(f.state, InstalledManifestFile), []byte("bozuk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v := VerifySelf(cfg); !v.Block {
		t.Fatalf("damaged manifest: %+v", v)
	}
	if v := VerifySelf(SelfVerifyConfig{}); v.Block {
		t.Fatal("empty exe blocked")
	}
}

func TestPlatformSignatureOnTestBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	st, err := PlatformSignature(exe)
	switch runtime.GOOS {
	case "windows":
		// A test binary built here is not signed.
		if st != SignatureAbsent {
			t.Fatalf("test binary: %v, %v", st, err)
		}
	default:
		t.Logf("%s: %v %v", runtime.GOOS, st, err)
	}
	t.Setenv(SelfVerifyEnv, "OFF")
	if !SelfVerifyDisabled() {
		t.Fatal("env not honoured")
	}
}

// A program with an embedded Microsoft signature verifies offline
// (read-only check on this computer when Edge is installed).
func TestPlatformSignatureSignedFile(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	p := filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe")
	if _, err := os.Stat(p); err != nil {
		t.Skip("Edge not installed")
	}
	if st, err := PlatformSignature(p); st != SignatureValid {
		t.Fatalf("msedge.exe: %v, %v", st, err)
	}
}
