package posture

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExtendedEncodeDecode(t *testing.T) {
	x := Extended{SecureBoot: On, TPM: Off, ScreenLock: On, LockMinutes: 10, Disk: On}
	s := x.Encode()
	if len(s) > MaxEncodedExtended {
		t.Fatalf("too long: %q", s)
	}
	got, err := DecodeExtended(s)
	if err != nil || got != x {
		t.Fatalf("round trip %q -> %+v %v", s, got, err)
	}
	for _, bad := range []string{"sb=x", "sb=y;sb=y", "zz=y", "lm=0", "lm=07", strings.Repeat("a", 50)} {
		if _, err := DecodeExtended(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	// The old field is untouched: Decode still rejects the new keys, so
	// the new statement must travel in its own field.
	if _, err := Decode("sb=y"); err == nil {
		t.Fatal("old decoder accepted new keys")
	}
}

func TestClassifyAndScreenLock(t *testing.T) {
	strong := Report{DiskEncryption: On, Firewall: On}
	if g, _ := Classify(strong, Extended{SecureBoot: On, ScreenLock: On, LockMinutes: 5}); g != GradeStrong {
		t.Fatalf("strong graded %s", g)
	}
	g, why := Classify(strong, Extended{ScreenLock: On, LockMinutes: 30})
	if g != GradeWeak || len(why) != 1 {
		t.Fatalf("slow lock: %s %v", g, why)
	}
	if g, _ := Classify(Report{}, Extended{}); g != GradeUnknown {
		t.Fatalf("empty graded %s", g)
	}
	if g, _ := Classify(Report{}, Extended{Disk: Off}); g != GradeWeak {
		t.Fatal("FileVault off not weak")
	}
	if u := EvaluateExtended(BootRequirement{ScreenLock: true}, Extended{ScreenLock: On, LockMinutes: 16}); len(u) != 1 {
		t.Fatalf("16 minutes accepted: %v", u)
	}
	if u := EvaluateExtended(BootRequirement{ScreenLock: true, SecureBoot: true, TPM: true}, Extended{ScreenLock: On, LockMinutes: 15, SecureBoot: On, TPM: On}); len(u) != 0 {
		t.Fatalf("good device refused: %v", u)
	}
}

func TestRuleConditionInternetOnly(t *testing.T) {
	c := RuleCondition{Require: Requirement{DiskEncryption: true}, OnFail: OutcomeInternetOnly}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if o, _ := c.Decide(Report{DiskEncryption: On}, Extended{}); o != OutcomeAllow {
		t.Fatalf("encrypted: %s", o)
	}
	if o, unmet := c.Decide(Report{DiskEncryption: Off}, Extended{}); o != OutcomeInternetOnly || len(unmet) != 1 {
		t.Fatalf("plain disk: %s %v", o, unmet)
	}
	// FileVault from the extended statement counts.
	if o, _ := c.Decide(Report{}, Extended{Disk: On}); o != OutcomeAllow {
		t.Fatalf("filevault: %s", o)
	}
	if o, _ := (RuleCondition{Boot: BootRequirement{SecureBoot: true}}).Decide(Report{}, Extended{}); o != OutcomeDeny {
		t.Fatalf("unknown secure boot: %s", o)
	}
	if (RuleCondition{OnFail: "maybe"}).Validate() == nil {
		t.Fatal("bad outcome accepted")
	}
}

func TestPlatformParsers(t *testing.T) {
	if ParseEFISecureBoot([]byte{6, 0, 0, 0, 1}) != On || ParseEFISecureBoot([]byte{6, 0, 0, 0, 0}) != Off || ParseEFISecureBoot(nil) != Unknown {
		t.Fatal("efi")
	}
	if s, m := WindowsScreenLock(900, "", "", ""); s != On || m != 15 {
		t.Fatal("policy")
	}
	if s, m := WindowsScreenLock(-1, "1", "1", "600"); s != On || m != 10 {
		t.Fatal("screensaver")
	}
	if s, _ := WindowsScreenLock(-1, "1", "0", "600"); s != Off {
		t.Fatal("insecure screensaver")
	}
	if s, _ := WindowsScreenLock(-1, "", "", ""); s != Unknown {
		t.Fatal("absent")
	}
	if s, m := GnomeScreenLock("true\n", "uint32 300\n"); s != On || m != 5 {
		t.Fatal("gnome")
	}
	if s, _ := GnomeScreenLock("true", "uint32 0"); s != Off {
		t.Fatal("gnome never")
	}
	if s, m := MacScreenLock("screenLock delay is 300 seconds"); s != On || m != 5 {
		t.Fatal("mac")
	}
	if s, _ := MacScreenLock("screenLock is off"); s != Off {
		t.Fatal("mac off")
	}
	if MacFileVault("FileVault is On.\n") != On || MacFileVault("FileVault is Off.") != Off || MacFileVault("") != Unknown {
		t.Fatal("filevault")
	}
}

type sinkFunc func(TamperEvent) error

func (f sinkFunc) PublishTamper(e TamperEvent) error { return f(e) }

func TestTamperWatcher(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "openscale.exe")
	netDir := filepath.Join(root, "network")
	if err := os.MkdirAll(netDir, 0o700); err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(bin, []byte("v1"), 0o600))
	must(os.WriteFile(filepath.Join(netDir, "anchor.json"), []byte("{}"), 0o600))
	pub, priv, _ := ed25519.GenerateKey(nil)
	var published []TamperEvent
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	cfg := TamperConfig{Device: "laptop", Paths: []string{bin, netDir}, StateDir: filepath.Join(root, "state"), Key: priv,
		Sink: sinkFunc(func(e TamperEvent) error { published = append(published, e); return nil }), Now: func() time.Time { return now }}
	w, err := OpenTamperWatcher(cfg)
	must(err)
	if ev, err := w.Check(); err != nil || len(ev) != 0 {
		t.Fatalf("clean check: %v %v", ev, err)
	}
	// An update OpenScale made itself is accepted first.
	must(os.WriteFile(bin, []byte("v2"), 0o600))
	must(w.Accept(bin))
	if ev, _ := w.Check(); len(ev) != 0 {
		t.Fatal("accepted change reported")
	}
	// An outside change, a new file and a removal.
	must(os.WriteFile(bin, []byte("evil"), 0o600))
	must(os.WriteFile(filepath.Join(netDir, "extra.json"), []byte("x"), 0o600))
	must(os.Remove(filepath.Join(netDir, "anchor.json")))
	ev, err := w.Check()
	must(err)
	if len(ev) != 3 || len(published) != 3 {
		t.Fatalf("events %+v", ev)
	}
	for _, e := range ev {
		if !e.Verify(pub) || e.Validate() != nil {
			t.Fatalf("bad event %+v", e)
		}
	}
	// A reopened watcher continues the chain.
	w2, err := OpenTamperWatcher(cfg)
	must(err)
	must(os.WriteFile(bin, []byte("evil2"), 0o600))
	if ev, _ := w2.Check(); len(ev) != 1 || ev[0].Seq != 4 {
		t.Fatalf("reopened: %+v", ev)
	}
	logBytes, err := os.ReadFile(filepath.Join(cfg.StateDir, tamperLogFile))
	must(err)
	if got, err := VerifyTamperLog(bytes.NewReader(logBytes), pub); err != nil || len(got) != 4 {
		t.Fatalf("verify: %d %v", len(got), err)
	}
	// Removing a line breaks the chain.
	lines := bytes.SplitAfter(logBytes, []byte("\n"))
	cut := append(append([]byte{}, lines[0]...), bytes.Join(lines[2:], nil)...)
	if _, err := VerifyTamperLog(bytes.NewReader(cut), pub); err == nil {
		t.Fatal("cut log verified")
	}
	// Another key does not verify.
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := VerifyTamperLog(bytes.NewReader(logBytes), other); err == nil {
		t.Fatal("foreign key verified")
	}
}

func FuzzDecodeExtended(f *testing.F) {
	f.Add("sb=y;tp=n;sl=u;lm=10;fv=y")
	f.Fuzz(func(t *testing.T, s string) {
		x, err := DecodeExtended(s)
		if err != nil {
			return
		}
		if y, err := DecodeExtended(x.Encode()); err != nil || y != x {
			t.Fatalf("re-encode of %q differs", s)
		}
	})
}
