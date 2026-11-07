package updater

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestChannelFileRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "update")
	if ch, err := ReadChannel(dir); err != nil || ch != ChannelStable {
		t.Fatalf("default = %q, %v", ch, err)
	}
	if err := WriteChannel(dir, "Beta"); err != nil {
		t.Fatal(err)
	}
	if ch, err := ReadChannel(dir); err != nil || ch != ChannelBeta {
		t.Fatalf("after write = %q, %v", ch, err)
	}
	if err := WriteChannel(dir, "nightly"); err == nil {
		t.Fatal("unknown channel accepted")
	}
	// A damaged or unexpected file means stable.
	for _, bad := range []string{`{"channel":"beta","x":1}`, `{"channel":"gece"}`, `bozuk`} {
		if err := os.WriteFile(filepath.Join(dir, ChannelFile), []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if ch, err := ReadChannel(dir); err == nil || ch != ChannelStable {
			t.Fatalf("%s: %q, %v", bad, ch, err)
		}
		if prereleaseAllowed(Options{StateDir: dir}) {
			t.Fatalf("%s: damaged file allowed a pre-release", bad)
		}
	}
}

func TestCheckChannel(t *testing.T) {
	if err := CheckChannel("1.0.0-beta.2", false); !errors.Is(err, ErrPrerelease) {
		t.Fatalf("beta without channel: %v", err)
	}
	if err := CheckChannel("1.0.0-rc.1", false); !errors.Is(err, ErrPrerelease) {
		t.Fatalf("any pre-release is refused: %v", err)
	}
	if err := CheckChannel("1.0.0-beta.2", true); err != nil {
		t.Fatal(err)
	}
	if err := CheckChannel("1.0.0", false); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRefusesBetaUnlessChosen(t *testing.T) {
	f := newFixture(t)
	dir := f.release("0.9.0-beta.1", program("0.9.0-beta.1", "ok"))
	if _, err := f.apply(f.opts(), dir); !errors.Is(err, ErrPrerelease) {
		t.Fatalf("Apply = %v, want ErrPrerelease", err)
	}
	if f.installedVersion() != "0.8.0" {
		t.Fatal("installed program changed")
	}
	if err := WriteChannel(f.state, ChannelBeta); err != nil {
		t.Fatal(err)
	}
	if _, err := f.apply(f.opts(), dir); err != nil {
		t.Fatalf("beta channel: %v", err)
	}
	if f.installedVersion() != "0.9.0-beta.1" {
		t.Fatalf("installed %s", f.installedVersion())
	}
}
