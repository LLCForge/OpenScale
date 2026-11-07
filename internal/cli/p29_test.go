package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/posture"
	"github.com/openscale/openscale/internal/stealth"
)

func TestParseRequirement(t *testing.T) {
	q, err := parseRequirement("disk, firewall,build=26100")
	if err != nil || q != (posture.Requirement{DiskEncryption: true, Firewall: true, MinWindowsBuild: 26100}) {
		t.Fatalf("parseRequirement = %+v, %v", q, err)
	}
	for _, bad := range []string{"tpm", "build=x", "build=0", "build=-5"} {
		if _, err := parseRequirement(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if q, err := parseRequirement(""); err != nil || !q.IsZero() {
		t.Fatalf("empty = %+v, %v", q, err)
	}
}

func TestStealthCommandKeepsProtectionsNote(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	env := &Env{Stdout: &out, Stderr: &errOut, Now: time.Now}
	if code := Run([]string{"stealth", "on", "--notifications=false", "--data-dir", dir}, env); code != exitOK {
		t.Fatalf("stealth on exit %d: %s", code, errOut.String())
	}
	s, err := stealth.Load(dir)
	if err != nil || !s.HideTray || s.QuietNotifications {
		t.Fatalf("saved = %+v, %v", s, err)
	}
	if !strings.Contains(out.String(), "Kill switch") {
		t.Fatalf("output lacks the protections note: %s", out.String())
	}
	if code := Run([]string{"stealth", "off", "--data-dir", dir}, env); code != exitOK {
		t.Fatalf("stealth off exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, stealth.FileName)); !os.IsNotExist(err) {
		t.Fatalf("file left behind: %v", err)
	}
	if code := Run([]string{"stealth", "on", "--tray=false", "--notifications=false", "--data-dir", dir}, env); code != exitUsage {
		t.Fatalf("empty stealth accepted: %d", code)
	}
}

func TestMsgSendRejectsBadInput(t *testing.T) {
	var out, errOut bytes.Buffer
	env := &Env{Stdout: &out, Stderr: &errOut, Now: time.Now}
	if code := Run([]string{"msg", "send", "phone"}, env); code != exitUsage {
		t.Fatalf("missing text: exit %d", code)
	}
	if code := Run([]string{"msg", "send", "phone", strings.Repeat("x", 5000)}, env); code != exitUsage {
		t.Fatalf("long text: exit %d", code)
	}
}
