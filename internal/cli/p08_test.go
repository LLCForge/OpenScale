package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

var (
	leaveLine = regexp.MustCompile(`osleave1\.[A-Za-z0-9_-]+`)
	rootLine  = regexp.MustCompile(`osroot1\.[A-Za-z0-9_-]+`)
)

func TestP08InviteCommands(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	var key trust.Key
	key[0] = 7
	fp := trust.CoordinatorFingerprint(key)
	h.run(exitOK, "network", "set-coordinator", "--dir", h.netDir, "--endpoint", "127.0.0.1:41820",
		"--wireguard-key", key.String(), "--fingerprint", fp, pass)
	out := h.run(exitOK, "invite", "create", "--dir", h.netDir, "--uses", "3", "--note", "Ayşe", pass)
	if !strings.Contains(out, "en fazla 3 cihaz") {
		t.Fatalf("invite create output: %s", out)
	}
	out = h.run(exitOK, "invite", "list", "--dir", h.netDir)
	if !strings.Contains(out, "0/3 kullanıldı") || !strings.Contains(out, "Ayşe") {
		t.Fatalf("invite list output: %s", out)
	}
	h.run(exitUsage, "invite", "create", "--dir", h.netDir, "--uses", "0", pass)
	data, _ := os.ReadFile(filepath.Join(h.netDir, "network.json"))
	if strings.Contains(string(data), "Ayşe") {
		t.Fatal("note leaked into the signed document")
	}
}

func TestP08PreauthLeaveAndRoot(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)

	// A preauthorized key joins a server without interaction.
	keyFile := filepath.Join(t.TempDir(), "ci.key")
	out := h.run(exitOK, "device", "preauth", "--dir", h.netDir, "--name", "ci", "--tags", "ci", "--ephemeral", "--out", keyFile, pass)
	if !strings.Contains(out, "ön onaylı") {
		t.Fatalf("preauth output:\n%s", out)
	}
	state := filepath.Join(t.TempDir(), "ci-state")
	out = h.run(exitOK, "preauth-join", "--key", "@"+keyFile, "--state-dir", state)
	if !strings.Contains(out, "ön onaylı kayıtla") {
		t.Fatalf("preauth-join output:\n%s", out)
	}
	if _, err := member.Open(state); err != nil {
		t.Fatalf("joined state: %v", err)
	}

	// Rotating the root: the joined server follows with root apply.
	recFile := filepath.Join(t.TempDir(), "kurtarma.txt")
	if err := securefile.WriteNew(recFile, []byte("başka bir kurtarma parolası 9\n")); err != nil {
		t.Fatal(err)
	}
	recOut := filepath.Join(t.TempDir(), "recovery.key")
	h.run(exitOK, "network", "recovery-key", "add", "--dir", h.netDir, "--out", recOut, pass, "--recovery-passphrase-file", recFile)
	out = h.run(exitOK, "network", "rotate-root", "--dir", h.netDir, "--confirm", "YENIKOK", pass)
	line := rootLine.FindString(out)
	if line == "" {
		t.Fatalf("rotate-root output:\n%s", out)
	}
	out = h.run(exitOK, "network", "transitions", "--dir", h.netDir)
	if !strings.Contains(out, "dönem 1") {
		t.Fatalf("transitions:\n%s", out)
	}
	// The server joined before the recovery key was published: give it the
	// version with the key first, then the rotation.
	h.run(exitOK, "root", "apply", "--state-dir", state, "--transitions", line, "--document", filepath.Join(h.netDir, "network.json"))
	st, err := member.Open(state)
	if err != nil || st.Epoch() != 1 {
		t.Fatalf("server not on the new root: %v", err)
	}
	h.run(exitOK, "network", "verify", "--dir", h.netDir)

	// The server leaves: its key is deleted and the owner applies the line.
	out = h.run(exitOK, "leave", "--state-dir", state, "--confirm", "AYRIL")
	req := leaveLine.FindString(out)
	if req == "" {
		t.Fatalf("leave output:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(state, "device.key")); !os.IsNotExist(err) {
		t.Fatal("device key not deleted")
	}
	out = h.run(exitOK, "device", "leave-apply", "--dir", h.netDir, "--request", req, pass)
	if !strings.Contains(out, "- cihaz ci") {
		t.Fatalf("leave-apply output:\n%s", out)
	}

	// Invites with uses and a local note.
	h.run(exitOK, "network", "min-version", "--dir", h.netDir, "--version", "1.2.3", pass)
	h.run(exitUsage, "network", "min-version", "--dir", h.netDir)
}
