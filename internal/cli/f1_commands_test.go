package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

func TestNetworkMembersOnlyCommand(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)

	h.run(exitUsage, "network", "members-only", "--dir", h.netDir)
	h.run(exitUsage, "network", "members-only", "--dir", h.netDir, "--show", "--set", "on")
	h.run(exitUsage, "network", "members-only", "--set", "on")
	// No device yet: it cannot be sealed.
	if out := h.run(exitError, "network", "members-only", "--dir", h.netDir, "--set", "on", pass); !strings.Contains(out, "en az bir cihaz") {
		t.Fatalf("blocked:\n%s", out)
	}

	req, fp := h.keygen(filepath.Join(t.TempDir(), "laptop"), "laptop")
	h.run(exitOK, "device", "add", "--dir", h.netDir, "--request", req, "--fingerprint", fp, pass)

	out := h.run(exitOK, "network", "members-only", "--dir", h.netDir, "--set", "on", "--dry-run", pass)
	if !strings.Contains(out, "Asgari istemci sürümü") || !strings.Contains(out, "imzalanmadı") {
		t.Fatalf("dry run:\n%s", out)
	}
	out = h.run(exitOK, "network", "members-only", "--dir", h.netDir, "--show")
	if !strings.Contains(out, "Üyelere mühürlü belge: kapalı") {
		t.Fatalf("show after dry run:\n%s", out)
	}
	out = h.run(exitOK, "network", "members-only", "--dir", h.netDir, "--set", "on", pass)
	if !strings.Contains(out, "imzalandı") || !strings.Contains(out, "coordinator harden --blind on") {
		t.Fatalf("on:\n%s", out)
	}
	data, err := securefile.ReadPrivate(filepath.Join(h.netDir, "network.json"), trust.MaxEnvelopeSize)
	if err != nil {
		t.Fatal(err)
	}
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(env.Payload), `"laptop"`) || !strings.Contains(string(env.Payload), "members_only") {
		t.Fatalf("network.json is not sealed:\n%s", env.Payload)
	}
	if out := h.run(exitOK, "network", "members-only", "--dir", h.netDir, "--set", "on", pass); !strings.Contains(out, "zaten") {
		t.Fatalf("on while on:\n%s", out)
	}
	out = h.run(exitOK, "network", "members-only", "--dir", h.netDir, "--set", "off", pass)
	if !strings.Contains(out, "kapalı") {
		t.Fatalf("off:\n%s", out)
	}
	data, err = securefile.ReadPrivate(filepath.Join(h.netDir, "network.json"), trust.MaxEnvelopeSize)
	if err != nil {
		t.Fatal(err)
	}
	if env, err = trust.UnmarshalEnvelope(data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(env.Payload), `"laptop"`) {
		t.Fatalf("network.json is still sealed:\n%s", env.Payload)
	}
}

func TestAdminOvertakeCommand(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	out := h.run(exitOK, "admin", "overtake", "--dir", h.netDir, pass)
	if !strings.Contains(out, "sürüm 65539") {
		t.Fatalf("overtake:\n%s", out)
	}
}

func TestUpdateRevocationsCommand(t *testing.T) {
	h := newHarness(t)
	work := t.TempDir()
	dir := filepath.Join(work, "update")
	root, rootPriv, err := release.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := release.PublicKeyFrom(pub)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, seq uint64) string {
		data, err := release.SignRevocations(rootPriv, release.Revocations{Sequence: seq, Issued: time.Now(),
			Revoked: []release.RevokedKey{{SigningKey: signing, Reason: "sizdi"}}})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(work, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	h.run(exitUsage, "update", "revocations", "--root-key", root.String(), "--update-dir", dir)
	out := h.run(exitOK, "update", "revocations", "--show", "--root-key", root.String(), "--update-dir", dir)
	if !strings.Contains(out, "iptal listesi yok") {
		t.Fatalf("show empty:\n%s", out)
	}
	out = h.run(exitOK, "update", "revocations", "--file", write("v2.json", 2), "--root-key", root.String(), "--update-dir", dir)
	if !strings.Contains(out, "sıra 2") || !strings.Contains(out, signing.Fingerprint()) {
		t.Fatalf("install:\n%s", out)
	}
	out = h.run(exitOK, "update", "revocations", "--show", "--root-key", root.String(), "--update-dir", dir)
	if !strings.Contains(out, "sıra 2") {
		t.Fatalf("show:\n%s", out)
	}
	h.run(exitError, "update", "revocations", "--file", write("v1.json", 1), "--root-key", root.String(), "--update-dir", dir)
}
