package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func p01Network(t *testing.T) (*harness, string) {
	t.Helper()
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	for _, name := range []string{"laptop", "masaustu"} {
		req, fp := h.keygen(filepath.Join(t.TempDir(), name), name)
		h.run(exitOK, "device", "add", "--dir", h.netDir, "--request", req, "--fingerprint", fp, pass)
	}
	return h, pass
}

func TestCLIDraftSignsOnce(t *testing.T) {
	h, pass := p01Network(t) // v3
	out := h.run(exitOK, "device", "rename", "--dir", h.netDir, "--name", "laptop", "--new-name", "dizustu", "--draft")
	if !strings.Contains(out, "Taslağa eklendi") {
		t.Fatalf("stage:\n%s", out)
	}
	h.run(exitOK, "device", "tag", "--dir", h.netDir, "--name", "dizustu", "--tags", "is", "--draft")
	out = h.run(exitOK, "network", "draft", "show", "--dir", h.netDir)
	if !strings.Contains(out, "düzenleme") {
		t.Fatalf("show:\n%s", out)
	}
	out = h.run(exitOK, "network", "show", "--dir", h.netDir)
	if !strings.Contains(out, "sürüm 3") || !strings.Contains(out, "Bekleyen değişiklik taslağı") {
		t.Fatalf("staging must not sign:\n%s", out)
	}
	out = h.run(exitOK, "network", "draft", "sign", "--dir", h.netDir, pass)
	if !strings.Contains(out, "sürüm 4") {
		t.Fatalf("sign:\n%s", out)
	}
	out = h.run(exitOK, "network", "draft", "show", "--dir", h.netDir)
	if !strings.Contains(out, "taslağı yok") {
		t.Fatalf("after sign:\n%s", out)
	}
	h.run(exitError, "network", "draft", "discard", "--dir", h.netDir)
}

func TestCLILockdownNeedsConfirmation(t *testing.T) {
	h, pass := p01Network(t)
	out := h.run(exitUsage, "network", "lockdown", "--dir", h.netDir, "--state", "on", pass)
	if !strings.Contains(out, "ÖNCEKİ KURALLARLA") {
		t.Fatalf("missing old device warning:\n%s", out)
	}
	h.run(exitOK, "network", "lockdown", "--dir", h.netDir, "--state", "on", "--reason", "deneme", "--yes", pass)
	out = h.run(exitOK, "network", "show", "--dir", h.netDir)
	if !strings.Contains(out, "ACİL KİLİT AÇIK") {
		t.Fatalf("show:\n%s", out)
	}
	out = h.run(exitOK, "network", "lockdown", "--dir", h.netDir, "--state", "off", pass)
	if !strings.Contains(out, "Acil kilit: kaldırıldı") {
		t.Fatalf("off:\n%s", out)
	}
}

func TestCLILedgerLimitsArtBulkKeyAge(t *testing.T) {
	h, pass := p01Network(t)
	out := h.run(exitOK, "network", "ledger", "--dir", h.netDir)
	if !strings.Contains(out, "3 kayıt") {
		t.Fatalf("ledger:\n%s", out)
	}
	out = h.run(exitOK, "network", "ledger", "--dir", h.netDir, "--check", filepath.Join(h.netDir, "network.json"))
	if !strings.Contains(out, "bu klasörde imzalandı") {
		t.Fatalf("check:\n%s", out)
	}
	out = h.run(exitOK, "network", "limits", "--dir", h.netDir)
	if !strings.Contains(out, "cihaz") {
		t.Fatalf("limits:\n%s", out)
	}
	out = h.run(exitOK, "network", "fingerprint-art", "--dir", h.netDir)
	if !strings.Contains(out, "[KÖK]") || !strings.Contains(out, "[laptop]") {
		t.Fatalf("art:\n%s", out)
	}
	out = h.run(exitOK, "device", "bulk", "--dir", h.netDir, "--names", "laptop,masaustu", "--add-tags", "ofis", pass)
	if !strings.Contains(out, "sürüm 4") {
		t.Fatalf("bulk:\n%s", out)
	}
	h.run(exitUsage, "device", "bulk", "--dir", h.netDir, "--names", "laptop", pass)
	h.run(exitUsage, "network", "key-age", "--dir", h.netDir, "--days", "90", pass)
	h.run(exitOK, "network", "key-age", "--dir", h.netDir, "--days", "90", "--yes", pass)
	out = h.run(exitOK, "device", "key-age", "--dir", h.netDir)
	if !strings.Contains(out, "en çok 90 gün") {
		t.Fatalf("key-age:\n%s", out)
	}
	h.run(exitUsage, "network", "revoked-compact", "--dir", h.netDir, pass)
}
