package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/qr"
)

func TestDeviceAddFromQRImage(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	req, fp := h.keygen(filepath.Join(t.TempDir(), "telefon"), "telefon")

	// A screenshot of the phone's enrollment QR code.
	code, err := qr.EncodeText(req, qr.L)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := code.PNG(&buf, 5); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(t.TempDir(), "istek.png")
	if err := os.WriteFile(img, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	out := h.run(exitUsage, "device", "add", "--dir", h.netDir, "--request", req, "--request-image", img, "--fingerprint", fp, pass)
	if !strings.Contains(out, "birlikte") {
		t.Fatalf("both sources accepted:\n%s", out)
	}
	out = h.run(exitOK, "device", "add", "--dir", h.netDir, "--request-image", img, "--fingerprint", fp, pass)
	if !strings.Contains(out, "+ cihaz telefon") {
		t.Fatalf("unexpected output:\n%s", out)
	}

	// A QR code whose text starts with "@" is not read as a file name.
	code, _ = qr.EncodeText("@"+h.passFile, qr.L)
	buf.Reset()
	_ = code.PNG(&buf, 5)
	evil := filepath.Join(t.TempDir(), "kotu.png")
	if err := os.WriteFile(evil, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	h.run(exitError, "device", "add", "--dir", h.netDir, "--request-image", evil, "--fingerprint", fp, pass)

	notImage := filepath.Join(t.TempDir(), "metin.png")
	if err := os.WriteFile(notImage, []byte("osreq1.x"), 0o600); err != nil {
		t.Fatal(err)
	}
	out = h.run(exitError, "device", "add", "--dir", h.netDir, "--request-image", notImage, "--fingerprint", fp, pass)
	if !strings.Contains(out, "PNG veya JPEG") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}
