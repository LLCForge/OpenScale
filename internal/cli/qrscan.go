package cli

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg" // photos of a phone screen
	_ "image/png"  // screenshots
	"strings"
	"unicode/utf8"

	"github.com/openscale/openscale/internal/qr"
	"github.com/openscale/openscale/internal/securefile"
)

// QR registration (#182, P27): the phone shows its enrollment request as a
// QR code; the owner's computer reads a photo or screenshot of it with the
// pure Go decoder. The owner then still compares the fingerprint or SAS as
// for a pasted request.

// maxQRImageFile bounds the image file read for a QR code.
const maxQRImageFile = 20 << 20

// readQRImage decodes the QR code in a PNG or JPEG file.
func readQRImage(path string) (string, error) {
	data, err := securefile.ReadLimited(path, maxQRImageFile)
	if err != nil {
		return "", fmt.Errorf("görüntü okunamadı: %w", err)
	}
	// Check the size before decoding the pixels.
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("görüntü PNG veya JPEG değil: %w", err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > qr.MaxDecodeSide || cfg.Height > qr.MaxDecodeSide || cfg.Width*cfg.Height > qr.MaxDecodePixels {
		return "", fmt.Errorf("görüntü çok büyük (en fazla %d×%d piksel)", qr.MaxDecodeSide, qr.MaxDecodeSide)
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("görüntü çözülemedi: %w", err)
	}
	text, err := qr.DecodeImage(img)
	if err != nil {
		if errors.Is(err, qr.ErrNotFound) {
			return "", errors.New("görüntüde okunabilir bir QR kodu bulunamadı")
		}
		return "", fmt.Errorf("QR kodu okunamadı: %w", err)
	}
	if !utf8.Valid(text) {
		return "", errors.New("QR kodu metin içermiyor")
	}
	return strings.TrimSpace(string(text)), nil
}

// showInviteQR draws an invite code as a QR code for the phone's camera.
// The code carries the invite secret, so a PNG is written owner-only and
// the owner is reminded to delete it.
func showInviteQR(env *Env, code string, terminal bool, pngPath string) error {
	if err := showQR(env, code, qr.L, pngPath, false, !terminal); err != nil {
		return err
	}
	if pngPath != "" {
		fmt.Fprintln(env.Stdout, "PNG dosyası davetin gizli anahtarını içerir; telefon okuduktan sonra sil.")
	}
	return nil
}
