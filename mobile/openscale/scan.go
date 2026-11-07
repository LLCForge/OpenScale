package openscale

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/openscale/openscale/internal/qr"
	"github.com/openscale/openscale/internal/trust"
)

// QR registration (#182, P27). The camera is the app's (Camera2, no
// third-party scanner); every frame's luminance plane comes here and the
// pure Go decoder of internal/qr reads it. What was read is only
// classified: nothing is joined or trusted until the owner confirms on
// screen (root fingerprint or SAS compared with the owner's screen).

// DecodeQR decodes a QR code in an 8-bit luminance frame (the Y plane of
// YUV_420_888): height rows of rowStride bytes, of which the first width
// are used. It returns the text, or an error when there is no readable
// code (the normal result for most frames).
func DecodeQR(luminance []byte, width, height, rowStride int) (string, error) {
	data, err := qr.DecodeGray(luminance, width, height, rowStride)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(data) {
		return "", errors.New("QR kodu metin içermiyor")
	}
	return string(data), nil
}

// Kinds of a scanned text.
const (
	scanInvite      = "invite"
	scanJoinBundle  = "join_bundle"
	scanEnrollment  = "enrollment_request"
	scanPaperBackup = "paper_backup"
	scanFingerprint = "root_fingerprint"
	scanUnknown     = "unknown"
)

// scanResult is what the app shows before the owner confirms a scan. It
// never carries secrets: the invite seed stays in the scanned text, which
// the app passes to InviteJoin as is.
type scanResult struct {
	Kind            string `json:"kind"`
	NetworkID       string `json:"network_id,omitempty"`
	RootFingerprint string `json:"root_fingerprint,omitempty"`
	RootSAS         string `json:"root_sas,omitempty"`
	Coordinator     string `json:"coordinator,omitempty"`
	Message         string `json:"message,omitempty"`
}

// ClassifyScan tells the app what a scanned (or pasted) text is, as JSON.
// An invite code is decoded and its network shown with the root
// fingerprint and SAS (ADR-0062) so the owner can compare them with the
// screen the code came from. A paper backup of the root key is refused on
// the phone: it belongs on the owner's computer only.
func ClassifyScan(text string) string {
	text = strings.TrimSpace(text)
	r := scanResult{Kind: scanUnknown}
	switch {
	case strings.HasPrefix(text, "osinv1."):
		code, err := trust.DecodeInviteCode(text)
		if err != nil {
			r.Message = "davet kodu bozuk"
			break
		}
		root := ed25519.PublicKey(code.RootKey[:])
		r = scanResult{
			Kind:            scanInvite,
			NetworkID:       code.NetworkID,
			RootFingerprint: trust.RootFingerprint(root),
			RootSAS:         trust.RootSAS(root),
			Coordinator:     code.Coordinator.Endpoint,
		}
	case strings.HasPrefix(text, "osjoin1."):
		r = scanResult{Kind: scanJoinBundle, Message: "katılım paketi: kök anahtar parmak izini sahibin ekranından yazın"}
	case strings.HasPrefix(text, "osreq1."):
		r = scanResult{Kind: scanEnrollment, Message: "bu bir kayıt isteği; yönetici bilgisayarda kullanılır"}
	case strings.HasPrefix(strings.ToUpper(text), trust.PaperQRPrefix):
		r = scanResult{Kind: scanPaperBackup, Message: "kök anahtarın kâğıt yedeği telefonda kullanılmaz; yalnızca sahibin bilgisayarında geri yüklenir"}
	default:
		if isFingerprint(text) {
			r = scanResult{Kind: scanFingerprint, RootFingerprint: text}
		}
	}
	out, err := json.Marshal(r)
	if err != nil {
		return `{"kind":"unknown"}`
	}
	return string(out)
}

// isFingerprint reports whether s is a fingerprint as OpenScale prints it:
// 16 base32 characters, optionally grouped with dashes or spaces.
func isFingerprint(s string) bool {
	if len(s) > 32 {
		return false
	}
	fp := trust.NormalizeFingerprint(s)
	if len(fp) != 16 {
		return false
	}
	for _, c := range fp {
		if (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}

// EncodeQRPNG returns text as a QR code PNG for the screen: the enrollment
// request the owner's computer reads (#182), at level L like
// "openscale key request".
func EncodeQRPNG(text string) ([]byte, error) {
	if text == "" || len(text) > qr.MaxInput {
		return nil, errors.New("QR koduna sığmayan metin")
	}
	code, err := qr.EncodeText(text, qr.L)
	if err != nil {
		return nil, err
	}
	// About 720 pixels wide, whole pixels per module.
	scale := min(max(720/(code.Size+2*qr.QuietZone), 2), qr.MaxPNGScale)
	var buf bytes.Buffer
	if err := code.PNG(&buf, scale); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DeviceSAS returns this device's short authentication string (ADR-0062),
// which the owner's screen shows for its enrollment request.
func DeviceSAS(secrets []byte) (string, error) {
	s, err := parseSecrets(secrets)
	if err != nil {
		return "", err
	}
	defer wipeSecrets(s)
	return s.SAS()
}
