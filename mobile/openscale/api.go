// Package openscale is the Go side of the OpenScale Android app (#173,
// ADR-0101). It is built with `gomobile bind` into an AAR; the Kotlin app
// is a thin shell around it: VpnService, Android Keystore and the screens.
// The trust core, membership and the WireGuard engine run here.
//
// Every exported name uses only what gomobile can bind: string, []byte,
// int, bool, error, the Platform callback interface and *Tunnel. Go int is
// Java long. Device keys are never written to disk by this package: the
// app keeps them encrypted with a Keystore key (#176) and hands the
// decrypted bytes in for each call; copies made here are wiped after use.
package openscale

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/trust"
)

// Platform is implemented by the Android app.
type Platform interface {
	// Protect keeps a socket out of the VPN (VpnService.protect). It
	// returns false when Android refused.
	Protect(fd int) bool
	// Log receives one JSON log line; level is LogDebug..LogError.
	Log(level int, line string)
	// StatusChanged is called when the tunnel starts, stops or fails;
	// status is the same JSON Tunnel.Status returns.
	StatusChanged(status string)
}

// Log levels passed to Platform.Log.
const (
	LogDebug = 0
	LogInfo  = 1
	LogWarn  = 2
	LogError = 3
)

// Limits of the inputs that come from the app.
const (
	maxStateDir = 1024
	maxBundle   = 64 << 10
	maxOptions  = 32 << 10 // room for a per-app split tunnel list (P27)
	maxHostname = 255
	maxFP       = 256
)

// Version is the API version of this binding; the app refuses an AAR it
// was not built for.
func Version() string { return "openscale-mobile/3" }

func wipe(b []byte) { clear(b) }

// parseSecrets decodes the device key file the app decrypted. The input
// stays the caller's; the parsed copy must be wiped with wipeSecrets.
func parseSecrets(data []byte) (*trust.DeviceSecrets, error) {
	if len(data) == 0 || len(data) > trust.MaxDeviceKeySize {
		return nil, errors.New("cihaz anahtarı eksik veya fazla büyük")
	}
	buf := append([]byte(nil), data...)
	defer wipe(buf)
	return trust.UnmarshalDeviceSecrets(buf)
}

func wipeSecrets(s *trust.DeviceSecrets) {
	if s == nil {
		return
	}
	wipe(s.SigningSeed)
	wipe(s.WireGuardPrivate)
}

func checkStateDir(dir string) error {
	if dir == "" || len(dir) > maxStateDir || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("durum klasörü mutlak ve temiz bir yol olmalı")
	}
	return nil
}

// GenerateDeviceSecrets creates new device keys and returns the device key
// file. The app encrypts it with its Keystore key at once (#176) and wipes
// its copy; nothing is stored here.
func GenerateDeviceSecrets() ([]byte, error) {
	s, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		return nil, err
	}
	defer wipeSecrets(s)
	return trust.MarshalDeviceSecrets(s)
}

// EnrollmentRequest returns the one-line enrollment request (the same as
// "openscale keygen" prints) the owner adds with "openscale device add",
// and its fingerprint for comparing on both screens, separated by a
// newline.
func EnrollmentRequest(secrets []byte, hostname string) (string, error) {
	if len(hostname) > maxHostname {
		return "", errors.New("cihaz adı çok uzun")
	}
	s, err := parseSecrets(secrets)
	if err != nil {
		return "", err
	}
	defer wipeSecrets(s)
	env, req, err := s.NewEnrollmentRequest(hostname, time.Now())
	if err != nil {
		return "", err
	}
	line, err := trust.EncodeEnrollment(env)
	if err != nil {
		return "", err
	}
	return line + "\n" + req.Fingerprint(), nil
}

type joinSummary struct {
	NetworkID string `json:"network_id"`
	Version   uint64 `json:"version"`
	Domain    string `json:"domain"`
}

// Join verifies a join bundle against the root fingerprint the owner typed
// and initializes stateDir (the app's no-backup files folder). It returns
// a JSON summary.
func Join(stateDir, bundle, rootFingerprint string) (string, error) {
	if err := checkStateDir(stateDir); err != nil {
		return "", err
	}
	bundle, rootFingerprint = strings.TrimSpace(bundle), strings.TrimSpace(rootFingerprint)
	if bundle == "" || len(bundle) > maxBundle || rootFingerprint == "" || len(rootFingerprint) > maxFP {
		return "", errors.New("katılım paketi ve kök parmak izi gerekli")
	}
	store, err := member.Join(stateDir, bundle, rootFingerprint, time.Now())
	if err != nil {
		return "", err
	}
	doc := store.Document()
	out, err := json.Marshal(joinSummary{NetworkID: doc.NetworkID, Version: doc.Version, Domain: doc.DNSDomain})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// IsJoined reports whether stateDir holds a joined network.
func IsJoined(stateDir string) bool {
	if checkStateDir(stateDir) != nil {
		return false
	}
	_, err := member.Open(stateDir)
	return err == nil
}

// selfDevice finds this device in doc by its WireGuard key.
func selfDevice(doc *trust.Document, s *trust.DeviceSecrets) (trust.Device, error) {
	_, wg, err := s.PublicKeys()
	if err != nil {
		return trust.Device{}, err
	}
	for _, d := range doc.Devices {
		if d.WireGuardKey == wg {
			return d, nil
		}
	}
	return trust.Device{}, errors.New("bu cihaz ağ belgesinde yok (henüz eklenmedi veya iptal edildi)")
}
