// Package stealth holds the optional low-visibility ("deniable") mode
// settings (ADR-0109, #247).
//
// The mode is cosmetic only: it hides the notification-area icon and
// silences balloon notifications. By construction it cannot weaken any
// protection. Settings carries no field that refers to the kill switch,
// leak protection, firewall rules, DNS or the tunnel; strict decoding
// refuses any such key; and Apply returns the protections unchanged. The
// package imports nothing that could change them (tests enforce all
// three).
//
// Renaming the tunnel interface or the Windows service is deliberately not
// part of the mode: the kill switch and leak filters are bound to those
// names, so renaming them is exactly the kind of change that could leave
// a protection pointing at nothing.
package stealth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/openscale/openscale/internal/securefile"
)

// FileName is the settings file in the service data directory (Windows)
// or the state directory. It sits in the administrator-only directory so
// a standard user cannot hide the VPN's status from the owner.
const FileName = "stealth.json"

const maxFile = 4 << 10

// Settings are the cosmetic switches. Every field must stay cosmetic;
// a test fails when a field outside the allowlist is added.
type Settings struct {
	// HideTray keeps the notification-area icon from being shown.
	HideTray bool `json:"hide_tray,omitempty"`
	// QuietNotifications drops balloon/toast notifications. The panel,
	// the audit log and the event stream still record every event.
	QuietNotifications bool `json:"quiet_notifications,omitempty"`
}

// Enabled reports whether any switch is on.
func (s Settings) Enabled() bool { return s.HideTray || s.QuietNotifications }

// Protections are the safety features the mode must never weaken.
type Protections struct {
	KillSwitch     bool
	LeakProtection bool
	DNSProtection  bool
	IPv6Protection bool
	Firewall       bool
}

// Apply returns p unchanged. It exists so callers that combine stealth
// settings with protection state have one place whose contract
// ("stealth never changes protections") is tested.
func (s Settings) Apply(p Protections) Protections { return p }

// Decode parses the settings strictly: an unknown key (for example
// "killswitch": false) is an error, never silently ignored.
func Decode(data []byte) (Settings, error) {
	var s Settings
	if len(data) > maxFile {
		return s, errors.New("gizli mod ayar dosyası çok büyük")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Settings{}, fmt.Errorf("gizli mod ayarları okunamadı: %w", err)
	}
	if dec.More() {
		return Settings{}, errors.New("gizli mod ayarlarında fazladan veri")
	}
	return s, nil
}

// Load reads the settings under dir. A missing file is the default (mode
// off); an unreadable or invalid file is also treated as off, so a
// damaged file can only make OpenScale more visible, never less.
func Load(dir string) (Settings, error) {
	if dir == "" {
		return Settings{}, nil
	}
	data, err := securefile.ReadLimited(filepath.Join(dir, FileName), maxFile)
	if errors.Is(err, fs.ErrNotExist) {
		return Settings{}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	return Decode(data)
}

// Save writes the settings under dir; the default removes the file.
func Save(dir string, s Settings) error {
	path := filepath.Join(dir, FileName)
	if !s.Enabled() {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return securefile.Replace(path, data)
}
