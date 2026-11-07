package winapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/openscale/openscale/internal/securefile"
)

// Discreet name mode (#687, ADR-0196). The tray tooltip, notification
// titles, the window title and the service's display name and
// description show a neutral name ("Ağ Yardımcısı" by default) instead
// of "OpenScale" and VPN wording. Like the low-visibility mode of
// ADR-0109 it is cosmetic only: the service name, the tunnel interface
// and every rule bound to them stay "OpenScale", because renaming those
// could leave the kill switch or leak filters pointing at nothing.
//
// The setting is discreet.json in the service data directory (Windows,
// administrator-only, so a standard user cannot rename the VPN away from
// the owner) or the user's config folder elsewhere; OPENSCALE_DISCREET=1
// turns it on for one process.

// DiscreetFile is the settings file name.
const DiscreetFile = "discreet.json"

// DiscreetEnv set to 1 turns the mode on for this process.
const DiscreetEnv = "OPENSCALE_DISCREET"

// Neutral defaults.
const (
	DefaultNeutralName        = "Ağ Yardımcısı"
	DefaultNeutralDescription = "Ağ bağlantısı yardımcı servisi"
	maxNeutralNameRunes       = 40
)

// Discreet is the saved setting.
type Discreet struct {
	Enabled bool `json:"enabled"`
	// Name replaces "OpenScale"; empty means DefaultNeutralName.
	Name string `json:"name,omitempty"`
}

// ValidNeutralName accepts 1-40 letters, digits, spaces, "." and "-",
// with no "OpenScale" or VPN wording (the point of the mode).
func ValidNeutralName(s string) error {
	n := utf8.RuneCountInString(s)
	if strings.TrimSpace(s) != s || n == 0 || n > maxNeutralNameRunes {
		return fmt.Errorf("ad 1-%d karakter olmalı, başta ve sonda boşluk olmamalı", maxNeutralNameRunes)
	}
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != ' ' && r != '.' && r != '-' {
			return errors.New("ad yalnızca harf, rakam, boşluk, nokta ve tire içerebilir")
		}
	}
	low := strings.ToLower(s)
	for _, w := range revealingWords {
		if strings.Contains(low, w) {
			return fmt.Errorf("ad %q sözcüğünü içeremez", w)
		}
	}
	return nil
}

// revealingWords are hidden by the mode.
var revealingWords = []string{"openscale", "vpn", "wireguard", "tünel", "tunnel", "mesh"}

// discreetDir is where the setting lives on this system.
func discreetDir() string {
	if d := DataDir(); d != "" {
		return d
	}
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		return ""
	}
	return filepath.Join(base, "OpenScale")
}

// LoadDiscreet reads the setting from dir; a missing file is off. A
// damaged file is an error and means off (the mode can only hide).
func LoadDiscreet(dir string) (Discreet, error) {
	if dir == "" {
		return Discreet{}, nil
	}
	data, err := securefile.ReadPrivate(filepath.Join(dir, DiscreetFile), 4<<10)
	if errors.Is(err, fs.ErrNotExist) {
		return Discreet{}, nil
	}
	if err != nil {
		return Discreet{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var d Discreet
	if err := dec.Decode(&d); err != nil {
		return Discreet{}, fmt.Errorf("%s bozuk: %w", DiscreetFile, err)
	}
	if d.Name != "" {
		if err := ValidNeutralName(d.Name); err != nil {
			return Discreet{}, err
		}
	}
	return d, nil
}

// SaveDiscreet writes the setting to dir.
func SaveDiscreet(dir string, d Discreet) error {
	if d.Name != "" {
		if err := ValidNeutralName(d.Name); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(dir, DiscreetFile), data)
}

// CurrentDiscreet is the effective setting of this process.
func CurrentDiscreet() Discreet {
	d, err := LoadDiscreet(discreetDir())
	if err != nil {
		d = Discreet{}
	}
	if os.Getenv(DiscreetEnv) == "1" {
		d.Enabled = true
	}
	return d
}

// NeutralName is the name shown in the mode.
func (d Discreet) NeutralName() string {
	if d.Name != "" {
		return d.Name
	}
	return DefaultNeutralName
}

// DisplayName is the name the desktop shows: "OpenScale" or the neutral
// name.
func DisplayName() string {
	d := CurrentDiscreet()
	if !d.Enabled {
		return "OpenScale"
	}
	return d.NeutralName()
}

// Neutralize replaces "OpenScale" and VPN wording in a user-visible text
// when the mode is on.
func (d Discreet) Neutralize(s string) string {
	if !d.Enabled {
		return s
	}
	return neutralizeText(s, d.NeutralName())
}

func neutralizeText(s, name string) string {
	r := strings.NewReplacer(
		"OpenScale", name, "openscale", name, "OPENSCALE", name,
		"VPN", "bağlantı", "vpn", "bağlantı",
		"WireGuard", "", "Tünel", "Bağlantı", "tünel", "bağlantı",
	)
	return strings.Join(strings.Fields(r.Replace(s)), " ")
}

// ServiceIdentity is the display name and description the service gets.
func (d Discreet) ServiceIdentity() (display, description string) {
	if !d.Enabled {
		return ServiceDisplayName, ServiceDescription
	}
	return d.NeutralName(), DefaultNeutralDescription
}
