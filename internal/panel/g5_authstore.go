package panel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/securefile"
)

// Panel sign-in settings of G5 (ADR-0199): registered security keys, the
// sealed TOTP seed and the switches for re-authentication and the
// administrator mode. The file lives next to the network directory's
// other panel files and holds no secret in the clear: public keys,
// sealed seeds and booleans.

// PanelAuthFile is the file name inside the network directory.
const PanelAuthFile = "panel-auth.json"

const (
	panelAuthVersion  = 1
	maxPanelAuthFile  = 256 << 10
	maxWebAuthnCreds  = 10
	maxExtraOrigins   = 8
	defaultRPID       = "localhost"
	totpAccountSuffix = "panel"
)

// TOTPState is the enrolled TOTP factor.
type TOTPState struct {
	// Local is sealed with the root key passphrase (this computer's panel).
	Local *SealedSeed `json:"local"`
	// Remote is sealed with the remote password (remote panel); nil when
	// the remote panel cannot use TOTP.
	Remote    *SealedSeed `json:"remote,omitempty"`
	LastStep  uint64      `json:"last_step"`
	CreatedAt time.Time   `json:"created_at"`
}

// PanelAuth is the content of PanelAuthFile.
type PanelAuth struct {
	Version  int                  `json:"version"`
	WebAuthn []WebAuthnCredential `json:"webauthn,omitempty"`
	TOTP     *TOTPState           `json:"totp,omitempty"`
	// ReauthCritical asks again for a password, code or touch before
	// critical actions (#676).
	ReauthCritical bool `json:"reauth_critical"`
	// AdminMode limits changes to 15 minutes after the last proof (#678).
	AdminMode bool `json:"admin_mode"`
	// AdminToken also ends the administrator mode when the YubiKey is
	// removed (#678).
	AdminToken bool `json:"admin_token"`
	// LocalMFA asks this computer's panel for the second factor too; the
	// remote panel always asks when a factor is enrolled (#673).
	LocalMFA bool `json:"local_mfa"`
	// RPID is the WebAuthn relying party ID (default "localhost").
	RPID string `json:"rp_id,omitempty"`
	// ExtraOrigins are further origins allowed in WebAuthn client data,
	// e.g. a remote panel reached by name over HTTPS.
	ExtraOrigins []string `json:"extra_origins,omitempty"`
}

// HasFactor reports whether a second factor is enrolled.
func (p *PanelAuth) HasFactor() bool { return len(p.WebAuthn) > 0 || p.TOTP != nil }

func (p *PanelAuth) rpID() string {
	if p.RPID == "" {
		return defaultRPID
	}
	return p.RPID
}

func validRPID(s string) bool {
	if s == "" || len(s) > 253 || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func validOrigin(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.Path == "" &&
		u.RawQuery == "" && u.Fragment == "" && u.User == nil && len(s) <= 200
}

// Validate checks the file strictly; an unknown or broken file is never
// half used.
func (p *PanelAuth) Validate() error {
	if p.Version != panelAuthVersion {
		return fmt.Errorf("panel-auth: sürüm %d tanınmıyor", p.Version)
	}
	if len(p.WebAuthn) > maxWebAuthnCreds {
		return errors.New("panel-auth: çok fazla güvenlik anahtarı")
	}
	seen := map[string]bool{}
	for _, c := range p.WebAuthn {
		raw, err := b64url.DecodeString(c.PublicKey)
		if err != nil || c.ID == "" || seen[c.ID] || len(c.Name) > 64 {
			return errors.New("panel-auth: güvenlik anahtarı kaydı bozuk")
		}
		if _, err := parseCOSEKey(raw); err != nil {
			return errors.New("panel-auth: güvenlik anahtarı kaydı bozuk")
		}
		seen[c.ID] = true
	}
	if p.TOTP != nil && (p.TOTP.Local == nil || len(p.TOTP.Local.Box) == 0) {
		return errors.New("panel-auth: TOTP kaydı bozuk")
	}
	if p.RPID != "" && !validRPID(p.RPID) {
		return errors.New("panel-auth: rp_id geçersiz")
	}
	if len(p.ExtraOrigins) > maxExtraOrigins {
		return errors.New("panel-auth: çok fazla ek kaynak")
	}
	for _, o := range p.ExtraOrigins {
		if !validOrigin(o) {
			return fmt.Errorf("panel-auth: kaynak geçersiz: %q", o)
		}
	}
	return nil
}

var panelAuthMu sync.Mutex

// LoadPanelAuth reads the file in dir; a missing file is the default.
func LoadPanelAuth(dir string) (*PanelAuth, error) {
	data, err := securefile.ReadLimited(filepath.Join(dir, PanelAuthFile), maxPanelAuthFile)
	if errors.Is(err, fs.ErrNotExist) {
		return &PanelAuth{Version: panelAuthVersion}, nil
	}
	if err != nil {
		return nil, err
	}
	var p PanelAuth
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, errors.New("panel-auth: dosya okunamadı")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// SavePanelAuth writes p to dir.
func SavePanelAuth(dir string, p *PanelAuth) error {
	if err := p.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(dir, PanelAuthFile), append(data, '\n'))
}

// UpdatePanelAuth loads, changes and saves the file under one lock.
func UpdatePanelAuth(dir string, change func(*PanelAuth) error) (*PanelAuth, error) {
	panelAuthMu.Lock()
	defer panelAuthMu.Unlock()
	p, err := LoadPanelAuth(dir)
	if err != nil {
		return nil, err
	}
	if err := change(p); err != nil {
		return nil, err
	}
	if err := SavePanelAuth(dir, p); err != nil {
		return nil, err
	}
	return p, nil
}
