package updater

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/release"
)

// Start-up self verification (#607, ADR-0195 section 3). Before the
// service opens the tunnel it checks its own program file:
//
//  1. the operating system signature, when the file carries one:
//     Authenticode on Windows (WinVerifyTrust, offline, no revocation
//     download), codesign on macOS; an unsigned development build passes,
//     a present but broken signature blocks;
//  2. the signed release manifest saved by the last "openscale update"
//     (CheckInstalled): when it exists, its signing key must not be on the
//     stored revocation list and the program must be byte for byte the signed
//     artifact, or the start is blocked.
//
// A block means the service exits before any key is read or any tunnel is
// opened. OPENSCALE_SELF_VERIFY=off skips the check for recovery; it is in
// the service's own environment, which only an administrator can set.

// SelfVerifyEnv set to "off" skips the check.
const SelfVerifyEnv = "OPENSCALE_SELF_VERIFY"

// ErrSelfVerify is the cause of a blocked start.
var ErrSelfVerify = errors.New("program kendi imza denetiminden geçmedi; tünel açılmadı")

// SignatureState is the result of the platform signature check.
type SignatureState int

const (
	SignatureUnknown SignatureState = iota // not checked on this system
	SignatureAbsent                        // the file is not signed
	SignatureValid                         // signed and valid
	SignatureInvalid                       // signed but broken or untrusted
)

func (s SignatureState) String() string {
	switch s {
	case SignatureAbsent:
		return "imzasız"
	case SignatureValid:
		return "geçerli"
	case SignatureInvalid:
		return "GEÇERSİZ"
	}
	return "denetlenmedi"
}

// SelfVerdict is the outcome of VerifySelf.
type SelfVerdict struct {
	Exe       string
	Signature SignatureState
	// SignatureErr explains SignatureInvalid.
	SignatureErr string
	// Manifest is the signed version the file matched, or "".
	Manifest string
	// ManifestChecked: a saved manifest was found and checked.
	ManifestChecked bool
	// Block is set when the service must not start.
	Block bool
	// Notes are Turkish lines for the log.
	Notes []string
}

// Err returns ErrSelfVerify with the reasons when Block is set.
func (v SelfVerdict) Err() error {
	if !v.Block {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrSelfVerify, strings.Join(v.Notes, "; "))
}

// SelfVerifyConfig are the inputs of VerifySelf.
type SelfVerifyConfig struct {
	Exe      string
	StateDir string // update directory with the saved manifest
	Root     *release.PublicKey
	Now      time.Time
	// Signature checks the platform signature; nil uses the system's.
	Signature func(path string) (SignatureState, error)
}

// VerifySelf runs both checks.
func VerifySelf(c SelfVerifyConfig) SelfVerdict {
	v := SelfVerdict{Exe: c.Exe}
	if c.Exe == "" {
		v.Notes = append(v.Notes, "program yolu bilinmiyor; denetim atlandı")
		return v
	}
	check := c.Signature
	if check == nil {
		check = PlatformSignature
	}
	st, err := check(c.Exe)
	v.Signature = st
	switch st {
	case SignatureInvalid:
		v.Block = true
		v.SignatureErr = fmt.Sprint(err)
		v.Notes = append(v.Notes, "işletim sistemi imzası geçersiz: "+v.SignatureErr)
	case SignatureValid:
		v.Notes = append(v.Notes, "işletim sistemi imzası geçerli")
	case SignatureAbsent:
		v.Notes = append(v.Notes, "program işletim sistemi imzası taşımıyor (geliştirme derlemesi)")
	}
	if c.Root == nil || c.StateDir == "" {
		v.Notes = append(v.Notes, "sürüm kök anahtarı veya güncelleme klasörü yok; imzalı manifesto denetimi atlandı")
		return v
	}
	ver, ok, err := CheckInstalled(c.StateDir, c.Exe, *c.Root, c.Now)
	switch {
	case err != nil && ver != "":
		v.ManifestChecked, v.Block = true, true
		v.Notes = append(v.Notes, fmt.Sprintf("program imzalı %s sürümüyle eşleşmiyor: %v", ver, err))
	case err != nil:
		// The saved manifest itself is broken or revoked: block, since a
		// manifest exists and cannot vouch for the program.
		v.ManifestChecked, v.Block = true, true
		v.Notes = append(v.Notes, "kayıtlı imzalı manifesto doğrulanamadı: "+err.Error())
	case ok:
		v.ManifestChecked, v.Manifest = true, ver
		v.Notes = append(v.Notes, "program imzalı "+ver+" sürümüyle bayt bayt aynı")
		if list, err := KnownRevocations(c.StateDir, *c.Root); err == nil && list == nil {
			v.Notes = append(v.Notes, "bu cihazda imzalı iptal listesi yok; iptal edilmiş imzalama anahtarı tanınamaz")
		}
	default:
		v.Notes = append(v.Notes, "kayıtlı imzalı manifesto yok (elle veya paketle kurulmuş)")
	}
	return v
}

// SelfVerifyDisabled reports whether the owner turned the check off.
func SelfVerifyDisabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(SelfVerifyEnv)), "off")
}

// VerifyRunningService runs VerifySelf for the installed service of this
// system with the default root key; ok is false when the check could not
// even be set up (no platform), which does not block.
func VerifyRunningService(now time.Time) (SelfVerdict, bool) {
	p, err := DefaultPlatform()
	if err != nil {
		return SelfVerdict{}, false
	}
	exe, err := os.Executable()
	if err != nil {
		return SelfVerdict{}, false
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	// Only the installed program is checked against its saved manifest; a
	// copy run from elsewhere (development, portable) is not the artifact.
	if !samePath(exe, p.Exe) {
		return SelfVerdict{}, false
	}
	cfg := SelfVerifyConfig{Exe: exe, StateDir: p.StateDir, Now: now}
	if root, _, err := LoadRootKey(""); err == nil {
		cfg.Root = &root
	}
	return VerifySelf(cfg), true
}

// samePath compares two program paths, without case on Windows.
func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
