package admin

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Key and crypto hardening for the owner (P13, ADR-0060, ADR-0062,
// ADR-0063): Argon2id calibration and upgrade, short authentication
// strings, and paper backups.

// ErrSASMismatch is returned when the typed short authentication string
// does not match the enrollment request.
var ErrSASMismatch = errors.New("short authentication string mismatch")

// ErrKDFCurrent is returned when the root key already uses parameters at
// least as strong as requested.
var ErrKDFCurrent = errors.New("root key already uses these or stronger Argon2id parameters")

// kdfTarget is the calibration target in nanoseconds; zero disables it.
// The openscale binary sets it; tests and libraries keep their own
// parameters.
var kdfTarget atomic.Int64

// SetKDFCalibration makes Init calibrate Argon2id to about target on this
// machine (#11). Zero turns calibration off.
func SetKDFCalibration(target time.Duration) { kdfTarget.Store(int64(target)) }

// calibratedArgon2 returns base, or the calibrated parameters when they are
// stronger and calibration is on.
func calibratedArgon2(base trust.Argon2Params) trust.Argon2Params {
	t := time.Duration(kdfTarget.Load())
	if t <= 0 {
		return base
	}
	return trust.StrongerArgon2(base, trust.CalibrateArgon2(t))
}

// KDFParams returns the Argon2id parameters of root.key.
func (n *Network) KDFParams() trust.Argon2Params {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.sealed.KDFParams()
}

// UpgradeKDF re-encrypts root.key under the same passphrase with a new salt
// and parameters at least as strong as both the current ones and target.
// Existing backups keep their own parameters.
func (n *Network) UpgradeKDF(passphrase []byte, target trust.Argon2Params) (trust.Argon2Params, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	current := n.sealed.KDFParams()
	next := trust.StrongerArgon2(current, target)
	if next == current {
		return current, ErrKDFCurrent
	}
	rootPriv, err := n.sealed.Open(passphrase)
	if err != nil {
		return current, err
	}
	defer wipe(rootPriv)
	sealed, err := trust.SealRootKey(rootPriv, passphrase, next, n.random)
	if err != nil {
		return current, err
	}
	data, err := trust.MarshalSealedRootKey(sealed)
	if err != nil {
		return current, err
	}
	if err := securefile.Replace(filepath.Join(n.dir, rootKeyFile), data); err != nil {
		return current, fmt.Errorf("write root key: %w", err)
	}
	n.sealed = sealed
	n.argon = trust.StrongerArgon2(n.argon, next)
	return next, nil
}

// RootSAS returns the short authentication string of the root key, which a
// device compares with the network it pinned.
func (n *Network) RootSAS() string { return trust.RootSAS(n.sealed.RootPublicKey()) }

// SAS returns the request's short authentication string (#20).
func (p *PendingDevice) SAS() string { return p.Request.SAS() }

// ConfirmSAS compares a code typed or read by the owner with the request's
// code in constant time. It is an alternative to ConfirmFingerprint.
func (p *PendingDevice) ConfirmSAS(typed string) error {
	if !trust.SASMatches(typed, p.Request.SAS()) {
		return ErrSASMismatch
	}
	return nil
}

// CreatePaperBackup makes a backup copy like CreateBackup and returns it
// packed for paper (#18, ADR-0063).
func (n *Network) CreatePaperBackup(current, backupPassphrase []byte, label string, now time.Time) ([]byte, error) {
	data, err := n.CreateBackup(current, backupPassphrase, label, now)
	if err != nil {
		return nil, err
	}
	sealed, err := trust.UnmarshalSealedRootKey(data)
	if err != nil {
		return nil, err
	}
	return trust.EncodePaperBackup(sealed)
}

// RestorePaper installs a paper backup (QR text or typed lines) as the
// root key of the network in dir, with the same checks as Restore.
func RestorePaper(dir, text string, passphrase []byte, opts Options) error {
	packed, err := trust.ParsePaperBackup(text)
	if err != nil {
		return err
	}
	sealed, err := trust.DecodePaperBackup(packed)
	if err != nil {
		return err
	}
	data, err := trust.MarshalSealedRootKey(sealed)
	if err != nil {
		return err
	}
	return Restore(dir, data, passphrase, opts)
}
