package posture

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Extended posture (#604, #608, ADR-0207): boot integrity and screen lock.
// Like Report it is the device's own statement and never proof. It
// travels in a separate system report field so devices that only know
// Report keep reading the old field unchanged.

// Extended is the second posture snapshot.
type Extended struct {
	// SecureBoot is UEFI Secure Boot.
	SecureBoot State
	// TPM is a TPM 2.0 (Windows, Linux) as the system reports it.
	TPM State
	// ScreenLock is an automatic, password protected screen lock.
	ScreenLock State
	// LockMinutes is the idle time before the lock (0: unknown).
	LockMinutes int
	// Disk is FileVault on macOS (elsewhere Report.DiskEncryption).
	Disk State
}

// MaxEncodedExtended bounds EncodeExtended's output.
const MaxEncodedExtended = 40

// MaxLockMinutes is the longest automatic lock delay that still counts as
// a screen lock for #608.
const MaxLockMinutes = 15

// Encode returns the compact form, e.g. "sb=y;tp=y;sl=y;lm=10".
func (x Extended) Encode() string {
	s := "sb=" + string(x.SecureBoot.code()) + ";tp=" + string(x.TPM.code()) + ";sl=" + string(x.ScreenLock.code())
	if x.LockMinutes > 0 && x.LockMinutes < 100000 {
		s += ";lm=" + strconv.Itoa(x.LockMinutes)
	}
	if x.Disk != Unknown {
		s += ";fv=" + string(x.Disk.code())
	}
	return s
}

// DecodeExtended parses Encode's form strictly.
func DecodeExtended(s string) (Extended, error) {
	var x Extended
	if s == "" {
		return x, nil
	}
	if len(s) > MaxEncodedExtended {
		return Extended{}, errors.New("extended posture too long")
	}
	seen := map[string]bool{}
	for part := range strings.SplitSeq(s, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok || seen[k] {
			return Extended{}, fmt.Errorf("bad extended posture field %q", part)
		}
		seen[k] = true
		switch k {
		case "sb", "tp", "sl", "fv":
			st, ok := stateFromCode(v)
			if !ok {
				return Extended{}, fmt.Errorf("bad extended posture value %q", part)
			}
			switch k {
			case "sb":
				x.SecureBoot = st
			case "tp":
				x.TPM = st
			case "sl":
				x.ScreenLock = st
			default:
				x.Disk = st
			}
		case "lm":
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 || n >= 100000 || strconv.Itoa(n) != v {
				return Extended{}, fmt.Errorf("bad lock minutes %q", part)
			}
			x.LockMinutes = n
		default:
			return Extended{}, fmt.Errorf("unknown extended posture field %q", k)
		}
	}
	return x, nil
}

// LockOK reports whether the screen lock satisfies #608: on, and the
// delay known and at most MaxLockMinutes.
func (x Extended) LockOK() bool {
	return x.ScreenLock == On && x.LockMinutes > 0 && x.LockMinutes <= MaxLockMinutes
}

// Merge returns r with FileVault folded into DiskEncryption on macOS.
func (x Extended) Merge(r Report) Report {
	if r.DiskEncryption == Unknown && x.Disk != Unknown {
		r.DiskEncryption = x.Disk
	}
	return r
}

// BootRequirement extends Requirement with the conditions of #604 and
// #608. Zero fields ask for nothing.
type BootRequirement struct {
	SecureBoot bool `json:"secure_boot,omitempty"`
	TPM        bool `json:"tpm,omitempty"`
	// ScreenLock asks for a lock within MaxLockMinutes.
	ScreenLock bool `json:"screen_lock,omitempty"`
}

// EvaluateExtended returns unmet conditions in Turkish (fail closed:
// Unknown never satisfies).
func EvaluateExtended(q BootRequirement, x Extended) []string {
	var out []string
	if q.SecureBoot && x.SecureBoot != On {
		out = append(out, "Secure Boot "+x.SecureBoot.String())
	}
	if q.TPM && x.TPM != On {
		out = append(out, "TPM "+x.TPM.String())
	}
	if q.ScreenLock && !x.LockOK() {
		switch {
		case x.ScreenLock != On:
			out = append(out, "ekran kilidi "+x.ScreenLock.String())
		case x.LockMinutes == 0:
			out = append(out, "ekran kilidi süresi bilinmiyor")
		default:
			out = append(out, fmt.Sprintf("ekran kilidi %d dakikada devreye giriyor, en çok %d olmalı", x.LockMinutes, MaxLockMinutes))
		}
	}
	return out
}

// Grade is the overall posture class.
type Grade string

// Grades.
const (
	GradeStrong  Grade = "strong"
	GradeWeak    Grade = "weak"
	GradeUnknown Grade = "unknown"
)

// Classify grades a device for #608 and #604: weak when the disk is not
// encrypted, the firewall is off, Secure Boot is off or the screen lock
// is off or too slow; unknown when nothing is known; otherwise strong.
// Reasons are in Turkish.
func Classify(r Report, x Extended) (Grade, []string) {
	r = x.Merge(r)
	var weak []string
	if r.DiskEncryption == Off {
		weak = append(weak, "disk şifresiz")
	}
	if r.Firewall == Off {
		weak = append(weak, "güvenlik duvarı kapalı")
	}
	if x.SecureBoot == Off {
		weak = append(weak, "Secure Boot kapalı")
	}
	if x.ScreenLock == Off {
		weak = append(weak, "ekran kilidi kapalı")
	} else if x.ScreenLock == On && x.LockMinutes > MaxLockMinutes {
		weak = append(weak, fmt.Sprintf("ekran kilidi %d dakikadan uzun", MaxLockMinutes))
	}
	if len(weak) > 0 {
		return GradeWeak, weak
	}
	if r.DiskEncryption == Unknown && r.Firewall == Unknown && x.SecureBoot == Unknown && x.ScreenLock == Unknown {
		return GradeUnknown, nil
	}
	return GradeStrong, nil
}

// Outcome is what a posture-conditioned rule does with a device.
type Outcome string

// Outcomes of RuleCondition.Decide.
const (
	// OutcomeAllow: every condition holds.
	OutcomeAllow Outcome = "allow"
	// OutcomeInternetOnly: the device may only use the exit node to reach
	// the internet, not other members (#604 example).
	OutcomeInternetOnly Outcome = "internet_only"
	// OutcomeDeny: the rule does not apply to the device.
	OutcomeDeny Outcome = "deny"
)

// RuleCondition is a posture condition a rule can carry (ADR-0207). The
// trust document's rule grammar is owned by the policy package; this type
// is the evaluation the policy calls. OnFail is "deny" (default) or
// "internet_only".
type RuleCondition struct {
	Require Requirement     `json:"require,omitempty"`
	Boot    BootRequirement `json:"boot,omitempty"`
	OnFail  Outcome         `json:"on_fail,omitempty"`
}

// Validate checks the condition strictly.
func (c RuleCondition) Validate() error {
	switch c.OnFail {
	case "", OutcomeDeny, OutcomeInternetOnly:
	default:
		return fmt.Errorf("bilinmeyen duruş sonucu %q", c.OnFail)
	}
	if c.Require.MinWindowsBuild < 0 || c.Require.MinWindowsBuild >= 1_000_000 {
		return errors.New("geçersiz Windows derlemesi")
	}
	return nil
}

// Decide applies the condition to a device's statements.
func (c RuleCondition) Decide(r Report, x Extended) (Outcome, []string) {
	unmet := append(Evaluate(c.Require, x.Merge(r)), EvaluateExtended(c.Boot, x)...)
	if len(unmet) == 0 {
		return OutcomeAllow, nil
	}
	if c.OnFail == OutcomeInternetOnly {
		return OutcomeInternetOnly, unmet
	}
	return OutcomeDeny, unmet
}

// CollectExtended runs the extended checks now; checks that cannot run
// report Unknown.
func CollectExtended() Extended { return collectExtended() }

var extCache struct {
	mu         sync.Mutex
	x          Extended
	at         time.Time
	refreshing bool
}

// CachedExtended is Cached for Extended.
func CachedExtended() Extended {
	extCache.mu.Lock()
	defer extCache.mu.Unlock()
	if !extCache.refreshing && (extCache.at.IsZero() || time.Since(extCache.at) > cacheTTL) {
		extCache.refreshing = true
		go func() {
			x := collectExtended()
			extCache.mu.Lock()
			extCache.x, extCache.at, extCache.refreshing = x, time.Now(), false
			extCache.mu.Unlock()
		}()
	}
	return extCache.x
}

// --- pure parsers, used by the platform files and tested everywhere ---

// ParseEFISecureBoot reads the SecureBoot EFI variable: four attribute
// bytes and one value byte.
func ParseEFISecureBoot(b []byte) State {
	if len(b) != 5 {
		return Unknown
	}
	switch b[4] {
	case 1:
		return On
	case 0:
		return Off
	}
	return Unknown
}

// WindowsScreenLock judges the machine inactivity policy (seconds, -1 when
// absent) and the user's screen saver values (registry strings, "" when
// absent).
func WindowsScreenLock(policySecs int, active, secure, timeout string) (State, int) {
	if policySecs > 0 {
		return On, (policySecs + 59) / 60
	}
	if active == "" && secure == "" {
		return Unknown, 0
	}
	if strings.TrimSpace(active) != "1" || strings.TrimSpace(secure) != "1" {
		return Off, 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(timeout))
	if err != nil || n <= 0 {
		return On, 0
	}
	return On, (n + 59) / 60
}

// GnomeScreenLock judges "gsettings get" output for
// org.gnome.desktop.screensaver lock-enabled and
// org.gnome.desktop.session idle-delay ("uint32 300").
func GnomeScreenLock(lockEnabled, idleDelay string) (State, int) {
	switch strings.TrimSpace(lockEnabled) {
	case "true":
	case "false":
		return Off, 0
	default:
		return Unknown, 0
	}
	f := strings.Fields(idleDelay)
	if len(f) == 0 {
		return On, 0
	}
	n, err := strconv.Atoi(f[len(f)-1])
	if err != nil || n < 0 {
		return On, 0
	}
	if n == 0 {
		// Idle never triggers the lock.
		return Off, 0
	}
	return On, (n + 59) / 60
}

// MacScreenLock judges "sysadminctl -screenLock status" output, for
// example "screenLock delay is 300 seconds" or "screenLock is off".
func MacScreenLock(out string) (State, int) {
	s := strings.ToLower(out)
	switch {
	case strings.Contains(s, "screenlock is off"):
		return Off, 0
	case strings.Contains(s, "immediate"):
		return On, 1
	}
	i := strings.Index(s, "delay is ")
	if i < 0 {
		return Unknown, 0
	}
	f := strings.Fields(s[i+len("delay is "):])
	if len(f) == 0 {
		return Unknown, 0
	}
	n, err := strconv.Atoi(f[0])
	if err != nil || n < 0 {
		return Unknown, 0
	}
	if n == 0 {
		return On, 1
	}
	return On, (n + 59) / 60
}

// MacFileVault judges "fdesetup status" output.
func MacFileVault(out string) State {
	switch {
	case strings.Contains(out, "FileVault is On"):
		return On
	case strings.Contains(out, "FileVault is Off"):
		return Off
	}
	return Unknown
}
