package winapp

import (
	"errors"
	"os"
	"strings"
)

// Keylogger-resistant passphrase entry (#649, ADR-0195 section 8). On
// Windows the root key passphrase can be typed on a separate desktop, the
// way the UAC prompt works: keyboard hooks and screen capture of programs
// on the user's normal desktop do not see that desktop's input or
// windows. Elsewhere, and when the separate desktop cannot be created,
// the terminal prompt is used.
//
// OPENSCALE_SECURE_INPUT=desktop turns it on for the CLI. The panel's
// on-screen keyboard and the hardware token touch are separate measures
// (panel hand-off, G1).

// SecureInputEnv selects the passphrase prompt.
const SecureInputEnv = "OPENSCALE_SECURE_INPUT"

// ErrSecureInputCancelled: the user pressed Cancel or closed the prompt.
var ErrSecureInputCancelled = errors.New("parola girişi iptal edildi")

// ErrSecureInputUnavailable: no separate desktop on this system.
var ErrSecureInputUnavailable = errors.New("güvenli masaüstünde parola girişi bu sistemde yok")

// SecureInputRequested reports whether the owner asked for the separate
// desktop prompt.
func SecureInputRequested() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(SecureInputEnv)), "desktop")
}

// maxSecretRunes bounds the passphrase field.
const maxSecretRunes = 1024

// promptText cleans the prompt shown on the secure desktop.
func promptText(p string) string {
	p = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(p), ":"))
	if p == "" {
		p = "Parola"
	}
	r := []rune(p)
	if len(r) > 200 {
		r = r[:200]
	}
	return strings.Map(func(c rune) rune {
		if c < 0x20 {
			return ' '
		}
		return c
	}, string(r))
}
