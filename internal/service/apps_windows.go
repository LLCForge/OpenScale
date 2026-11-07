//go:build windows

package service

import (
	"strings"

	"github.com/openscale/openscale/internal/trust"
)

// sshRuleUser maps the account a client asks for to the name rules use.
// The Windows service runs as LocalSystem and the SSH server cannot switch
// accounts, so only "system" exists here, and only a rule that lists it
// explicitly lets anyone in (ADR-0030).
func sshRuleUser(user string) (string, bool) {
	if strings.EqualFold(user, trust.SSHWindowsUser) {
		return trust.SSHWindowsUser, true
	}
	return "", false
}

// accountIsSuperuser: "system" is checked by name above.
func accountIsSuperuser(string) bool { return false }
