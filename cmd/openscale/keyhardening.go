package main

import (
	"os"
	"strings"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Key hardening applies to the openscale program only, not to tests or
// other tools linking the packages (ADR-0060):
//   - device and coordinator key files are protected with the operating
//     system key store (Windows DPAPI) and old plaintext files migrate on
//     first read; OPENSCALE_KEY_PROTECTION=off turns that off for the
//     process, "openscale key unprotect" for a folder;
//   - a new root key's Argon2id parameters are calibrated to this machine.
func init() {
	securefile.EnableKeyProtection(!strings.EqualFold(os.Getenv("OPENSCALE_KEY_PROTECTION"), "off"))
	admin.SetKDFCalibration(trust.DefaultKDFTarget)
}
