//go:build linux

package srvaudit

import (
	"os"

	"github.com/openscale/openscale/internal/posture"
)

// Audit audits this server. Run it as root for the disk and firewall
// checks; it only reads.
func Audit(o Options) (Report, error) {
	root := os.DirFS("/")
	p := posture.Collect()
	return Run(root, Facts{DiskEncryption: p.DiskEncryption, Firewall: p.Firewall, Listeners: ReadListeners(root)}, o), nil
}
