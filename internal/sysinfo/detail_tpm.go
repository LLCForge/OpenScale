package sysinfo

import "github.com/openscale/openscale/internal/tpm"

// tpmDetail reports the TPM version and manufacturer. Detection sends no
// command; the manufacturer comes from TPM2_GetCapability through
// internal/tpm's read-only transport, which refuses every other command.
func tpmDetail() (version, vendor string) {
	p, err := tpm.Detect()
	if err != nil {
		return "", ""
	}
	if !p.Present {
		return "none", ""
	}
	version = p.Version
	if version != "2.0" {
		return version, ""
	}
	t, err := tpm.Open()
	if err != nil {
		return version, ""
	}
	defer t.Close()
	if info, err := tpm.Query(t); err == nil {
		vendor = info.Manufacturer
	}
	return version, vendor
}
