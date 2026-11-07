//go:build windows

package winapp

import "github.com/openscale/openscale/internal/stealth"

// stealthSettings reads the low-visibility mode (ADR-0109, #247) from the
// service data directory. Any read error means "mode off": a damaged file
// can only make OpenScale more visible.
func stealthSettings() stealth.Settings {
	s, err := stealth.Load(DataDir())
	if err != nil {
		return stealth.Settings{}
	}
	return s
}
