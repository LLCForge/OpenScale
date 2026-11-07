// Package memprofile holds the memory profiles of the OpenScale process
// (#392). The low profile targets a 32 MiB budget for a Raspberry Pi Zero
// or a small VPS: a soft Go memory limit, a more eager garbage collector
// and a smaller connection tracking table. The optional services (file
// transfer, SSH, remote desktop, speed test and the rest) are already off
// unless the owner turns them on, so the profile does not touch them.
//
// The profile is chosen with OPENSCALE_MEMORY_PROFILE=low (the systemd
// unit, the OpenWrt init script or the shell) and applied once at program
// start. GOMEMLIMIT and GOGC, when set, win over the profile.
package memprofile

import (
	"fmt"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/openscale/openscale/internal/filter"
)

// EnvProfile selects the profile.
const EnvProfile = "OPENSCALE_MEMORY_PROFILE"

// Profile names.
const (
	NameDefault = "default"
	NameLow     = "low"
)

// LowBudget is the whole-process target of the low profile; the node test
// TestLowMemoryProfileBudget keeps a running tunnel under it.
const LowBudget = 32 << 20

// Profile is one memory profile.
type Profile struct {
	Name string `json:"name"`
	// MemoryLimit is the soft Go runtime limit in bytes; 0 leaves it.
	MemoryLimit int64 `json:"memory_limit,omitempty"`
	// GCPercent is the GOGC value; 0 leaves it.
	GCPercent int `json:"gc_percent,omitempty"`
	// ConnTrack fills the connection tracking limits the owner left at 0.
	ConnTrack filter.Limits `json:"conntrack"`
}

// Lookup returns a profile by name; "" is the default profile.
func Lookup(name string) (Profile, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", NameDefault:
		return Profile{Name: NameDefault}, nil
	case NameLow:
		return Profile{
			Name:        NameLow,
			MemoryLimit: 24 << 20,
			GCPercent:   50,
			ConnTrack: filter.Limits{
				MaxFlows:     4096,
				MaxFragments: 256,
				UDPTimeout:   filter.MinUDPTimeout * 6,
			},
		}, nil
	}
	return Profile{}, fmt.Errorf("%s: bilinmeyen bellek profili %q (default veya low)", EnvProfile, name)
}

// Applied tells what Apply changed.
type Applied struct {
	Profile Profile `json:"profile"`
	// MemoryLimitSet and GCSet are false when the environment (GOMEMLIMIT,
	// GOGC) already decided.
	MemoryLimitSet bool `json:"memory_limit_set,omitempty"`
	GCSet          bool `json:"gc_set,omitempty"`
}

var (
	mu      sync.Mutex
	current = Applied{Profile: Profile{Name: NameDefault}}
)

// Apply makes p the process profile.
func Apply(p Profile, getenv func(string) string) Applied {
	a := Applied{Profile: p}
	if p.MemoryLimit > 0 && strings.TrimSpace(getenv("GOMEMLIMIT")) == "" {
		debug.SetMemoryLimit(p.MemoryLimit)
		a.MemoryLimitSet = true
	}
	if p.GCPercent > 0 && strings.TrimSpace(getenv("GOGC")) == "" {
		debug.SetGCPercent(p.GCPercent)
		a.GCSet = true
	}
	mu.Lock()
	current = a
	mu.Unlock()
	return a
}

// ApplyFromEnv reads EnvProfile and applies it. An unknown name keeps the
// default profile and is returned as an error for a warning.
func ApplyFromEnv(getenv func(string) string) (Applied, error) {
	p, err := Lookup(getenv(EnvProfile))
	if err != nil {
		return Current(), err
	}
	if p.Name == NameDefault {
		return Current(), nil
	}
	return Apply(p, getenv), nil
}

// Current returns the profile in force.
func Current() Applied {
	mu.Lock()
	defer mu.Unlock()
	return current
}

// FillConnTrack fills the zero fields of l from the active profile; set
// fields stay as the owner chose them.
func FillConnTrack(l filter.Limits) filter.Limits {
	p := Current().Profile.ConnTrack
	if l.MaxFlows == 0 {
		l.MaxFlows = p.MaxFlows
	}
	if l.MaxFragments == 0 {
		l.MaxFragments = p.MaxFragments
	}
	if l.UDPTimeout == 0 {
		l.UDPTimeout = p.UDPTimeout
	}
	if l.TCPTimeout == 0 {
		l.TCPTimeout = p.TCPTimeout
	}
	if l.ICMPTimeout == 0 {
		l.ICMPTimeout = p.ICMPTimeout
	}
	if l.OtherTimeout == 0 {
		l.OtherTimeout = p.OtherTimeout
	}
	return l
}
