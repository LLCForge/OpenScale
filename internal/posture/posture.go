// Package posture reports this device's security posture (ADR-0109, #105,
// #155, #41): whether the system disk is encrypted, whether a host
// firewall is on and, on Windows, the OS build number.
//
// Every value is the device's own statement. A compromised or modified
// device can report anything, so posture is shown to the owner and can be
// checked against an optional requirement, but it is never proof of
// security and never replaces the signed document's rules.
package posture

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// State is a tri-state answer: a check that could not run is Unknown,
// never Off or On.
type State uint8

const (
	Unknown State = iota
	Off
	On
)

// String returns the Turkish display form.
func (s State) String() string {
	switch s {
	case On:
		return "açık"
	case Off:
		return "kapalı"
	}
	return "bilinmiyor"
}

func (s State) code() byte {
	switch s {
	case On:
		return 'y'
	case Off:
		return 'n'
	}
	return 'u'
}

func stateFromCode(c string) (State, bool) {
	switch c {
	case "y":
		return On, true
	case "n":
		return Off, true
	case "u":
		return Unknown, true
	}
	return Unknown, false
}

// Report is one posture snapshot.
type Report struct {
	// DiskEncryption is BitLocker on the system drive (Windows) or a
	// dm-crypt/LUKS layer under the root file system (Linux).
	DiskEncryption State
	// Firewall is the host firewall: every Windows profile enabled, or an
	// input filtering chain (nftables, ufw) on Linux.
	Firewall State
	// WindowsBuild is the Windows build number; 0 elsewhere.
	WindowsBuild int
}

// MaxEncoded bounds Encode's output; it rides in the system report.
const MaxEncoded = 32

// Encode returns the compact form carried in the system report, e.g.
// "d=y;f=n;b=26300".
func (r Report) Encode() string {
	s := "d=" + string(r.DiskEncryption.code()) + ";f=" + string(r.Firewall.code())
	if r.WindowsBuild > 0 && r.WindowsBuild < 1_000_000 {
		s += ";b=" + strconv.Itoa(r.WindowsBuild)
	}
	return s
}

// Decode parses Encode's form strictly. A report from another device is
// display data: anything malformed is rejected as a whole.
func Decode(s string) (Report, error) {
	var r Report
	if s == "" {
		return r, nil
	}
	if len(s) > MaxEncoded {
		return Report{}, errors.New("posture report too long")
	}
	seen := map[string]bool{}
	for part := range strings.SplitSeq(s, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok || seen[k] {
			return Report{}, fmt.Errorf("bad posture field %q", part)
		}
		seen[k] = true
		switch k {
		case "d", "f":
			st, ok := stateFromCode(v)
			if !ok {
				return Report{}, fmt.Errorf("bad posture value %q", part)
			}
			if k == "d" {
				r.DiskEncryption = st
			} else {
				r.Firewall = st
			}
		case "b":
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 || n >= 1_000_000 || strconv.Itoa(n) != v {
				return Report{}, fmt.Errorf("bad posture build %q", part)
			}
			r.WindowsBuild = n
		default:
			return Report{}, fmt.Errorf("unknown posture field %q", k)
		}
	}
	return r, nil
}

// Requirement is an optional posture condition the owner may attach to a
// rule or a device in documentation and the panel (ADR-0109). It is
// advisory: the device's own statement cannot be verified.
type Requirement struct {
	DiskEncryption  bool `json:"disk_encryption,omitempty"`
	Firewall        bool `json:"firewall,omitempty"`
	MinWindowsBuild int  `json:"min_windows_build,omitempty"`
}

// IsZero reports whether the requirement asks for nothing.
func (q Requirement) IsZero() bool { return q == Requirement{} }

// Evaluate returns the requirement's unmet conditions in Turkish. Unknown
// never satisfies a condition (fail closed). MinWindowsBuild applies only
// to reports that carry a Windows build; other systems are not judged by
// it.
func Evaluate(q Requirement, r Report) []string {
	var out []string
	if q.DiskEncryption && r.DiskEncryption != On {
		out = append(out, "disk şifreleme "+r.DiskEncryption.String())
	}
	if q.Firewall && r.Firewall != On {
		out = append(out, "güvenlik duvarı "+r.Firewall.String())
	}
	if q.MinWindowsBuild > 0 && r.WindowsBuild > 0 && r.WindowsBuild < q.MinWindowsBuild {
		out = append(out, fmt.Sprintf("Windows derlemesi %d, en az %d isteniyor", r.WindowsBuild, q.MinWindowsBuild))
	}
	return out
}

// Disclaimer is printed wherever posture is shown.
const Disclaimer = "Bu bilgiler cihazın kendi ifadesidir; kesin güvenlik kanıtı sayılmaz."

// Collect runs the checks now. It may take seconds (Windows asks the
// volume encryption provider) and never fails: checks that cannot run
// report Unknown.
func Collect() Report { return collect() }

const cacheTTL = 30 * time.Minute

var cache struct {
	mu         sync.Mutex
	report     Report
	at         time.Time
	refreshing bool
}

// Cached returns the last collected report without blocking and starts a
// background refresh when it is older than 30 minutes. The first call
// returns an all-unknown report.
func Cached() Report {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if !cache.refreshing && (cache.at.IsZero() || time.Since(cache.at) > cacheTTL) {
		cache.refreshing = true
		go func() {
			r := collect()
			cache.mu.Lock()
			cache.report, cache.at, cache.refreshing = r, time.Now(), false
			cache.mu.Unlock()
		}()
	}
	return cache.report
}
