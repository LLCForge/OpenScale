package sysinfo

import (
	"net"
	"strings"
	"sync"
)

var (
	extraMu sync.RWMutex
	extraFn func(*Info)
)

// SetExtra registers fn to fill the fields that belong to services of this
// process (the SSH host key fingerprint and the Wake-on-LAN MAC address)
// whenever a report is collected. nil removes it.
func SetExtra(fn func(*Info)) {
	extraMu.Lock()
	extraFn = fn
	extraMu.Unlock()
}

func applyExtra(in *Info) {
	extraMu.RLock()
	fn := extraFn
	extraMu.RUnlock()
	if fn != nil {
		fn(in)
	}
}

const maxFingerprint = 64

// sanitizeExtra keeps only well-formed service fields; a report from a
// peer is display data and must not smuggle anything else.
func (in *Info) sanitizeExtra() {
	fp := strings.TrimSpace(in.SSHHostKey)
	if !strings.HasPrefix(fp, "SHA256:") || len(fp) > maxFingerprint || strings.ContainsFunc(fp[7:], func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '+' || r == '/' || r == '=')
	}) {
		fp = ""
	}
	in.SSHHostKey = fp
	in.WakeMAC = NormalizeMAC(in.WakeMAC)
}

// NormalizeMAC returns a 48-bit unicast MAC address in lowercase
// colon form, or "" when s is not one.
func NormalizeMAC(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 17 {
		return ""
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 || hw[0]&0x01 != 0 {
		return ""
	}
	zero := true
	for _, b := range hw {
		if b != 0 {
			zero = false
		}
	}
	if zero {
		return ""
	}
	return hw.String()
}
