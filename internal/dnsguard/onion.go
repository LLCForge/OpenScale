package dnsguard

import "strings"

// OnionAction is the resolver's answer to a name (#721).
type OnionAction int

// Onion actions.
const (
	// OnionNotOnion: the name is not below .onion; resolve as usual.
	OnionNotOnion OnionAction = iota
	// OnionViaTor: hand the name to the Tor client (its DNSPort or SOCKS
	// with remote resolution); never to an ordinary resolver.
	OnionViaTor
	// OnionNXDOMAIN: answer NXDOMAIN locally; the name must not leak to
	// any resolver (RFC 7686 2).
	OnionNXDOMAIN
)

func (a OnionAction) String() string {
	switch a {
	case OnionViaTor:
		return "via-tor"
	case OnionNXDOMAIN:
		return "nxdomain"
	}
	return "not-onion"
}

// onionV3Len is the length of a version 3 onion service label: base32 of
// a 32-byte key, a 2-byte checksum and a version byte.
const onionV3Len = 56

// OnionDecision decides a query for name on a device whose Tor exit is on
// (torExit) or off. Only well formed version 3 addresses reach Tor;
// version 2 addresses were retired by Tor and are refused.
func OnionDecision(name string, torExit bool) OnionAction {
	n := strings.TrimSuffix(absName(name), ".")
	if n != "onion" && !strings.HasSuffix(n, ".onion") {
		return OnionNotOnion
	}
	if !torExit || n == "onion" {
		return OnionNXDOMAIN
	}
	labels := strings.Split(strings.TrimSuffix(n, ".onion"), ".")
	if !validOnionV3(labels[len(labels)-1]) {
		return OnionNXDOMAIN
	}
	for _, l := range labels[:len(labels)-1] {
		if l == "" || len(l) > 63 {
			return OnionNXDOMAIN
		}
	}
	return OnionViaTor
}

// validOnionV3 checks the label's form and version byte; the checksum
// needs SHA3 and is left to Tor, which refuses a wrong one.
func validOnionV3(l string) bool {
	if len(l) != onionV3Len {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !('a' <= c && c <= 'z' || '2' <= c && c <= '7') {
			return false
		}
	}
	// The last base32 character holds the low bits of the version byte,
	// which is 3: 56 chars = 280 bits = 35 bytes; the last 5 bits are
	// the low 5 bits of byte 35 (version 0x03) -> value 3 -> 'd'.
	return l[onionV3Len-1] == 'd'
}
