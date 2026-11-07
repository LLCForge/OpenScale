package osnet

import (
	"strings"
	"unicode/utf8"
)

// Network identity for the automatic exit node on untrusted networks
// (#80, ADR-0133). Only names are read (Wi-Fi SSID or connection profile,
// wired adapters); nothing is changed.

// Network kinds.
const (
	NetworkWiFi  = "wifi"
	NetworkWired = "wired"
)

// CurrentNetwork is one network this computer is connected to.
type CurrentNetwork struct {
	Kind string `json:"kind"`
	// Name is the Wi-Fi SSID (or the connection profile name); for wired
	// networks the adapter or profile name, informational only.
	Name string `json:"name"`
}

// maxNetworkName bounds a network name taken from the system.
const maxNetworkName = 128

// cleanNetworkName drops control characters and invalid UTF-8 and bounds
// the length, so a hostile SSID cannot corrupt logs or the panel.
func cleanNetworkName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || r < 0x20 || r == 0x7f {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > maxNetworkName {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// splitNmcli splits one line of "nmcli -t" output on unescaped colons and
// removes the escapes ("\:" and "\\").
func splitNmcli(line string) []string {
	var fields []string
	var cur strings.Builder
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\\' && i+1 < len(line):
			i++
			cur.WriteByte(line[i])
		case c == ':':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(fields, cur.String())
}

// parseNmcliDevices reads "nmcli -t -f TYPE,STATE,CONNECTION device".
// Connected Wi-Fi devices yield their connection name (NetworkManager
// names Wi-Fi connections after the SSID by default), connected ethernet
// devices a wired network. Everything else is ignored.
func parseNmcliDevices(out string) []CurrentNetwork {
	var nets []CurrentNetwork
	for _, line := range strings.Split(out, "\n") {
		f := splitNmcli(strings.TrimRight(line, "\r"))
		if len(f) != 3 || f[1] != "connected" {
			continue
		}
		name := cleanNetworkName(f[2])
		switch f[0] {
		case "wifi":
			if name != "" {
				nets = append(nets, CurrentNetwork{Kind: NetworkWiFi, Name: name})
			}
		case "ethernet":
			nets = append(nets, CurrentNetwork{Kind: NetworkWired, Name: name})
		}
	}
	return nets
}

// NetworkTrust decides whether the current networks are trusted (#80).
type NetworkTrust struct {
	// Trusted lists trusted Wi-Fi names (exact, case-sensitive like SSIDs).
	Trusted []string
	// TrustWired counts wired networks as trusted.
	TrustWired bool
}

// IsTrusted reports whether every current network is trusted. No network
// at all, or an error reading them, counts as untrusted: the exit node
// then stays on (fail closed).
func (t NetworkTrust) IsTrusted(nets []CurrentNetwork, err error) bool {
	if err != nil || len(nets) == 0 {
		return false
	}
	for _, n := range nets {
		switch n.Kind {
		case NetworkWired:
			if !t.TrustWired {
				return false
			}
		case NetworkWiFi:
			ok := false
			for _, name := range t.Trusted {
				ok = ok || name == n.Name
			}
			if !ok {
				return false
			}
		default:
			return false
		}
	}
	return true
}
