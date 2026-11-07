package osnet

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
)

// Network fingerprint for the UDP block memory (#393). The fingerprint is a
// keyed hash of the connected Wi-Fi names: it is kept only on this device
// and the key (a random per-device salt) never leaves it, so the file that
// stores fingerprints does not list the networks the device has visited.
//
// Only Wi-Fi networks with a known name count. Wired networks are named
// after the local adapter ("Ethernet"), which is the same for every
// network the cable is plugged into; remembering them would carry a hotel's
// UDP block over to the home network. Any wired or unnamed network in the
// current set therefore yields no fingerprint (nothing is remembered and
// nothing is recalled).

// NetworkFingerprintLen is the length of a fingerprint in hex characters.
const NetworkFingerprintLen = 32

// NetworkFingerprint returns the keyed fingerprint of nets, or "" when the
// set cannot be identified reliably (no network, a wired network, an
// unnamed Wi-Fi network or an empty salt).
func NetworkFingerprint(nets []CurrentNetwork, salt []byte) string {
	if len(nets) == 0 || len(salt) == 0 {
		return ""
	}
	names := make([]string, 0, len(nets))
	for _, n := range nets {
		name := cleanNetworkName(n.Name)
		if n.Kind != NetworkWiFi || name == "" {
			return ""
		}
		names = append(names, name)
	}
	slices.Sort(names)
	names = slices.Compact(names)
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte("openscale-netident-v1\x00"))
	mac.Write([]byte(strings.Join(names, "\x00")))
	return hex.EncodeToString(mac.Sum(nil))[:NetworkFingerprintLen]
}
