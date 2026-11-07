// Package wgconf builds wireguard-go UAPI configuration and parses its
// status output. Keys are passed as hex, as UAPI requires.
package wgconf

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/openscale/openscale/internal/trust"
)

// Peer is the desired configuration of one WireGuard peer.
type Peer struct {
	PublicKey  trust.Key
	AllowedIPs []netip.Prefix
	// Endpoint is optional; the zero value leaves it unset.
	Endpoint  netip.AddrPort
	Keepalive int
}

// Interface returns the UAPI lines for the private key and listen port.
func Interface(privateKey []byte, listenPort int) string {
	return fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(privateKey), listenPort)
}

// AddOrUpdate returns UAPI lines that create or update a peer, replacing
// its allowed IPs.
func AddOrUpdate(p Peer) string {
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
	if p.Endpoint.IsValid() {
		fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint.String())
	}
	if p.Keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.Keepalive)
	}
	b.WriteString("replace_allowed_ips=true\n")
	for _, ip := range p.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", ip.String())
	}
	return b.String()
}

// SetEndpointString updates an existing peer's endpoint to a value the
// bind parses itself, such as a relay endpoint.
func SetEndpointString(key trust.Key, ep string) string {
	return fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", hex.EncodeToString(key[:]), ep)
}

// SetEndpoint returns UAPI lines that only update an existing peer's endpoint.
func SetEndpoint(key trust.Key, ep netip.AddrPort) string {
	return fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", hex.EncodeToString(key[:]), ep.String())
}

// Remove returns UAPI lines that remove a peer.
func Remove(key trust.Key) string {
	return fmt.Sprintf("public_key=%s\nremove=true\n", hex.EncodeToString(key[:]))
}

// HostPrefixes returns the /32 and /128 prefixes for two addresses.
func HostPrefixes(v4, v6 netip.Addr) []netip.Prefix {
	return []netip.Prefix{netip.PrefixFrom(v4, 32), netip.PrefixFrom(v6, 128)}
}

// Status is the parsed IpcGet output.
type Status struct {
	ListenPort int
	Peers      map[trust.Key]PeerStatus
}

// PeerStatus is one peer in Status.
type PeerStatus struct {
	Endpoint netip.AddrPort
	// Relayed is true when the peer is reached through the coordinator.
	Relayed           bool
	LastHandshakeUnix int64
	RxBytes, TxBytes  uint64
}

// ParseStatus parses the output of device.IpcGet.
func ParseStatus(s string) (Status, error) {
	st := Status{Peers: map[trust.Key]PeerStatus{}}
	var current *trust.Key
	var peer PeerStatus
	flush := func() {
		if current != nil {
			st.Peers[*current] = peer
		}
	}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "listen_port":
			n, err := strconv.Atoi(value)
			if err != nil {
				return Status{}, fmt.Errorf("parse listen_port: %w", err)
			}
			st.ListenPort = n
		case "public_key":
			flush()
			raw, err := hex.DecodeString(value)
			if err != nil || len(raw) != trust.KeySize {
				return Status{}, fmt.Errorf("parse public_key")
			}
			var k trust.Key
			copy(k[:], raw)
			current, peer = &k, PeerStatus{}
		case "endpoint":
			if ep, err := netip.ParseAddrPort(value); err == nil {
				peer.Endpoint = ep
			} else if strings.HasPrefix(value, "relay-") {
				peer.Relayed = true
			}
		case "last_handshake_time_sec":
			peer.LastHandshakeUnix, _ = strconv.ParseInt(value, 10, 64)
		case "rx_bytes":
			peer.RxBytes, _ = strconv.ParseUint(value, 10, 64)
		case "tx_bytes":
			peer.TxBytes, _ = strconv.ParseUint(value, 10, 64)
		}
	}
	flush()
	return st, sc.Err()
}
