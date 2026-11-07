package openscale

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Network recognition without location permission (#477, P08). Android
// returns the Wi-Fi name (SSID) only with location permission, so the
// network policy (#179) can also match a local network identity built from
// what LinkProperties gives without any permission: the IPv4 default
// gateway, the DHCP server, the DNS servers, the search domain and the IPv4
// subnet. The values are hashed with a random per-install salt (HMAC) so
// the identity says nothing outside this phone and cannot be correlated
// between phones. It is not authenticated, like an SSID: a network that
// copies these values (common home router defaults) matches the same
// rule, so turning the exit node off for an identity is warned about.

const (
	netIDPrefix  = "n1-"
	netIDHexLen  = 24
	saltHexLen   = 64
	maxNetDNS    = 8
	maxNetDomain = 253
	maxNetInput  = 1024
)

// NewNetworkIDSalt returns a random salt (hex) the app stores once.
func NewNetworkIDSalt() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func validNetID(s string) bool {
	if len(s) != len(netIDPrefix)+netIDHexLen || !strings.HasPrefix(s, netIDPrefix) {
		return false
	}
	for _, c := range []byte(s[len(netIDPrefix):]) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// netAddr parses an address the app read from LinkProperties; zones and
// IPv4-mapped forms are normalized.
func netAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimPrefix(strings.TrimSpace(s), "/"))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("geçersiz adres %q", s)
	}
	return a.WithZone("").Unmap(), nil
}

// stableDNS keeps the DNS servers that do not change with the provider's
// IPv6 prefix: IPv4, IPv6 link-local and unique local addresses.
func stableDNS(a netip.Addr) bool {
	return a.Is4() || a.IsLinkLocalUnicast() || (a.Is6() && a.As16()[0]&0xfe == 0xfc)
}

func normDomain(s string) (string, error) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if len(s) > maxNetDomain {
		return "", errors.New("arama alanı fazla uzun")
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == ' ') {
			return "", fmt.Errorf("geçersiz arama alanı %q", s)
		}
	}
	// Android joins several search domains with spaces.
	return strings.Join(strings.Fields(s), " "), nil
}

// NetworkID returns the salted identity of the network described by its
// IPv4 default gateway, DHCP server, comma-separated DNS servers, search
// domain(s) and IPv4 subnet ("192.168.1.0/24"); any of them may be "", but
// a gateway or a DNS server is required. Global IPv6 DNS addresses and
// IPv6 subnets are ignored because they change with the provider's prefix.
func NetworkID(salt, gateway, dhcpServer, dnsServers, domain, subnet string) (string, error) {
	if len(salt) != saltHexLen {
		return "", errors.New("ağ kimliği tuzu geçersiz")
	}
	key, err := hex.DecodeString(salt)
	if err != nil {
		return "", errors.New("ağ kimliği tuzu geçersiz")
	}
	if len(gateway)+len(dhcpServer)+len(dnsServers)+len(domain)+len(subnet) > maxNetInput {
		return "", errors.New("ağ bilgisi fazla uzun")
	}
	var parts []string
	gw := ""
	if strings.TrimSpace(gateway) != "" {
		a, err := netAddr(gateway)
		if err != nil {
			return "", err
		}
		if !a.Is4() {
			return "", errors.New("ağ geçidi IPv4 olmalı")
		}
		gw = a.String()
	}
	parts = append(parts, "gw="+gw)
	dhcp := ""
	if strings.TrimSpace(dhcpServer) != "" {
		a, err := netAddr(dhcpServer)
		if err != nil {
			return "", err
		}
		if a.Is4() && !a.IsUnspecified() {
			dhcp = a.String()
		}
	}
	parts = append(parts, "dhcp="+dhcp)
	var dns []string
	for _, f := range strings.Split(dnsServers, ",") {
		if strings.TrimSpace(f) == "" {
			continue
		}
		a, err := netAddr(f)
		if err != nil {
			return "", err
		}
		if stableDNS(a) {
			dns = append(dns, a.String())
		}
	}
	slices.Sort(dns)
	dns = slices.Compact(dns)
	if len(dns) > maxNetDNS {
		return "", errors.New("fazla DNS sunucusu")
	}
	if gw == "" && len(dns) == 0 {
		return "", errors.New("ağ tanınamıyor: ağ geçidi ve DNS sunucusu yok")
	}
	parts = append(parts, "dns="+strings.Join(dns, ","))
	dom, err := normDomain(domain)
	if err != nil {
		return "", err
	}
	parts = append(parts, "domain="+dom)
	sub := ""
	if strings.TrimSpace(subnet) != "" {
		p, err := netip.ParsePrefix(strings.TrimSpace(subnet))
		if err != nil {
			return "", fmt.Errorf("geçersiz alt ağ %q", subnet)
		}
		if p.Addr().Is4() {
			sub = p.Masked().String()
		}
	}
	parts = append(parts, "subnet="+sub)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("openscale-netid-v1\n" + strings.Join(parts, "\n")))
	sum := mac.Sum(nil)
	return netIDPrefix + hex.EncodeToString(sum)[:netIDHexLen], nil
}
