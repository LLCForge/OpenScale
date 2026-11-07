// Package upstream connects an exit node to an outside WireGuard provider
// such as Mullvad (ADR-0142, "üst çıkış"): members' internet traffic that
// reaches this exit node leaves through a second WireGuard tunnel instead
// of the exit node's own address. OpenScale never talks to the provider's
// API; the owner imports the provider's own WireGuard .conf files.
package upstream

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Limits of an imported .conf file. A provider's file is a few hundred
// bytes; the limits only keep a hostile file from costing memory.
const (
	MaxConfSize   = 16 << 10
	maxConfLines  = 256
	maxLineLength = 1024
	maxDNS        = 4
	keySize       = 32
)

// Config is a provider's WireGuard configuration: exactly the fields an
// upstream tunnel needs and nothing else.
type Config struct {
	// PrivateKey is this exit node's key at the provider (one device slot).
	PrivateKey [keySize]byte
	// Address4 and Address6 are the tunnel addresses the provider gave this
	// key; Address6 is invalid when the provider gave none.
	Address4 netip.Addr
	Address6 netip.Addr
	// DNS are the provider's resolvers, reached through the tunnel.
	DNS []netip.Addr
	// PeerKey and Endpoint identify the provider's server.
	PeerKey  [keySize]byte
	Endpoint netip.AddrPort
	// IPv6 reports whether AllowedIPs carried ::/0 as well as 0.0.0.0/0.
	IPv6 bool
	// MTU is the provider's [Interface] MTU (Cloudflare WARP files carry
	// one); 0 when the file has none. An MTU chosen with "use --mtu" wins.
	MTU int
	// EndpointHost is the name the file gave as Endpoint, resolved once at
	// import (ParseWith); "" when the file gave an IP address. It is not
	// stored: the canonical file keeps only the address.
	EndpointHost string
}

// Resolver turns an Endpoint name into one address. It is used only while
// a file is imported, never at run time (ADR-0142, Tor/WARP appendix).
type Resolver func(host string) (netip.Addr, error)

// maxHostLength bounds an Endpoint name (RFC 1035).
const maxHostLength = 253

// ConfError is a parse error with the 1-based line it refers to (0 when
// it concerns the whole file). It never quotes a key.
type ConfError struct {
	Line int
	Msg  string
}

func (e *ConfError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("WireGuard yapılandırması, satır %d: %s", e.Line, e.Msg)
	}
	return "WireGuard yapılandırması: " + e.Msg
}

func confErr(line int, format string, args ...any) error {
	return &ConfError{Line: line, Msg: fmt.Sprintf(format, args...)}
}

// Parse reads a WireGuard .conf file. Only [Interface] PrivateKey, Address,
// DNS and MTU and one [Peer] with PublicKey, Endpoint and AllowedIPs are
// accepted; any other field (PostUp, PresharedKey, MTU, Table, ...) is an
// error, so nothing in a downloaded file can run a command or change how
// the host routes. The endpoint must be an IP address: resolving a name
// would send a DNS query outside the tunnel. [Interface] MTU (1280-1420)
// is accepted too, as Cloudflare WARP files carry it.
func Parse(data []byte) (*Config, error) { return ParseWith(data, nil) }

// ParseWith is Parse that also accepts an Endpoint name and turns it into
// an address with resolve, once. A nil resolve refuses names. The name is
// resolved only after the whole file is valid, so a bad file sends no
// query.
func ParseWith(data []byte, resolve Resolver) (*Config, error) {
	if len(data) > MaxConfSize {
		return nil, confErr(0, "dosya çok büyük (en fazla %d bayt)", MaxConfSize)
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(data) {
		return nil, confErr(0, "dosya UTF-8 değil")
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > maxConfLines {
		return nil, confErr(0, "çok fazla satır (en fazla %d)", maxConfLines)
	}

	var (
		c                       Config
		section                 string
		interfaces, peers       int
		seen                    = map[string]bool{}
		havePriv, havePeerKey   bool
		haveEndpoint, haveAllow bool
		allow4                  bool
		endpointHost            string
		endpointPort            uint16
		endpointLine            int
	)
	for i, raw := range lines {
		n := i + 1
		if len(raw) > maxLineLength {
			return nil, confErr(n, "satır çok uzun")
		}
		line := raw
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.ContainsFunc(line, func(r rune) bool { return r < 0x20 && r != '\t' || r == 0x7f }) {
			return nil, confErr(n, "denetim karakteri içeriyor")
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, confErr(n, "bölüm başlığı kapanmamış")
			}
			switch strings.ToLower(strings.TrimSpace(line[1 : len(line)-1])) {
			case "interface":
				interfaces++
				if interfaces > 1 {
					return nil, confErr(n, "birden fazla [Interface] bölümü")
				}
				section = "interface"
			case "peer":
				peers++
				if peers > 1 {
					return nil, confErr(n, "birden fazla [Peer] bölümü; üst çıkış tek sunucuya bağlanır")
				}
				section = "peer"
			default:
				return nil, confErr(n, "bilinmeyen bölüm %s", quoteShort(line))
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, confErr(n, "\"Alan = değer\" biçiminde değil")
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if section == "" {
			return nil, confErr(n, "alan bir bölümün dışında")
		}
		if value == "" {
			return nil, confErr(n, "%s boş", key)
		}
		id := section + "." + key
		list := id == "interface.address" || id == "interface.dns" || id == "peer.allowedips"
		if seen[id] && !list {
			return nil, confErr(n, "%s iki kez yazılmış", key)
		}
		seen[id] = true

		switch id {
		case "interface.privatekey":
			k, err := parseKey(value)
			if err != nil {
				return nil, confErr(n, "PrivateKey geçerli bir WireGuard anahtarı değil")
			}
			if k == ([keySize]byte{}) {
				return nil, confErr(n, "PrivateKey sıfır")
			}
			c.PrivateKey, havePriv = k, true
		case "interface.address":
			for _, item := range splitItems(value) {
				p, err := netip.ParsePrefix(item)
				if err != nil {
					a, aerr := netip.ParseAddr(item)
					if aerr != nil {
						return nil, confErr(n, "Address %s geçerli bir adres değil", quoteShort(item))
					}
					p = netip.PrefixFrom(a, a.BitLen())
				}
				a := p.Addr()
				if a.Zone() != "" || a.Is4In6() || !usableUnicast(a) {
					return nil, confErr(n, "Address %s kullanılamaz", quoteShort(item))
				}
				if a.Is4() {
					if c.Address4.IsValid() {
						return nil, confErr(n, "birden fazla IPv4 adresi")
					}
					c.Address4 = a
				} else {
					if c.Address6.IsValid() {
						return nil, confErr(n, "birden fazla IPv6 adresi")
					}
					c.Address6 = a
				}
			}
		case "interface.dns":
			for _, item := range splitItems(value) {
				a, err := netip.ParseAddr(item)
				if err != nil || a.Zone() != "" {
					// wg-quick takes names as search domains; an upstream
					// exit forwards queries only to resolver addresses.
					return nil, confErr(n, "DNS %s bir IP adresi değil (arama alanı desteklenmez)", quoteShort(item))
				}
				a = a.Unmap()
				if !usableUnicast(a) {
					return nil, confErr(n, "DNS %s kullanılamaz", quoteShort(item))
				}
				if len(c.DNS) >= maxDNS {
					return nil, confErr(n, "en fazla %d DNS sunucusu", maxDNS)
				}
				c.DNS = append(c.DNS, a)
			}
		case "interface.mtu":
			v, err := strconv.Atoi(value)
			if err != nil || v < MinMTU || v > MaxMTU || value[0] == '+' {
				return nil, confErr(n, "MTU %d ile %d arasında bir sayı olmalı", MinMTU, MaxMTU)
			}
			c.MTU = v
		case "peer.publickey":
			k, err := parseKey(value)
			if err != nil {
				return nil, confErr(n, "PublicKey geçerli bir WireGuard anahtarı değil")
			}
			c.PeerKey, havePeerKey = k, true
		case "peer.endpoint":
			ap, err := netip.ParseAddrPort(value)
			if err != nil {
				host, port, ok := endpointName(value)
				if !ok {
					return nil, confErr(n, "Endpoint IP:port veya ad:port olmalı")
				}
				if resolve == nil {
					return nil, confErr(n, "Endpoint IP:port olmalı; ad çözümlemesi tünel dışına DNS sorgusu gönderirdi")
				}
				endpointHost, endpointPort, endpointLine, haveEndpoint = host, port, n, true
				continue
			}
			ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
			if ap.Port() == 0 || ap.Addr().Zone() != "" || ap.Addr().IsUnspecified() || ap.Addr().IsMulticast() {
				return nil, confErr(n, "Endpoint kullanılamaz")
			}
			c.Endpoint, haveEndpoint = ap, true
		case "peer.allowedips":
			for _, item := range splitItems(value) {
				p, err := netip.ParsePrefix(item)
				if err != nil {
					return nil, confErr(n, "AllowedIPs %s geçerli bir aralık değil", quoteShort(item))
				}
				switch {
				case p.Bits() == 0 && p.Addr().Is4():
					allow4 = true
				case p.Bits() == 0 && p.Addr().Is6():
					c.IPv6 = true
				default:
					// An upstream exit carries all internet traffic; a split
					// configuration would leave part of it on this host.
					return nil, confErr(n, "AllowedIPs yalnızca 0.0.0.0/0 ve ::/0 olabilir (tam tünel)")
				}
			}
			haveAllow = true
		default:
			return nil, confErr(n, "desteklenmeyen alan %s [%s] içinde; yalnızca PrivateKey, Address, DNS, MTU ve PublicKey, Endpoint, AllowedIPs kabul edilir", quoteShort(key), section)
		}
	}

	switch {
	case interfaces == 0:
		return nil, confErr(0, "[Interface] bölümü yok")
	case peers == 0:
		return nil, confErr(0, "[Peer] bölümü yok")
	case !havePriv:
		return nil, confErr(0, "PrivateKey yok")
	case !c.Address4.IsValid():
		return nil, confErr(0, "IPv4 tünel adresi (Address) yok")
	case len(c.DNS) == 0:
		// Members' DNS goes to the provider's resolver through the tunnel;
		// without one it would have to leave somewhere else.
		return nil, confErr(0, "DNS yok; üyelerin DNS sorguları sağlayıcının çözücüsüne tünel içinden gider")
	case !havePeerKey:
		return nil, confErr(0, "PublicKey yok")
	case !haveEndpoint:
		return nil, confErr(0, "Endpoint yok")
	case !haveAllow || !allow4:
		return nil, confErr(0, "AllowedIPs 0.0.0.0/0 içermeli")
	}
	if !c.IPv6 {
		// IPv6 addresses without ::/0 would never carry anything.
		c.Address6 = netip.Addr{}
	}
	pub, err := c.PublicKey()
	if err != nil {
		return nil, confErr(0, "PrivateKey kullanılamaz")
	}
	if pub == c.PeerKey {
		return nil, confErr(0, "PublicKey bu yapılandırmanın kendi anahtarı")
	}
	if endpointHost != "" {
		// The one DNS query of an import: the owner runs it, now; the
		// running tunnel never resolves anything.
		a, err := resolve(endpointHost)
		if err != nil {
			return nil, confErr(endpointLine, "Endpoint adı %s çözümlenemedi", quoteShort(endpointHost))
		}
		a = a.Unmap()
		if !a.IsValid() || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() {
			return nil, confErr(endpointLine, "Endpoint adı %s kullanılamayan bir adrese çözümlendi", quoteShort(endpointHost))
		}
		c.Endpoint, c.EndpointHost = netip.AddrPortFrom(a, endpointPort), endpointHost
	}
	return &c, nil
}

// endpointName splits "name:port" when name is a DNS host name (letters,
// digits, inner hyphens, dots; at least two labels) and port is 1-65535.
func endpointName(v string) (string, uint16, bool) {
	host, portText, err := net.SplitHostPort(v)
	if err != nil || host == "" || len(host) > maxHostLength || portText == "" || portText[0] == '+' {
		return "", 0, false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, false
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", 0, false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", 0, false
		}
		for i := 0; i < len(l); i++ {
			ch := l[i]
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", 0, false
			}
		}
	}
	// An all-numeric last label is a mistyped address, not a name.
	if _, err := strconv.Atoi(labels[len(labels)-1]); err == nil {
		return "", 0, false
	}
	return host, uint16(port), true
}

// Marshal writes the configuration back in canonical form: the comments
// and anything else of the original file are dropped.
func (c *Config) Marshal() []byte {
	var b bytes.Buffer
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + base64.StdEncoding.EncodeToString(c.PrivateKey[:]) + "\n")
	addrs := []string{netip.PrefixFrom(c.Address4, 32).String()}
	if c.Address6.IsValid() {
		addrs = append(addrs, netip.PrefixFrom(c.Address6, 128).String())
	}
	b.WriteString("Address = " + strings.Join(addrs, ", ") + "\n")
	dns := make([]string, len(c.DNS))
	for i, a := range c.DNS {
		dns[i] = a.String()
	}
	b.WriteString("DNS = " + strings.Join(dns, ", ") + "\n")
	if c.MTU != 0 {
		b.WriteString("MTU = " + strconv.Itoa(c.MTU) + "\n")
	}
	b.WriteString("\n")
	b.WriteString("[Peer]\n")
	b.WriteString("PublicKey = " + base64.StdEncoding.EncodeToString(c.PeerKey[:]) + "\n")
	allowed := "0.0.0.0/0"
	if c.IPv6 {
		allowed += ", ::/0"
	}
	b.WriteString("AllowedIPs = " + allowed + "\n")
	b.WriteString("Endpoint = " + c.Endpoint.String() + "\n")
	return b.Bytes()
}

// PublicKey derives this configuration's own public key, the one the
// provider lists for the device.
func (c *Config) PublicKey() ([keySize]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(c.PrivateKey[:])
	if err != nil {
		return [keySize]byte{}, err
	}
	var out [keySize]byte
	copy(out[:], priv.PublicKey().Bytes())
	return out, nil
}

// PublicKeyString is PublicKey in base64, "" on error.
func (c *Config) PublicKeyString() string {
	k, err := c.PublicKey()
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

// Wipe clears the private key.
func (c *Config) Wipe() {
	if c != nil {
		clear(c.PrivateKey[:])
	}
}

// ResolverFor returns the provider resolver to ask and the tunnel address
// to ask it from, preferring IPv4.
func (c *Config) ResolverFor() (server, source netip.Addr, ok bool) {
	for _, a := range c.DNS {
		if a.Is4() && c.Address4.IsValid() {
			return a, c.Address4, true
		}
	}
	for _, a := range c.DNS {
		if a.Is6() && c.Address6.IsValid() {
			return a, c.Address6, true
		}
	}
	return netip.Addr{}, netip.Addr{}, false
}

func parseKey(s string) ([keySize]byte, error) {
	var k [keySize]byte
	if len(s) != base64.StdEncoding.EncodedLen(keySize) {
		return k, errors.New("bad key length")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) != keySize {
		return k, errors.New("bad key")
	}
	copy(k[:], raw)
	clear(raw)
	return k, nil
}

func splitItems(v string) []string {
	var out []string
	for _, item := range strings.Split(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// usableUnicast rejects addresses that can never be a tunnel address or a
// resolver: unspecified, loopback, multicast, link-local and broadcast.
func usableUnicast(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
		return false
	}
	return a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// quoteShort quotes at most 40 bytes of s, for error messages.
func quoteShort(s string) string {
	if len(s) > 40 {
		s = s[:40] + "…"
	}
	return fmt.Sprintf("%q", s)
}
