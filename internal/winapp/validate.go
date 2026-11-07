package winapp

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf16"
)

const (
	maxProgramPathLen = 1024
	maxURLLen         = 2048
)

// validateProgramPath accepts only an absolute, drive-letter Windows path to
// an .exe file. The value ends up as a netsh argument, so anything that could
// be interpreted as an extra token or a different file is rejected.
func validateProgramPath(p string) (string, error) {
	if p == "" {
		return "", errors.New("program yolu boş")
	}
	if len(p) > maxProgramPathLen {
		return "", errors.New("program yolu çok uzun")
	}
	if len(p) < 4 || !isASCIILetter(p[0]) || p[1] != ':' || p[2] != '\\' {
		return "", fmt.Errorf("program yolu mutlak bir Windows yolu olmalı (ör. C:\\...): %q", p)
	}
	for i, r := range p {
		switch {
		case r < 0x20 || r == 0x7f:
			return "", errors.New("program yolu kontrol karakteri içeremez")
		case r == '"' || r == '<' || r == '>' || r == '|' || r == '?' || r == '*' || r == '/':
			return "", fmt.Errorf("program yolunda geçersiz karakter: %q", r)
		case r == ':' && i != 1:
			return "", errors.New("program yolunda geçersiz ':' karakteri")
		case r == '\uFFFD':
			return "", errors.New("program yolu geçerli UTF-8 değil")
		}
	}
	for _, part := range strings.Split(p[3:], `\`) {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("program yolu sadeleştirilmiş olmalı: %q", p)
		}
		if strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return "", fmt.Errorf("program yolu nokta veya boşlukla biten bir bileşen içeremez: %q", p)
		}
	}
	if !strings.EqualFold(p[len(p)-4:], ".exe") {
		return "", errors.New("program yolu bir .exe dosyasını göstermeli")
	}
	return p, nil
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// validateIPv4CIDR parses an IPv4 prefix such as 100.80.0.0/16 and returns
// its canonical, masked form. A /0 prefix is refused because it would open
// ping to the whole Internet.
func validateIPv4CIDR(s string) (string, error) {
	if s == "" {
		return "", errors.New("ağ aralığı boş")
	}
	if len(s) > len("255.255.255.255/32") {
		return "", fmt.Errorf("geçersiz ağ aralığı: %q", s)
	}
	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		return "", fmt.Errorf("geçersiz ağ aralığı %q: CIDR biçiminde olmalı (ör. 100.80.0.0/16)", s)
	}
	if !pfx.Addr().Is4() {
		return "", fmt.Errorf("ağ aralığı IPv4 olmalı: %q", s)
	}
	if pfx.Bits() < 1 {
		return "", errors.New("ağ aralığı /0 olamaz")
	}
	return pfx.Masked().String(), nil
}

// firewallAddArgs returns the netsh argument lists that (re)create the
// OpenScale inbound rules. Inputs must already be validated.
func firewallAddArgs(exePath, cidr string) [][]string {
	return [][]string{
		{
			"advfirewall", "firewall", "add", "rule",
			"name=" + firewallRuleUDP,
			"dir=in", "action=allow", "protocol=UDP",
			"program=" + exePath,
			"profile=any", "enable=yes",
		},
		{
			"advfirewall", "firewall", "add", "rule",
			"name=" + firewallRulePing,
			"dir=in", "action=allow", "protocol=icmpv4:8,any",
			"remoteip=" + cidr,
			"profile=any", "enable=yes",
		},
	}
}

func firewallDeleteArgs() [][]string {
	return [][]string{
		{"advfirewall", "firewall", "delete", "rule", "name=" + firewallRuleUDP},
		{"advfirewall", "firewall", "delete", "rule", "name=" + firewallRulePing},
	}
}

// validateLoopbackURL accepts only plain http URLs whose host is a loopback IP
// literal (127.0.0.0/8 or ::1). Host names, credentials and other schemes are
// refused so the shell can never be asked to open something remote.
func validateLoopbackURL(raw string) (string, error) {
	if raw == "" || len(raw) > maxURLLen {
		return "", errors.New("geçersiz adres")
	}
	for _, r := range raw {
		if r < 0x21 || r == 0x7f || r == '"' || r == '\\' {
			return "", errors.New("adres geçersiz karakter içeriyor")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("adres çözümlenemedi")
	}
	if u.Scheme != "http" || u.Opaque != "" || u.User != nil {
		return "", errors.New("yalnızca http://127.0.0.1 adresleri açılabilir")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.Unmap().IsLoopback() || ip.Zone() != "" {
		return "", errors.New("yalnızca bu bilgisayardaki (127.0.0.1) adresler açılabilir")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("adresteki port geçersiz")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return "", errors.New("adresteki port geçersiz")
	}
	return u.String(), nil
}

// copyUTF16 writes s into the fixed-size, NUL-terminated buffer dst,
// truncating without splitting a surrogate pair. Embedded NULs are dropped.
func copyUTF16(dst []uint16, s string) {
	clear(dst)
	if len(dst) == 0 {
		return
	}
	enc := utf16.Encode([]rune(strings.ReplaceAll(s, "\x00", "")))
	n := min(len(enc), len(dst)-1)
	if n > 0 && n < len(enc) && utf16.IsSurrogate(rune(enc[n-1])) && enc[n-1] < 0xDC00 {
		n-- // do not leave a lone high surrogate at the end
	}
	copy(dst, enc[:n])
}

// menuLabel escapes '&' (mnemonic prefix in Win32 menus) and drops NULs and
// line breaks so arbitrary device names render literally.
func menuLabel(s string) string {
	s = strings.Map(func(r rune) rune {
		switch r {
		case 0:
			return -1
		case '\r', '\n', '\t':
			return ' '
		}
		return r
	}, s)
	return strings.ReplaceAll(s, "&", "&&")
}
