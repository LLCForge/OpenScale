package webview

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// action is what the window does with a URL it is asked to load.
type action int

const (
	// actionBlock refuses the URL.
	actionBlock action = iota
	// actionAllow loads the URL in the window.
	actionAllow
	// actionExternal hands the URL to the system browser.
	actionExternal
)

func (a action) String() string {
	switch a {
	case actionAllow:
		return "allow"
	case actionExternal:
		return "external"
	default:
		return "block"
	}
}

// origin is the single loopback origin the window may show.
type origin struct {
	addr netip.Addr
	port uint16
}

func (o origin) String() string {
	return "http://" + netip.AddrPortFrom(o.addr, o.port).String()
}

// maxExternalURLBytes bounds what is handed to the system browser.
const maxExternalURLBytes = 2048

// errOrigin is returned for a malformed AllowedOrigin.
var errOrigin = errors.New("webview: AllowedOrigin http://127.0.0.1:<port> veya http://[::1]:<port> biçiminde olmalı")

// parseOrigin accepts exactly http://127.0.0.1:<port> or http://[::1]:<port>
// with an explicit port and nothing after it but an optional "/".
func parseOrigin(s string) (origin, error) {
	if strings.ContainsAny(s, "\\\x00\r\n\t ") {
		return origin{}, errOrigin
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "http" || u.Opaque != "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return origin{}, errOrigin
	}
	addr, port, ok := hostPort(u)
	if !ok || port == 0 || !strings.Contains(u.Host, ":") {
		return origin{}, errOrigin
	}
	if addr != netip.MustParseAddr("127.0.0.1") && addr != netip.IPv6Loopback() {
		return origin{}, errOrigin
	}
	return origin{addr: addr, port: port}, nil
}

// resolveOrigin returns the AllowedOrigin, or the origin of start when
// allowed is empty.
func resolveOrigin(allowed, start string) (origin, error) {
	if allowed != "" {
		return parseOrigin(allowed)
	}
	u, err := url.Parse(start)
	if err != nil || u.Scheme != "http" || u.Host == "" {
		return origin{}, fmt.Errorf("webview: AllowedOrigin boş ve başlangıç adresi bir loopback http adresi değil")
	}
	return parseOrigin("http://" + u.Host)
}

// hostPort returns the literal IP address and the effective port of an
// http(s) URL. Host names are refused: only an IP literal can be compared
// without a resolver.
func hostPort(u *url.URL) (netip.Addr, uint16, bool) {
	host := u.Hostname()
	if host == "" {
		return netip.Addr{}, 0, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, 0, false
	}
	// 127.0.0.1 written as ::ffff:127.0.0.1 is a different origin for the
	// web engine; keep it different here too.
	ps := u.Port()
	if ps == "" {
		if strings.HasSuffix(u.Host, ":") {
			return netip.Addr{}, 0, false
		}
		switch u.Scheme {
		case "http":
			return addr, 80, true
		case "https":
			return addr, 443, true
		}
		return netip.Addr{}, 0, false
	}
	if len(ps) > 1 && ps[0] == '0' {
		return netip.Addr{}, 0, false
	}
	p, err := strconv.ParseUint(ps, 10, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	return addr, uint16(p), true
}

// check decides what happens to a top-level or frame navigation to raw.
// userInitiated is ignored here; see navigate.
func (o origin) check(raw string) action {
	if raw == "about:blank" {
		return actionAllow
	}
	if raw == "" || len(raw) > maxURLBytes || strings.ContainsAny(raw, "\\\x00\r\n\t") {
		return actionBlock
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil {
		return actionBlock
	}
	if u.Scheme != "http" {
		return actionBlock
	}
	addr, port, ok := hostPort(u)
	if !ok || addr != o.addr || port != o.port {
		return actionBlock
	}
	return actionAllow
}

// navigate decides a navigation or new-window request: inside the origin it
// is allowed; an https link the user clicked goes to the system browser;
// everything else is blocked.
func (o origin) navigate(raw string, userInitiated bool) action {
	if a := o.check(raw); a == actionAllow {
		return a
	}
	if userInitiated && externalURL(raw) != "" {
		return actionExternal
	}
	return actionBlock
}

// externalURL returns the canonical form of raw when it may be handed to
// the system browser: https, a host name or public-looking address, no
// user information, bounded length. It returns "" otherwise.
func externalURL(raw string) string {
	if raw == "" || len(raw) > maxExternalURLBytes || strings.ContainsAny(raw, "\\\x00\r\n\t \"'<>`") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Host == "" {
		return ""
	}
	host := u.Hostname()
	if host == "" || strings.HasPrefix(host, "-") {
		return ""
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		// Loopback and link-local services of this computer are never
		// opened outside the window.
		if addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() {
			return ""
		}
	} else if !externalHostName(host) {
		return ""
	}
	s := u.String()
	if len(s) > maxExternalURLBytes {
		return ""
	}
	return s
}

// externalHostName reports whether host (not an IP literal) is a plain DNS
// name the system browser may be sent to. Browsers turn more spellings into
// a loopback address than netip parses: "localhost." (trailing dot),
// IPv4 shorthand such as "127.1", "2130706433", "0x7f000001" or
// "0177.0.0.1", and full-width or percent-encoded letters that IDNA maps to
// "localhost". So only ASCII letters, digits, '-' and '.' are accepted, no
// empty label (which also refuses a trailing dot), no "localhost" name, and
// a name whose last label is numeric or hexadecimal is refused: a real
// top-level domain never is.
func externalHostName(host string) bool {
	if len(host) > 253 {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	lower := strings.ToLower(host)
	labels := strings.Split(lower, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return false
		}
	}
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return false
	}
	last := labels[len(labels)-1]
	if strings.HasPrefix(last, "0x") || strings.Trim(last, "0123456789") == "" {
		return false
	}
	return true
}

// subresource decides a request made by a page (image, script, fetch):
// the origin, data: and blob: of the origin are allowed, everything else
// is blocked. Navigations use navigate instead.
func (o origin) subresource(raw string) bool {
	if o.check(raw) == actionAllow && raw != "about:blank" {
		return true
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "data:") {
		return true
	}
	if rest, ok := strings.CutPrefix(lower, "blob:"); ok {
		return o.check(rest) == actionAllow && rest != "about:blank"
	}
	return false
}

// browserArguments are the engine flags that enforce the origin at the
// network level (WebView2). Every request goes through a proxy that is
// the allowed origin itself, except requests to the origin, which go
// direct: a request outside the origin reaches only the panel, which
// refuses the foreign Host, and never another computer or another local
// service. "<-loopback>" removes the engine's implicit loopback bypass.
func browserArguments(o origin) string {
	hp := netip.AddrPortFrom(o.addr, o.port).String()
	return "--proxy-server=http://" + hp + " --proxy-bypass-list=<-loopback>;" + hp
}
