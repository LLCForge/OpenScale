// Package privacy holds the local privacy measures of ADR-0008: log
// masking, process hardening against crash dumps, secure removal of the
// data directories and the local privacy report. Nothing here talks to the
// network.
package privacy

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
)

// Redacted replaces a secret value in a log record.
const Redacted = "[REDACTED]"

// maxMaskedLen bounds the text masked in one value; longer values are cut
// so a hostile string cannot make logging expensive.
const maxMaskedLen = 8 << 10

var (
	// ipv4Re finds dotted quads; the match is checked with netip.
	ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// ipv6Re finds runs of hex digits and colons with at least two colons
	// (optionally with a zone); the match is checked with netip.
	ipv6Re = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%[0-9A-Za-z_.-]{1,32})?`)
	// keyLikeRe finds base64 encoded 32-byte values (WireGuard and
	// Curve25519 keys look like this).
	keyLikeRe = regexp.MustCompile(`\b[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=`)
)

// secretKeyWords mark attribute names whose value is never logged at any
// level. The match is on lower-case substrings, so "device_key" and
// "PrivateKey" are both caught; a false positive only hides a value.
var secretKeyWords = []string{
	"key", "secret", "token", "password", "passphrase", "psk", "private",
	"seed", "cookie", "authorization", "credential", "bundle", "invite_code", "enrollment",
}

// IsSecretKey reports whether a log attribute with this name holds a secret.
func IsSecretKey(name string) bool {
	n := strings.ToLower(name)
	for _, w := range secretKeyWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// MaskAddr masks one IP address: an IPv4 address keeps its first two
// octets, an IPv6 address its first two groups. Loopback and unspecified
// addresses carry no information about the user and stay as they are.
func MaskAddr(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	if a.IsLoopback() || a.IsUnspecified() {
		return a.String()
	}
	if a.Is4() || a.Is4In6() {
		b := a.Unmap().As4()
		return fmt.Sprintf("%d.%d.*.*", b[0], b[1])
	}
	b := a.As16()
	return fmt.Sprintf("%x:%x:*", uint16(b[0])<<8|uint16(b[1]), uint16(b[2])<<8|uint16(b[3]))
}

// MaskText masks every IP address in s (with or without a port). Text
// that only looks like an address, such as a time of day, is left alone.
func MaskText(s string) string {
	if len(s) > maxMaskedLen {
		s = s[:maxMaskedLen] + "…"
	}
	s = ipv4Re.ReplaceAllStringFunc(s, func(m string) string {
		a, err := netip.ParseAddr(m)
		if err != nil {
			return m
		}
		return MaskAddr(a)
	})
	if strings.Count(s, ":") < 2 {
		return s
	}
	return ipv6Re.ReplaceAllStringFunc(s, func(m string) string {
		// "2001:db8::1: refused" matches with the trailing colon.
		addr := m
		suffix := ""
		for strings.HasSuffix(addr, ":") && !strings.HasSuffix(addr, "::") {
			addr, suffix = addr[:len(addr)-1], ":"+suffix
		}
		a, err := netip.ParseAddr(addr)
		if err != nil || !a.Is6() || a.Is4In6() {
			return m
		}
		return MaskAddr(a) + suffix
	})
}

// RedactSecrets hides values in s that look like keys in any log level:
// base64 32-byte keys and PEM blocks.
func RedactSecrets(s string) string {
	if strings.Contains(s, "-----BEGIN") {
		return Redacted
	}
	return keyLikeRe.ReplaceAllString(s, Redacted)
}

// MaskingHandler wraps a slog.Handler (ADR-0008, #42):
//   - attributes named like secrets and key-like values are redacted at
//     every level;
//   - at Info and above, IP addresses in the message and in string, error
//     and Stringer values are masked; Debug keeps them for the owner who
//     turned debugging on.
//
// Attributes bound with WithAttrs do not know the level of later records,
// so they are always masked.
type MaskingHandler struct {
	next slog.Handler
}

// NewMaskingHandler wraps next.
func NewMaskingHandler(next slog.Handler) *MaskingHandler {
	return &MaskingHandler{next: next}
}

// NewMaskedLogger is slog.New(NewMaskingHandler(h)).
func NewMaskedLogger(h slog.Handler) *slog.Logger {
	return slog.New(NewMaskingHandler(h))
}

// Enabled implements slog.Handler.
func (h *MaskingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

// Handle implements slog.Handler.
func (h *MaskingHandler) Handle(ctx context.Context, r slog.Record) error {
	maskIPs := r.Level >= slog.LevelInfo
	msg := RedactSecrets(r.Message)
	if maskIPs {
		msg = MaskText(msg)
	}
	out := slog.NewRecord(r.Time, r.Level, msg, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(maskAttr(a, maskIPs))
		return true
	})
	return h.next.Handle(ctx, out)
}

// WithAttrs implements slog.Handler.
func (h *MaskingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	masked := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		masked[i] = maskAttr(a, true)
	}
	return &MaskingHandler{next: h.next.WithAttrs(masked)}
}

// WithGroup implements slog.Handler.
func (h *MaskingHandler) WithGroup(name string) slog.Handler {
	return &MaskingHandler{next: h.next.WithGroup(name)}
}

// MaskAttr applies the masking rules to one attribute; maskIPs selects the
// Info-and-above behaviour.
func MaskAttr(a slog.Attr, maskIPs bool) slog.Attr { return maskAttr(a, maskIPs) }

func maskAttr(a slog.Attr, maskIPs bool) slog.Attr {
	if IsSecretKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindGroup:
		group := v.Group()
		out := make([]any, 0, len(group))
		for _, g := range group {
			out = append(out, maskAttr(g, maskIPs))
		}
		return slog.Group(a.Key, out...)
	case slog.KindString:
		return slog.String(a.Key, maskString(v.String(), maskIPs))
	case slog.KindAny:
		switch x := v.Any().(type) {
		case error:
			return slog.String(a.Key, maskString(x.Error(), maskIPs))
		case netip.Addr:
			if maskIPs {
				return slog.String(a.Key, MaskAddr(x))
			}
		case netip.AddrPort:
			if maskIPs {
				return slog.String(a.Key, MaskText(x.String()))
			}
		case netip.Prefix:
			if maskIPs {
				return slog.String(a.Key, MaskText(x.String()))
			}
		case fmt.Stringer:
			return slog.String(a.Key, maskString(x.String(), maskIPs))
		case []byte:
			// Raw bytes in a log line are never wanted; they may be key
			// material.
			return slog.String(a.Key, Redacted)
		}
	}
	return slog.Attr{Key: a.Key, Value: v}
}

func maskString(s string, maskIPs bool) string {
	s = RedactSecrets(s)
	if maskIPs {
		s = MaskText(s)
	}
	return s
}
