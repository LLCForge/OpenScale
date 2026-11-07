// Package urlclean removes tracking parameters from addresses an exit
// node sees in plain text HTTP (#722, ADR-0214).
//
// What it can and cannot do, honestly:
//
//   - It works only on unencrypted HTTP. The Location header of a plain
//     HTTP redirect and the Referer header of a plain HTTP request are
//     visible to the exit node; their tracking parameters are removed.
//   - HTTPS is never touched. The exit node cannot read or change an
//     encrypted request or response and OpenScale does not intercept TLS:
//     no certificate is installed on any device. Most of the web is
//     HTTPS, so this cleans only a small part of the traffic.
//   - A redirect that leads to an HTTPS address is cleaned only because
//     the redirect itself travelled in plain text; the HTTPS page and its
//     own redirects stay as they are.
//
// The functions are pure: no I/O, no logging of addresses.
package urlclean

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Limits.
const (
	MaxRuleFileSize = 64 << 10
	MaxRules        = 1024
	MaxURLLen       = 8192
	maxRuleLen      = 128
)

// defaultExact are well known click and campaign identifiers; defaultPrefix
// are parameter families (utm_source, utm_medium, ...).
var (
	defaultExact = []string{
		"fbclid", "gclid", "gclsrc", "dclid", "gbraid", "wbraid", "msclkid", "yclid", "twclid",
		"ttclid", "li_fat_id", "igshid", "igsh", "mc_eid", "mc_cid", "_hsenc", "_hsmi", "__hssc",
		"__hstc", "__hsfp", "hsctatracking", "mkt_tok", "oly_anon_id", "oly_enc_id", "vero_id",
		"vero_conv", "_openstat", "wickedid", "rb_clickid", "s_cid", "ef_id", "srsltid", "si",
		"_ga", "_gl", "ga_source", "ga_medium", "ga_campaign", "ga_content", "ga_term",
	}
	defaultPrefix = []string{"utm_", "pk_", "mtm_", "piwik_", "matomo_", "hmb_"}
)

// Rules is a set of parameter names to remove; immutable once built.
type Rules struct {
	exact  map[string]bool
	prefix []string
}

// DefaultRules returns the built-in list. "si" is included because it is
// the share identifier of common media links; it is a plain parameter
// name, never a site.
func DefaultRules() *Rules {
	r := &Rules{exact: map[string]bool{}}
	for _, n := range defaultExact {
		r.exact[n] = true
	}
	r.prefix = append(r.prefix, defaultPrefix...)
	return r
}

// ParseRules reads the owner's extra rules on top of the defaults: one
// parameter name per line, "prefix*" for a family, "!name" to keep a
// default one, '#' comments. Names are case-insensitive.
func ParseRules(r io.Reader) (*Rules, error) {
	out := DefaultRules()
	sc := bufio.NewScanner(io.LimitReader(r, MaxRuleFileSize+1))
	sc.Buffer(make([]byte, 0, 1024), 1024)
	read, n := 0, 0
	for sc.Scan() {
		read += len(sc.Bytes()) + 1
		if read > MaxRuleFileSize {
			return nil, errors.New("kural dosyası çok büyük")
		}
		s := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(s, '#'); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
		if s == "" {
			continue
		}
		if n++; n > MaxRules {
			return nil, fmt.Errorf("en fazla %d kural olabilir", MaxRules)
		}
		s = strings.ToLower(s)
		keep := strings.HasPrefix(s, "!")
		s = strings.TrimPrefix(s, "!")
		pfx := strings.HasSuffix(s, "*")
		s = strings.TrimSuffix(s, "*")
		if !validParam(s) {
			return nil, fmt.Errorf("geçersiz parametre adı: %q", sc.Text())
		}
		switch {
		case keep && pfx:
			out.prefix = remove(out.prefix, s)
		case keep:
			delete(out.exact, s)
		case pfx:
			if !contains(out.prefix, s) {
				out.prefix = append(out.prefix, s)
			}
		default:
			out.exact[s] = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("kural dosyası okunamadı: %w", err)
	}
	sort.Strings(out.prefix)
	return out, nil
}

func validParam(s string) bool {
	if s == "" || len(s) > maxRuleLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func remove(l []string, s string) []string {
	out := l[:0:0]
	for _, x := range l {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

// Tracking reports whether a parameter name (raw, possibly escaped) is
// removed by the rules.
func (r *Rules) Tracking(name string) bool {
	if n, err := url.QueryUnescape(name); err == nil {
		name = n
	}
	name = strings.ToLower(name)
	if r.exact[name] {
		return true
	}
	for _, p := range r.prefix {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// CleanURL removes tracking parameters from raw and returns the result
// and the number removed. Every other byte, including the order and the
// escaping of the remaining parameters and the fragment, is unchanged.
// Addresses that do not parse, are longer than MaxURLLen or have no query
// are returned as they are.
func (r *Rules) CleanURL(raw string) (string, int) {
	if len(raw) > MaxURLLen {
		return raw, 0
	}
	if _, err := url.Parse(raw); err != nil {
		return raw, 0
	}
	q := strings.IndexByte(raw, '?')
	if q < 0 {
		return raw, 0
	}
	head, rest := raw[:q], raw[q+1:]
	frag := ""
	if h := strings.IndexByte(rest, '#'); h >= 0 {
		rest, frag = rest[:h], rest[h:]
	}
	if q2 := strings.IndexByte(head, '#'); q2 >= 0 {
		return raw, 0 // '?' inside the fragment: no query
	}
	parts := strings.Split(rest, "&")
	kept := parts[:0:0]
	removed := 0
	for _, p := range parts {
		name := p
		if i := strings.IndexByte(p, '='); i >= 0 {
			name = p[:i]
		}
		if name != "" && r.Tracking(name) {
			removed++
			continue
		}
		kept = append(kept, p)
	}
	if removed == 0 {
		return raw, 0
	}
	out := head
	if len(kept) > 0 {
		out += "?" + strings.Join(kept, "&")
	}
	return out + frag, removed
}

// redirectStatus are the HTTP redirect codes with a Location header.
var redirectStatus = map[int]bool{
	http.StatusMovedPermanently: true, http.StatusFound: true, http.StatusSeeOther: true,
	http.StatusTemporaryRedirect: true, http.StatusPermanentRedirect: true,
}

// CleanRedirect is applied by the exit node to a response it relays. It
// changes nothing unless the connection is plain text HTTP (requestScheme
// "http", never "https") and status is a redirect; then the Location value
// is cleaned. changed reports whether the header must be rewritten.
func (r *Rules) CleanRedirect(requestScheme string, status int, location string) (string, bool) {
	if !strings.EqualFold(requestScheme, "http") || !redirectStatus[status] || location == "" {
		return location, false
	}
	out, n := r.CleanURL(location)
	return out, n > 0
}

// CleanReferer is applied to a plain text HTTP request's Referer header:
// tracking parameters of the page the user came from are removed. HTTPS
// requests are never touched.
func (r *Rules) CleanReferer(requestScheme, referer string) (string, bool) {
	if !strings.EqualFold(requestScheme, "http") || referer == "" {
		return referer, false
	}
	out, n := r.CleanURL(referer)
	return out, n > 0
}
