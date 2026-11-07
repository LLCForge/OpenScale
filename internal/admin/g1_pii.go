package admin

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/openscale/openscale/internal/trust"
)

// Personal data warnings for network names (#688, ADR-0177). Device names,
// aliases, tags, groups, the network name, rule descriptions and DNS
// records end up on every member and (unless #629 is used) on the
// coordinator. Before a signature the owner is warned when one of them
// looks like an e-mail address, a phone number, a Turkish identity number
// or a common given name. A warning never blocks; it is a local check and
// nothing is sent anywhere.

// PII kinds.
const (
	PIIEmail    = "e-posta"
	PIIPhone    = "telefon"
	PIINationID = "kimlik numarası"
	PIIName     = "kişi adı"
)

// PIIWarning is one suspicious value.
type PIIWarning struct {
	Field string `json:"field"`
	Value string `json:"value"`
	Kind  string `json:"kind"`
}

// String renders the warning in Turkish.
func (w PIIWarning) String() string {
	return fmt.Sprintf("UYARI (kişisel veri): %s %q bir %s içeriyor olabilir", w.Field, w.Value, w.Kind)
}

var (
	reEmail  = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	reDigits = regexp.MustCompile(`\+?\d[\d\s().\-]{6,}\d`)
)

// commonGivenNames is a short list of very common Turkish and English
// given names (ASCII-folded, lowercase). It is a heuristic: it finds
// "ahmet-laptop" and "maria-phone", not every name.
var commonGivenNames = []string{
	"ahmet", "mehmet", "mustafa", "ali", "huseyin", "hasan", "ibrahim", "ismail", "yusuf", "omer",
	"murat", "emre", "burak", "onur", "serkan", "kemal", "osman", "fatih", "can", "cem",
	"ayse", "fatma", "emine", "hatice", "zeynep", "elif", "merve", "esra", "ozlem", "selin",
	"ebru", "derya", "gamze", "busra", "seda", "yasemin", "aylin", "deniz", "ece", "irem",
	"john", "james", "robert", "michael", "william", "david", "richard", "thomas", "daniel", "paul",
	"mary", "patricia", "jennifer", "linda", "elizabeth", "susan", "sarah", "jessica", "maria", "anna",
	"peter", "mark", "lisa", "laura", "emma", "olivia", "sophia", "lucas", "noah", "liam",
}

// PersonalDataWarnings scans the names in doc.
func PersonalDataWarnings(doc *trust.Document) []PIIWarning {
	var out []PIIWarning
	check := func(field, value string) {
		if value == "" {
			return
		}
		for _, kind := range piiKinds(value) {
			w := PIIWarning{Field: field, Value: value, Kind: kind}
			if !slices.Contains(out, w) {
				out = append(out, w)
			}
		}
	}
	check("ağ adı", doc.DisplayName)
	for _, d := range doc.Devices {
		check("cihaz adı", d.Name)
		for _, a := range d.Aliases {
			check("cihaz takma adı", a)
		}
		for _, t := range d.Tags {
			check("etiket", t)
		}
	}
	for _, g := range doc.Groups {
		check("grup", g.Name)
	}
	for _, r := range doc.Rules {
		check("kural açıklaması", r.Description)
	}
	for _, i := range doc.Invites {
		for _, t := range i.Tags {
			check("davet etiketi", t)
		}
	}
	for _, s := range jsonStrings(doc.MagicDNS) {
		check("DNS kaydı", s)
	}
	return out
}

// newPIIWarnings returns the warnings of next whose value prev did not
// already carry, so the diff warns once per new value.
func newPIIWarnings(prev, next *trust.Document) []PIIWarning {
	old := PersonalDataWarnings(prev)
	var out []PIIWarning
	for _, w := range PersonalDataWarnings(next) {
		if !slices.Contains(old, w) {
			out = append(out, w)
		}
	}
	return out
}

func piiKinds(value string) []string {
	var kinds []string
	if reEmail.MatchString(value) {
		kinds = append(kinds, PIIEmail)
	}
	for _, m := range reDigits.FindAllString(value, -1) {
		digits := onlyDigits(m)
		switch {
		case len(digits) == 11 && validTCKN(digits):
			kinds = append(kinds, PIINationID)
		case len(digits) >= 10 && len(digits) <= 15:
			kinds = append(kinds, PIIPhone)
		}
	}
	// A bare run of 10-15 digits in a label ("05321234567").
	if !slices.Contains(kinds, PIIPhone) && !slices.Contains(kinds, PIINationID) {
		for _, tok := range tokens(value) {
			d := onlyDigits(tok)
			if len(d) == len(tok) && len(d) == 11 && validTCKN(d) {
				kinds = append(kinds, PIINationID)
			} else if len(d) == len(tok) && len(d) >= 10 && len(d) <= 15 {
				kinds = append(kinds, PIIPhone)
			}
		}
	}
	for _, tok := range tokens(value) {
		if isGivenName(foldASCII(tok)) {
			kinds = append(kinds, PIIName)
			break
		}
	}
	slices.Sort(kinds)
	return slices.Compact(kinds)
}

func tokens(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || r == ' ' || r == ':' || r == '@' || r == '/'
	})
}

func isGivenName(tok string) bool {
	for _, n := range commonGivenNames {
		if tok == n {
			return true
		}
		// Turkish suffixes: "ahmetin", "zeynepnin"; only for names long
		// enough not to match ordinary words.
		if len(n) >= 4 && strings.HasPrefix(tok, n) && len(tok)-len(n) <= 3 && !strings.ContainsFunc(tok[len(n):], unicode.IsDigit) {
			return true
		}
	}
	return false
}

func foldASCII(s string) string {
	r := strings.NewReplacer("ç", "c", "ğ", "g", "ı", "i", "ö", "o", "ş", "s", "ü", "u", "İ", "i")
	return r.Replace(s)
}

func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// validTCKN checks the Turkish identity number checksum.
func validTCKN(d string) bool {
	if len(d) != 11 || d[0] == '0' {
		return false
	}
	var n [11]int
	for i := range d {
		n[i] = int(d[i] - '0')
	}
	odd := n[0] + n[2] + n[4] + n[6] + n[8]
	even := n[1] + n[3] + n[5] + n[7]
	d10 := ((odd*7-even)%10 + 10) % 10
	if d10 != n[9] {
		return false
	}
	sum := 0
	for i := 0; i < 10; i++ {
		sum += n[i]
	}
	return sum%10 == n[10]
}

// jsonStrings returns every string value of v's JSON form.
func jsonStrings(v any) []string {
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var tree any
	if json.Unmarshal(data, &tree) != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(tree)
	slices.Sort(out)
	return out
}

// g1Changes adds the ADR-0172/0174/0177 lines to the diff.
func g1Changes(prev, next *trust.Document) []string {
	var out []string
	for _, id := range next.RevokedAdmins {
		if !slices.Contains(prev.RevokedAdmins, id) {
			out = append(out, "Yönetici yetkisi geri alındı: "+id)
		}
	}
	switch {
	case prev.Sensitive == nil && next.Sensitive != nil:
		out = append(out, fmt.Sprintf("Hassas cihaz çift onay kuralı: %s (%d/%d onay)", strings.Join(next.Sensitive.Targets, ", "), next.Sensitive.Threshold, len(next.Sensitive.Approvers)))
	case prev.Sensitive != nil && next.Sensitive == nil:
		out = append(out, "Hassas cihaz çift onay kuralı: kaldırıldı (mevcut onaycıların imzası gerekir)")
	case !prev.Sensitive.Equal(next.Sensitive):
		out = append(out, fmt.Sprintf("Hassas cihaz çift onay kuralı değişti: %s (%d/%d onay)", strings.Join(next.Sensitive.Targets, ", "), next.Sensitive.Threshold, len(next.Sensitive.Approvers)))
	}
	if next.Sensitive != nil && trust.SensitiveFingerprint(prev) != trust.SensitiveFingerprint(next) {
		out = append(out, "Hassas cihazlara erişim değişti: bu sürüm onaycıların yeni imzalarını ister (openscale admin sensitive approve)")
	}
	if (len(prev.RevokedAdmins) == 0 && prev.Sensitive == nil) && (len(next.RevokedAdmins) > 0 || next.Sensitive != nil) {
		out = append(out, "UYARI: bu sürüm yeni belge alanı kullanıyor; ADR-0172/0174 öncesi cihazlar ve koordinatör onu reddeder")
	}
	for _, w := range newPIIWarnings(prev, next) {
		out = append(out, w.String())
	}
	return out
}
