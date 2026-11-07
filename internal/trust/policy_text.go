package trust

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Text policy file (F-075, #228, ADR-0120): the groups, named addresses,
// rules and tests of a document as commented JSON. Comments start with //
// or # (or are /* ... */ blocks) and a comma before a closing bracket is
// allowed; otherwise it is plain JSON with the document's own field names,
// decoded strictly. The file is only a source: importing it changes a copy
// of the document, which is validated, tested, shown as a difference and
// then signed as raw bytes like every other version (R-15).

// MaxPolicyTextSize bounds a policy file.
const MaxPolicyTextSize = 1 << 20

// PolicyFile is the content of a text policy file. Every section must be
// present (possibly empty), so a file that forgets one cannot silently
// delete it.
type PolicyFile struct {
	Groups []Group        `json:"groups"`
	Hosts  []NamedAddress `json:"hosts"`
	Rules  []Rule         `json:"rules"`
	Tests  []PolicyTest   `json:"tests"`
}

var policySections = []string{"groups", "hosts", "rules", "tests"}

// ErrPolicyText is wrapped by every parse error of a policy file.
var ErrPolicyText = errors.New("politika dosyası geçersiz")

// stripJSONC blanks comments and trailing commas with spaces. The output
// has the input's length and line breaks, so JSON error offsets still
// point at the right line.
func stripJSONC(data []byte) ([]byte, error) {
	out := bytes.Clone(data)
	blank := func(from, to int) {
		for k := from; k < to; k++ {
			if out[k] != '\n' && out[k] != '\r' {
				out[k] = ' '
			}
		}
	}
	inString := false
	lastSig := -1
	for i := 0; i < len(out); i++ {
		c := out[i]
		if inString {
			switch c {
			case '\\':
				i++
			case '"':
				inString = false
				lastSig = i
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			lastSig = i
		case c == '#' || (c == '/' && i+1 < len(out) && out[i+1] == '/'):
			end := bytes.IndexByte(out[i:], '\n')
			if end < 0 {
				end = len(out) - i
			}
			blank(i, i+end)
			i += end - 1
		case c == '/' && i+1 < len(out) && out[i+1] == '*':
			end := bytes.Index(out[i+2:], []byte("*/"))
			if end < 0 {
				return nil, fmt.Errorf("%w: satır %d: kapanmayan /* yorumu", ErrPolicyText, lineOf(data, i))
			}
			blank(i, i+2+end+2)
			i += 2 + end + 1
		case c == ']' || c == '}':
			if lastSig >= 0 && out[lastSig] == ',' {
				out[lastSig] = ' '
			}
			lastSig = i
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
		default:
			lastSig = i
		}
	}
	return out, nil
}

func lineOf(data []byte, offset int) int {
	if offset > len(data) {
		offset = len(data)
	}
	if offset < 0 {
		offset = 0
	}
	return bytes.Count(data[:offset], []byte("\n")) + 1
}

// ParsePolicyText parses a policy file. Port names in tcp and udp rules
// are expanded to numbers (#110); "allow" actions are stored empty like
// AddRule does.
func ParsePolicyText(data []byte) (*PolicyFile, error) {
	if len(data) > MaxPolicyTextSize {
		return nil, fmt.Errorf("%w: dosya %d bayttan büyük", ErrPolicyText, MaxPolicyTextSize)
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	clean, err := stripJSONC(data)
	if err != nil {
		return nil, err
	}
	var sections map[string]json.RawMessage
	if err := json.Unmarshal(clean, &sections); err != nil {
		return nil, jsonError(data, err)
	}
	for _, s := range policySections {
		if _, ok := sections[s]; !ok {
			return nil, fmt.Errorf("%w: %q bölümü eksik (boşsa [] yazın)", ErrPolicyText, s)
		}
	}
	var p PolicyFile
	if err := decodeStrict(clean, &p); err != nil {
		return nil, jsonError(data, err)
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Action == RuleAllow {
			r.Action = ""
		}
		if r.Service == "" {
			ports, err := ExpandPortNames(r.Protocol, r.Ports)
			if err != nil {
				return nil, fmt.Errorf("%w: kural %d: %v", ErrPolicyText, i+1, err)
			}
			r.Ports = ports
		}
	}
	p.normalize()
	return &p, nil
}

func jsonError(data []byte, err error) error {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Errorf("%w: satır %d: %v", ErrPolicyText, lineOf(data, int(syn.Offset)), err)
	case errors.As(err, &typ):
		return fmt.Errorf("%w: satır %d: %s alanı için yanlış değer türü", ErrPolicyText, lineOf(data, int(typ.Offset)), typ.Field)
	}
	return fmt.Errorf("%w: %v", ErrPolicyText, err)
}

// normalize gives slices the shape the signed document has, so a parsed
// file and an exported document compare equal.
func (p *PolicyFile) normalize() {
	if p.Rules == nil {
		p.Rules = []Rule{}
	}
	if p.Groups == nil {
		p.Groups = []Group{}
	}
	if p.Hosts == nil {
		p.Hosts = []NamedAddress{}
	}
	if p.Tests == nil {
		p.Tests = []PolicyTest{}
	}
	for i := range p.Rules {
		if p.Rules[i].Ports == nil {
			p.Rules[i].Ports = []string{}
		}
	}
	for i := range p.Groups {
		if p.Groups[i].Members == nil {
			p.Groups[i].Members = []string{}
		}
	}
}

// PolicyFile returns a copy of the document's policy sections.
func (doc *Document) PolicyFile() (*PolicyFile, error) {
	c, err := doc.clone()
	if err != nil {
		return nil, err
	}
	p := &PolicyFile{Groups: c.Groups, Hosts: c.Hosts, Rules: c.Rules, Tests: c.PolicyTests}
	p.normalize()
	return p, nil
}

// ApplyPolicy replaces the document's groups, named addresses, rules and
// tests with the file's. Device tags, exit_users and everything else stay.
// The result is validated; the caller's Prepare also runs the tests.
func (doc *Document) ApplyPolicy(p *PolicyFile) error {
	if p == nil {
		return errors.New("policy file is missing")
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	var c PolicyFile
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}
	c.normalize()
	return doc.transact(func() error {
		doc.Groups, doc.Hosts, doc.PolicyTests = nil, nil, nil
		if len(c.Groups) > 0 {
			doc.Groups = c.Groups
		}
		if len(c.Hosts) > 0 {
			doc.Hosts = c.Hosts
		}
		if len(c.Tests) > 0 {
			doc.PolicyTests = c.Tests
		}
		doc.Rules = c.Rules
		return nil
	})
}

// RuleSummary renders a rule for comments and listings, for example
// "laptop <-> masaustu tcp/3389(rdp)".
func RuleSummary(r Rule) string {
	arrow := " -> "
	if r.Bidirectional {
		arrow = " <-> "
	}
	s := strings.Join(r.From, ",") + arrow + strings.Join(r.To, ",") + " "
	switch {
	case r.Service != "":
		s += "servis " + string(r.Service)
	default:
		s += string(r.Protocol)
		if len(r.Ports) > 0 {
			ports := make([]string, len(r.Ports))
			for i, p := range r.Ports {
				ports[i] = p
				if name := PortLabel(r.Protocol, p); name != "" {
					ports[i] += "(" + name + ")"
				}
			}
			s += "/" + strings.Join(ports, ",")
		}
		if len(r.ICMPTypes) > 0 {
			s += " [" + strings.Join(r.ICMPTypes, ",") + "]"
		}
	}
	if r.IsDeny() {
		s = "reddet: " + s
	}
	if t := RuleTimeSummary(r); t != "" {
		s += " (" + t + ")"
	}
	if r.Disabled {
		s += " (kapalı)"
	}
	return s
}

// RuleTimeSummary renders the time conditions of a rule, or "".
func RuleTimeSummary(r Rule) string {
	var parts []string
	if !r.NotBefore.IsZero() {
		parts = append(parts, "başlangıç "+r.NotBefore.UTC().Format(time.RFC3339))
	}
	if !r.NotAfter.IsZero() {
		parts = append(parts, "bitiş "+r.NotAfter.UTC().Format(time.RFC3339))
	}
	if s := r.Schedule; s != nil {
		days := "her gün"
		if len(s.Days) > 0 {
			days = strings.Join(s.Days, ",")
		}
		off := s.UTCOffset
		if off == "" {
			off = "UTC"
		}
		parts = append(parts, fmt.Sprintf("%s %s-%s %s", days, s.Start, s.End, off))
	}
	return strings.Join(parts, "; ")
}

// FormatPolicyText renders the document's policy as a commented policy
// file. It refuses when the text would not parse back to exactly the same
// policy, so exporting can never lose a field.
func FormatPolicyText(doc *Document) ([]byte, error) {
	p, err := doc.PolicyFile()
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString("// OpenScale politika dosyası (ADR-0120)\n")
	fmt.Fprintf(&b, "// Ağ %s, belge sürümü %d.\n", doc.NetworkID, doc.Version)
	b.WriteString("// Yorumlar // veya # ile başlar. Dosya imzalanmaz: 'openscale policy import'\n")
	b.WriteString("// doğrular, testleri çalıştırır, farkı gösterir ve belgeyi kök anahtarla imzalar.\n")
	fmt.Fprintf(&b, "// Port yerine ad yazılabilir. tcp: %s; udp: %s.\n", strings.Join(PortNames(ProtocolTCP), ", "), strings.Join(PortNames(ProtocolUDP), ", "))
	b.WriteString("{\n")
	b.WriteString("  // Gruplar: üyeler cihaz adı veya tag:<etiket>; kurallarda group:<ad>.\n")
	if err := writeSection(&b, "groups", p.Groups, nil, false); err != nil {
		return nil, err
	}
	b.WriteString("  // Adlandırılmış adresler: ağın kendi aralığında CIDR; kurallarda host:<ad>.\n")
	if err := writeSection(&b, "hosts", p.Hosts, nil, false); err != nil {
		return nil, err
	}
	b.WriteString("  // Kurallar: reddet her zaman izinden önce gelir; izin verilmeyen her şey reddedilir.\n")
	b.WriteString("  // Alanlar: from, to (cihaz, tag:, group:, host:, CIDR, *), protocol, ports, action (deny),\n")
	b.WriteString("  // bidirectional, icmp_types (echo, v4:<n>, v6:<n>), not_before, not_after, schedule.\n")
	rules := make([]string, len(p.Rules))
	for i, r := range p.Rules {
		rules[i] = fmt.Sprintf("%d: %s", i+1, RuleSummary(r))
	}
	if err := writeSection(&b, "rules", p.Rules, rules, false); err != nil {
		return nil, err
	}
	b.WriteString("  // Testler: {\"from\":\"a\",\"to\":\"b\",\"protocol\":\"tcp\",\"port\":22,\"expect\":\"deny\"}.\n")
	b.WriteString("  // İmzadan önce çalışır; biri başarısızsa belge imzalanmaz.\n")
	tests := make([]string, len(p.Tests))
	for i, t := range p.Tests {
		tests[i] = fmt.Sprintf("%d: %s", i+1, t.String())
	}
	if err := writeSection(&b, "tests", p.Tests, tests, true); err != nil {
		return nil, err
	}
	b.WriteString("}\n")
	back, err := ParsePolicyText(b.Bytes())
	if err != nil {
		return nil, fmt.Errorf("politika metne çevrilemedi: %w", err)
	}
	want, _ := json.Marshal(p)
	got, _ := json.Marshal(back)
	if !bytes.Equal(want, got) {
		return nil, errors.New("politika metne kayıpsız çevrilemedi; bu sürüm belgedeki bazı alanları tanımıyor")
	}
	return b.Bytes(), nil
}

func writeSection[T any](b *bytes.Buffer, name string, items []T, comments []string, last bool) error {
	fmt.Fprintf(b, "  %q: [", name)
	if len(items) == 0 {
		b.WriteString("]")
	} else {
		b.WriteString("\n")
		for i, it := range items {
			line, err := json.Marshal(it)
			if err != nil {
				return err
			}
			if i < len(comments) {
				// Comments hold only validated names, numbers and fixed
				// words, never free text such as descriptions.
				b.WriteString("    // " + strings.ReplaceAll(comments[i], "\n", " ") + "\n")
			}
			b.WriteString("    ")
			b.Write(line)
			if i < len(items)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString("  ]")
	}
	if !last {
		b.WriteString(",")
	}
	b.WriteString("\n")
	return nil
}
