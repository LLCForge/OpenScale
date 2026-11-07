// Package netreport turns a network document into a readable report
// (#553): devices, roles, rules as sentences, DNS and coordinators, as
// Markdown or a self-contained HTML page. It is for the owner's records
// and for sharing with family; it never contains a key, a key
// fingerprint, an invite secret or a signature, so passing it on reveals
// the network's shape but gives no way into it.
package netreport

import (
	"bytes"
	"fmt"
	"html/template"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Schema of the report's data.
const Schema = 1

// Report is the data of a report; every field is plain text.
type Report struct {
	Schema       int           `json:"schema"`
	Network      string        `json:"network"`
	Domain       string        `json:"domain"`
	Version      uint64        `json:"version"`
	IssuedAt     time.Time     `json:"issuedAt"`
	ExpiresAt    time.Time     `json:"expiresAt"`
	CreatedAt    time.Time     `json:"createdAt"`
	IPv4Prefix   string        `json:"ipv4Prefix"`
	IPv6Prefix   string        `json:"ipv6Prefix"`
	Devices      []Device      `json:"devices"`
	Groups       []Group       `json:"groups"`
	Rules        []Rule        `json:"rules"`
	ExitUsers    string        `json:"exitUsers"`
	DNS          []string      `json:"dns"`
	Coordinators []Coordinator `json:"coordinators"`
}

// Device is one row of the device table.
type Device struct {
	Name      string `json:"name"`
	IPv4      string `json:"ipv4"`
	Roles     string `json:"roles"`
	Tags      string `json:"tags"`
	Expires   string `json:"expires"`
	Routes    string `json:"routes,omitempty"`
	Ephemeral bool   `json:"ephemeral,omitempty"`
}

// Group is a group and its members.
type Group struct {
	Name    string `json:"name"`
	Members string `json:"members"`
}

// Rule is one access rule as a sentence.
type Rule struct {
	Number   int    `json:"number"`
	Sentence string `json:"sentence"`
	Allow    bool   `json:"allow"`
	Disabled bool   `json:"disabled,omitempty"`
}

// Coordinator is one coordinator.
type Coordinator struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	Region   string `json:"region,omitempty"`
}

const dateForm = "2006-01-02"

// Build makes the report of doc at now.
func Build(doc *trust.Document, now time.Time) Report {
	r := Report{
		Schema:     Schema,
		Network:    doc.DisplayName,
		Domain:     doc.DNSDomain,
		Version:    doc.Version,
		IssuedAt:   doc.IssuedAt.UTC(),
		ExpiresAt:  doc.ExpiresAt.UTC(),
		CreatedAt:  now.UTC(),
		IPv4Prefix: prefixText(doc.IPv4Prefix.IsValid(), doc.IPv4Prefix.String()),
		IPv6Prefix: prefixText(doc.IPv6Prefix.IsValid(), doc.IPv6Prefix.String()),
		// Empty lists, never null, so templates and scripts can count them.
		Devices: []Device{}, Groups: []Group{}, Rules: []Rule{}, Coordinators: []Coordinator{},
	}
	if r.Network == "" {
		r.Network = doc.DNSDomain
	}
	for _, d := range doc.Devices {
		row := Device{Name: d.Name, IPv4: addrText(d.IPv4.IsValid(), d.IPv4.String()), Tags: strings.Join(d.Tags, ", "), Ephemeral: d.Ephemeral}
		var roles []string
		for _, role := range d.Roles {
			roles = append(roles, roleText(role))
		}
		row.Roles = strings.Join(roles, ", ")
		if !d.ExpiresAt.IsZero() {
			row.Expires = d.ExpiresAt.UTC().Format(dateForm)
		}
		var routes []string
		for _, p := range d.Routes {
			routes = append(routes, p.String())
		}
		row.Routes = strings.Join(routes, ", ")
		r.Devices = append(r.Devices, row)
	}
	slices.SortFunc(r.Devices, func(a, b Device) int { return strings.Compare(a.Name, b.Name) })
	for _, g := range doc.Groups {
		var members []string
		for _, m := range g.Members {
			members = append(members, entryText(m))
		}
		r.Groups = append(r.Groups, Group{Name: g.Name, Members: strings.Join(members, ", ")})
	}
	for i, rule := range doc.Rules {
		r.Rules = append(r.Rules, Rule{Number: i + 1, Sentence: RuleSentence(rule), Allow: rule.Action != trust.RuleDeny, Disabled: rule.Disabled})
	}
	switch {
	case doc.ExitUsers == nil:
		r.ExitUsers = "Çıkış düğümlerini bütün cihazlar kullanabilir."
	case len(*doc.ExitUsers) == 0:
		r.ExitUsers = "Çıkış düğümlerini hiçbir cihaz kullanamaz."
	default:
		r.ExitUsers = "Çıkış düğümlerini yalnızca şunlar kullanabilir: " + entriesText(*doc.ExitUsers) + "."
	}
	r.DNS = dnsLines(doc)
	if r.DNS == nil {
		r.DNS = []string{}
	}
	if c := doc.Coordinator; c != nil {
		r.Coordinators = append(r.Coordinators, coordinator(*c, "ana koordinatör"))
	}
	for _, c := range doc.Coordinators {
		r.Coordinators = append(r.Coordinators, coordinator(c, "koordinatör"))
	}
	return r
}

func coordinator(c trust.Coordinator, def string) Coordinator {
	name := c.Name
	if name == "" {
		name = def
	}
	return Coordinator{Name: name, Endpoint: c.Endpoint, Region: c.Region}
}

func prefixText(ok bool, s string) string {
	if !ok {
		return ""
	}
	return s
}

func addrText(ok bool, s string) string {
	if !ok {
		return ""
	}
	return s
}

func roleText(r trust.Role) string {
	switch r {
	case trust.RoleExitNode:
		return "çıkış düğümü"
	case trust.RoleAdmin:
		return "yönetici"
	}
	return string(r)
}

// entryText names a rule entry for people.
func entryText(e string) string {
	switch {
	case e == trust.RuleWildcard:
		return "bütün cihazlar"
	case strings.HasPrefix(e, trust.TagPrefix):
		return "'" + strings.TrimPrefix(e, trust.TagPrefix) + "' etiketli cihazlar"
	case strings.HasPrefix(e, trust.GroupPrefix):
		return "'" + strings.TrimPrefix(e, trust.GroupPrefix) + "' grubu"
	case strings.HasPrefix(e, "host:"):
		return "'" + strings.TrimPrefix(e, "host:") + "' adres aralığı"
	}
	return e
}

func entriesText(list []string) string {
	parts := make([]string, 0, len(list))
	for _, e := range list {
		parts = append(parts, entryText(e))
	}
	switch len(parts) {
	case 0:
		return "hiçbiri"
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " ve " + parts[len(parts)-1]
}

var serviceNames = map[trust.RuleService]string{
	trust.ServiceSSH:           "SSH",
	trust.ServiceFiles:         "dosya gönderme",
	trust.ServiceWake:          "uzaktan uyandırma",
	trust.ServiceSpeedtest:     "hız testi",
	trust.ServiceRemoteDesktop: "uzak masaüstü",
	trust.ServicePanel:         "yönetim paneli",
	trust.ServiceSync:          "klasör eşitleme",
	trust.ServiceServe:         "servis yayınlama",
	trust.ServiceCert:          "sertifika",
}

// what says which traffic a rule covers.
func what(r trust.Rule) string {
	if r.Service != "" {
		name, ok := serviceNames[r.Service]
		if !ok {
			name = string(r.Service)
		}
		s := name + " hizmeti"
		var extra []string
		if len(r.Users) > 0 {
			extra = append(extra, "kullanıcılar: "+strings.Join(r.Users, ", "))
		}
		if r.AllowRoot {
			extra = append(extra, "root dahil")
		}
		if r.AllowControl {
			extra = append(extra, "klavye ve fare denetimiyle")
		}
		if r.AllowUnattended {
			extra = append(extra, "onaysız")
		}
		if len(extra) > 0 {
			s += " (" + strings.Join(extra, "; ") + ")"
		}
		return s
	}
	proto := strings.ToUpper(string(r.Protocol))
	switch r.Protocol {
	case trust.ProtocolICMP:
		return "ping (ICMP)"
	case "", trust.ProtocolAny:
		proto = "bütün protokoller"
	}
	if len(r.Ports) == 0 || (len(r.Ports) == 1 && r.Ports[0] == "*") {
		if r.Protocol == "" || r.Protocol == trust.ProtocolAny {
			return "her türlü trafik"
		}
		return proto + ", bütün portlar"
	}
	return proto + " " + strings.Join(r.Ports, ", ") + " portları"
}

// RuleSentence describes a rule in one Turkish sentence.
func RuleSentence(r trust.Rule) string {
	verb := "erişebilir"
	if r.Action == trust.RuleDeny {
		verb = "erişemez"
	}
	s := fmt.Sprintf("%s → %s: %s %s.", capitalize(entriesText(r.From)), entriesText(r.To), what(r), verb)
	if d := strings.TrimSpace(r.Description); d != "" {
		s += " Not: " + d
	}
	if r.Disabled {
		s += " (Devre dışı; uygulanmıyor.)"
	}
	return s
}

func capitalize(s string) string {
	// Device, tag and group names keep their spelling; only the wildcard
	// phrase starts a sentence.
	if rest, ok := strings.CutPrefix(s, "bütün"); ok {
		return "Bütün" + rest
	}
	return s
}

func dnsLines(doc *trust.Document) []string {
	var out []string
	if doc.DNSDomain != "" {
		out = append(out, "Cihaz adları "+doc.DNSDomain+" alanında çözülür (MagicDNS).")
	}
	if d := doc.DNS; d != nil {
		if len(d.Nameservers) > 0 {
			var ns []string
			for _, a := range d.Nameservers {
				ns = append(ns, a.String())
			}
			out = append(out, "Diğer bütün adlar şu çözücülere sorulur: "+strings.Join(ns, ", ")+".")
		}
		for _, sp := range d.Split {
			var ns []string
			for _, a := range sp.Nameservers {
				ns = append(ns, a.String())
			}
			out = append(out, sp.Domain+" altındaki adlar şuraya sorulur: "+strings.Join(ns, ", ")+".")
		}
	}
	if m := doc.MagicDNS; m != nil {
		if len(m.Search) > 0 {
			out = append(out, "Kısa adlara eklenen arama alanları: "+strings.Join(m.Search, ", ")+".")
		}
		if len(m.Records) > 0 {
			out = append(out, "Ağ alanında "+strconv.Itoa(len(m.Records))+" ek DNS kaydı var.")
		}
		if m.DeviceSubdomains {
			out = append(out, "Cihaz alt alanları açık (ör. web.nas."+doc.DNSDomain+").")
		}
	}
	for _, p := range doc.DNSProfiles {
		line := "'" + p.Name + "' DNS süzgeç profili: " + entriesText(p.Members)
		if p.SafeSearch {
			line += ", güvenli arama açık"
		}
		out = append(out, line+".")
	}
	return out
}

// mdEscape keeps a value from breaking the Markdown table or starting
// markup: the report is data, never formatting.
func mdEscape(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
	return strings.NewReplacer(`\`, `\\`, "|", `\|`, "*", `\*`, "_", `\_`, "`", "\\`", "<", "&lt;", ">", "&gt;", "[", `\[`, "]", `\]`, "#", `\#`).Replace(s)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Markdown renders the report.
func Markdown(r Report) string {
	var b strings.Builder
	e := mdEscape
	fmt.Fprintf(&b, "# %s ağı\n\n", e(r.Network))
	fmt.Fprintf(&b, "Bu rapor %s tarihinde OpenScale tarafından oluşturuldu. Anahtar, parmak izi veya davet kodu içermez; ağa giriş sağlamaz.\n\n", r.CreatedAt.Format(dateForm))
	fmt.Fprintf(&b, "- Ağ alanı: %s\n- Belge sürümü: %d (imza: %s, geçerlilik sonu: %s)\n- Adres aralığı: %s %s\n\n",
		e(orDash(r.Domain)), r.Version, r.IssuedAt.Format(dateForm), r.ExpiresAt.Format(dateForm), e(orDash(r.IPv4Prefix)), e(r.IPv6Prefix))
	fmt.Fprintf(&b, "## Cihazlar (%d)\n\n| Ad | Adres | Rol | Etiketler | Üyelik sonu |\n|---|---|---|---|---|\n", len(r.Devices))
	for _, d := range r.Devices {
		name := e(d.Name)
		if d.Ephemeral {
			name += " (geçici)"
		}
		roles := d.Roles
		if d.Routes != "" {
			roles = strings.TrimPrefix(roles+", alt ağ: "+d.Routes, ", ")
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", name, e(orDash(d.IPv4)), e(orDash(roles)), e(orDash(d.Tags)), e(orDash(d.Expires)))
	}
	if len(r.Groups) > 0 {
		b.WriteString("\n## Gruplar\n\n")
		for _, g := range r.Groups {
			fmt.Fprintf(&b, "- **%s**: %s\n", e(g.Name), e(orDash(g.Members)))
		}
	}
	b.WriteString("\n## Erişim kuralları\n\n")
	if len(r.Rules) == 0 {
		b.WriteString("Kural yok: cihazlar birbirine bağlanamaz.\n")
	}
	for _, rule := range r.Rules {
		fmt.Fprintf(&b, "%d. %s\n", rule.Number, e(rule.Sentence))
	}
	fmt.Fprintf(&b, "\n%s\n", e(r.ExitUsers))
	if len(r.DNS) > 0 {
		b.WriteString("\n## DNS\n\n")
		for _, l := range r.DNS {
			fmt.Fprintf(&b, "- %s\n", e(l))
		}
	}
	b.WriteString("\n## Koordinatörler\n\n")
	if len(r.Coordinators) == 0 {
		b.WriteString("Koordinatör kayıtlı değil.\n")
	}
	for _, c := range r.Coordinators {
		line := fmt.Sprintf("- %s: %s", e(c.Name), e(orDash(c.Endpoint)))
		if c.Region != "" {
			line += " (" + e(c.Region) + ")"
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

var htmlPage = template.Must(template.New("report").Funcs(template.FuncMap{
	"date": func(t time.Time) string { return t.Format(dateForm) },
	"dash": orDash,
}).Parse(`<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>{{.Network}} ağı</title>
<style>
:root{--bg:#fbfaf7;--fg:#1c1b19;--muted:#5d5a54;--line:#dedad2;--accent:#1f6f5c}
@media (prefers-color-scheme:dark){:root{--bg:#161614;--fg:#ecebe6;--muted:#a9a69e;--line:#34322e;--accent:#6cc3a8}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:56rem;margin:0 auto;padding:2rem 1rem}
h1{font-size:1.75rem;margin:0 0 .25rem}h2{font-size:1.15rem;margin:2rem 0 .5rem;color:var(--accent)}
p.meta,.muted{color:var(--muted)}table{border-collapse:collapse;width:100%;font-size:.95rem}
th,td{text-align:left;padding:.4rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}
.table{overflow-x:auto}ol,ul{padding-left:1.25rem}.deny{font-weight:600}.off{color:var(--muted);text-decoration:line-through}
</style>
</head>
<body>
<main>
<h1>{{.Network}} ağı</h1>
<p class="meta">Oluşturma: {{date .CreatedAt}}. Anahtar, parmak izi veya davet kodu içermez; ağa giriş sağlamaz.</p>
<p>Ağ alanı: {{dash .Domain}} &middot; Belge sürümü {{.Version}} (geçerlilik sonu {{date .ExpiresAt}}) &middot; Adres aralığı {{dash .IPv4Prefix}} {{.IPv6Prefix}}</p>
<h2>Cihazlar ({{len .Devices}})</h2>
<div class="table"><table>
<thead><tr><th>Ad</th><th>Adres</th><th>Rol</th><th>Etiketler</th><th>Üyelik sonu</th></tr></thead>
<tbody>{{range .Devices}}<tr><td>{{.Name}}{{if .Ephemeral}} (geçici){{end}}</td><td>{{dash .IPv4}}</td><td>{{dash .Roles}}{{if .Routes}}; alt ağ: {{.Routes}}{{end}}</td><td>{{dash .Tags}}</td><td>{{dash .Expires}}</td></tr>
{{end}}</tbody></table></div>
{{if .Groups}}<h2>Gruplar</h2><ul>{{range .Groups}}<li><strong>{{.Name}}</strong>: {{dash .Members}}</li>{{end}}</ul>{{end}}
<h2>Erişim kuralları</h2>
{{if .Rules}}<ol>{{range .Rules}}<li class="{{if .Disabled}}off{{else if not .Allow}}deny{{end}}">{{.Sentence}}</li>{{end}}</ol>{{else}}<p>Kural yok: cihazlar birbirine bağlanamaz.</p>{{end}}
<p>{{.ExitUsers}}</p>
{{if .DNS}}<h2>DNS</h2><ul>{{range .DNS}}<li>{{.}}</li>{{end}}</ul>{{end}}
<h2>Koordinatörler</h2>
{{if .Coordinators}}<ul>{{range .Coordinators}}<li>{{.Name}}: {{dash .Endpoint}}{{if .Region}} ({{.Region}}){{end}}</li>{{end}}</ul>{{else}}<p>Koordinatör kayıtlı değil.</p>{{end}}
</main>
</body>
</html>
`))

// HTML renders the report as one self-contained page: no scripts, no
// outside resources, every value escaped.
func HTML(r Report) (string, error) {
	var b bytes.Buffer
	if err := htmlPage.Execute(&b, r); err != nil {
		return "", err
	}
	return b.String(), nil
}
