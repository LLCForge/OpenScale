package admin

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Device retirement wizard (#825). Before a device is revoked the owner
// sees everything that names it: the rules it passes through, its groups,
// DNS records and resolvers, exit chains, sync and backup partners, SSH
// access, Wake-on-LAN relay duties and the internal CA. The retirement is
// one change, so the revocation and every clean-up are signed together in
// one version; nothing is left pointing at a device that no longer exists.
//
// The preview is computed by running the same change on a copy of the
// document, so what it lists is what the signature does. trust.Document is
// only read and called; no field is added to it.

// Retire section ids, in display order.
const (
	RetireRules       = "rules"
	RetireGroups      = "groups"
	RetireDNS         = "dns"
	RetireExit        = "exit"
	RetireSync        = "sync"
	RetireSSH         = "ssh"
	RetireWake        = "wake"
	RetireCA          = "ca"
	RetireRoutes      = "routes"
	RetirePolicyTests = "tests"
)

var retireTitles = map[string]string{
	RetireRules:       "Erişim kuralları",
	RetireGroups:      "Gruplar",
	RetireDNS:         "DNS kayıtları ve çözücüler",
	RetireExit:        "Çıkış düğümü ve çıkış zinciri",
	RetireSync:        "Eşitleme ve yedek eşleri",
	RetireSSH:         "SSH erişimi ve sertifikalar",
	RetireWake:        "Wake-on-LAN aracılığı",
	RetireCA:          "İç sertifika otoritesi",
	RetireRoutes:      "Alt ağ yönlendirmeleri",
	RetirePolicyTests: "Kural testleri",
}

var retireOrder = []string{RetireRules, RetireGroups, RetireDNS, RetireExit, RetireSync, RetireSSH, RetireWake, RetireCA, RetireRoutes, RetirePolicyTests}

// RetireItem is one reference to the retiring device.
type RetireItem struct {
	// Title names the reference, e.g. "Kural 3: laptop -> nas tcp/22".
	Title string `json:"title"`
	// Effect says what the retirement does to it (Turkish).
	Effect string `json:"effect"`
	// Cleaned is true when the signed retirement changes or removes it;
	// false for information only (for example a rule that matched the
	// device through a tag and simply stops applying to it).
	Cleaned bool `json:"cleaned"`
}

// RetireSection groups the items of one kind.
type RetireSection struct {
	ID    string       `json:"id"`
	Title string       `json:"title"`
	Items []RetireItem `json:"items"`
}

// RetirePreview is everything a retirement touches.
type RetirePreview struct {
	Device   string          `json:"device"`
	IPv4     string          `json:"ipv4"`
	IPv6     string          `json:"ipv6"`
	ExitNode bool            `json:"exitNode"`
	Sections []RetireSection `json:"sections"`
	// Cleaned counts the items the signature changes.
	Cleaned int `json:"cleaned"`
	// Notes are things the document cannot change (Turkish).
	Notes []string `json:"notes"`
}

// RetireChange revokes the device and removes every reference to it in one
// change. Exit chains are removed first: the revocation itself does not
// touch them.
func RetireChange(name string, now time.Time) Change {
	return func(doc *trust.Document) error {
		if _, ok := doc.DeviceByName(name); !ok {
			return fmt.Errorf("%w: %s", trust.ErrUnknownDevice, name)
		}
		for _, c := range slices.Clone(doc.ExitChains) {
			if c.Entry == name || c.Final == name {
				if err := doc.SetExitChain(c.Entry, ""); err != nil {
					return err
				}
			}
		}
		_, err := doc.RevokeDevice(name, now)
		return err
	}
}

// PreviewRetire lists what retiring name changes in doc. doc is not
// modified.
func PreviewRetire(doc *trust.Document, name string, now time.Time) (RetirePreview, error) {
	d, ok := doc.DeviceByName(name)
	if !ok {
		return RetirePreview{}, fmt.Errorf("%w: %s", trust.ErrUnknownDevice, name)
	}
	after, err := copyDocument(doc)
	if err != nil {
		return RetirePreview{}, err
	}
	if err := RetireChange(name, now)(after); err != nil {
		return RetirePreview{}, err
	}
	p := RetirePreview{Device: d.Name, ExitNode: d.HasRole(trust.RoleExitNode), Sections: []RetireSection{}, Notes: []string{}}
	if d.IPv4.IsValid() {
		p.IPv4 = d.IPv4.String()
	}
	if d.IPv6.IsValid() {
		p.IPv6 = d.IPv6.String()
	}
	items := map[string][]RetireItem{}
	add := func(section string, it RetireItem) { items[section] = append(items[section], it) }

	retireRules(doc, after, name, add)
	retireGroups(doc, name, add)
	retireDNS(doc, after, d, add)
	retireExit(doc, d, add)
	if doc.InternalCA != nil && doc.InternalCA.Issuer == name {
		add(RetireCA, RetireItem{Title: "Sertifika dağıtıcısı: " + name, Effect: "İç CA belgeden kaldırılır; iç TLS sertifikaları yenilenemez, yeni bir CA kurulmalı.", Cleaned: true})
	}
	for _, r := range d.Routes {
		add(RetireRoutes, RetireItem{Title: r.String(), Effect: "Yönlendirme kalkar; bu alt ağa başvuran kural girdileri de silinir.", Cleaned: true})
	}
	for _, t := range doc.PolicyTests {
		if t.From == name || t.To == name {
			add(RetirePolicyTests, RetireItem{Title: t.From + " -> " + t.To, Effect: "Test silinir.", Cleaned: true})
		}
	}

	for _, id := range retireOrder {
		if len(items[id]) == 0 {
			continue
		}
		p.Sections = append(p.Sections, RetireSection{ID: id, Title: retireTitles[id], Items: items[id]})
		for _, it := range items[id] {
			if it.Cleaned {
				p.Cleaned++
			}
		}
	}
	p.Notes = append(p.Notes,
		"Cihazın imza ve WireGuard anahtarları kalıcı olarak iptal edilir; aynı anahtarlarla bir daha katılamaz.",
		fmt.Sprintf("Daha önce verilmiş kısa ömürlü SSH sertifikaları belgede tutulmaz; en çok %d dakika içinde kendiliğinden geçersiz olur.", int(MaxSSHCertLife.Minutes())),
	)
	if p.ExitNode {
		p.Notes = append(p.Notes, "Bu cihaz çıkış düğümü: onu seçmiş cihazlar internet trafiği için başka bir çıkış düğümü seçmeli.")
	}
	return p, nil
}

// PreviewRetire is PreviewRetire on the network's current document.
func (n *Network) PreviewRetire(name string, now time.Time) (RetirePreview, error) {
	doc, err := n.Document()
	if err != nil {
		return RetirePreview{}, err
	}
	return PreviewRetire(doc, name, now)
}

func retireRules(doc, after *trust.Document, name string, add func(string, RetireItem)) {
	surviving := ruleCounts(after.Rules)
	for i, r := range doc.Rules {
		direct := slices.Contains(r.From, name) || slices.Contains(r.To, name) || slices.Contains(r.Via, name)
		indirect := !direct && (doc.MatchesEntries(r.From, name) || doc.MatchesEntries(r.To, name) || doc.MatchesEntries(r.Via, name))
		if !direct && !indirect {
			// Rules naming only the device's routes are removed by the
			// revocation as well (dropUnroutedRefs).
			if s := RuleString(r); surviving[s] == 0 {
				add(RetireRules, RetireItem{Title: fmt.Sprintf("Kural %d: %s", i+1, s), Effect: "Kural silinir: başvurduğu alt ağ bu cihazla birlikte kalkar.", Cleaned: true})
			} else {
				surviving[s]--
			}
			continue
		}
		section := RetireRules
		switch {
		case r.Service == trust.ServiceSSH:
			section = RetireSSH
		case r.Service == trust.ServiceSync:
			section = RetireSync
		case r.Service == trust.ServiceWake && slices.Contains(r.Via, name):
			section = RetireWake
		}
		title := fmt.Sprintf("Kural %d: %s", i+1, RuleString(r))
		if r.Service == trust.ServiceSync && r.Backup {
			title += " (yedek)"
		}
		if indirect {
			add(section, RetireItem{Title: title, Effect: "Kural değişmez; cihaz etiket, grup veya * yoluyla eşleşiyordu ve artık eşleşmez."})
			continue
		}
		from := slices.DeleteFunc(slices.Clone(r.From), func(s string) bool { return s == name })
		to := slices.DeleteFunc(slices.Clone(r.To), func(s string) bool { return s == name })
		via := slices.DeleteFunc(slices.Clone(r.Via), func(s string) bool { return s == name })
		effect := "Cihaz kuraldan çıkarılır; kural diğer girdileriyle kalır."
		switch {
		case len(from) == 0 || len(to) == 0:
			effect = "Kural silinir: başka kaynak veya hedefi kalmıyor."
		case len(r.Via) > 0 && len(via) == 0:
			effect = "Kural silinir: başka aracı cihazı kalmıyor."
		case slices.Contains(r.Via, name):
			effect = "Cihaz aracı listesinden çıkarılır; diğer aracılar kalır."
		}
		add(section, RetireItem{Title: title, Effect: effect, Cleaned: true})
	}
}

func retireGroups(doc *trust.Document, name string, add func(string, RetireItem)) {
	for _, g := range doc.Groups {
		if !slices.Contains(g.Members, name) {
			continue
		}
		effect := "Cihaz grup üyeliğinden çıkarılır."
		if len(g.Members) == 1 {
			effect = "Cihaz çıkarılır; grup boş kalır ve hiçbir cihazla eşleşmez."
		}
		add(RetireGroups, RetireItem{Title: "group:" + g.Name, Effect: effect, Cleaned: true})
	}
	if users, set := doc.ExitUsersList(); set && slices.Contains(users, name) {
		add(RetireGroups, RetireItem{Title: "Çıkış düğümü kullanıcıları", Effect: "Cihaz listeden çıkarılır.", Cleaned: true})
	}
	for _, p := range doc.DNSProfiles {
		if slices.Contains(p.Members, name) {
			add(RetireDNS, RetireItem{Title: "DNS profili: " + p.Name, Effect: "Cihaz profilden çıkarılır.", Cleaned: true})
		}
	}
}

func retireDNS(doc, after *trust.Document, d trust.Device, add func(string, RetireItem)) {
	if doc.MagicDNS != nil {
		kept := map[trust.DNSRecord]int{}
		if after.MagicDNS != nil {
			for _, r := range after.MagicDNS.Records {
				kept[r]++
			}
		}
		for _, r := range doc.MagicDNS.Records {
			if kept[r] > 0 {
				kept[r]--
				continue
			}
			add(RetireDNS, RetireItem{Title: fmt.Sprintf("%s %s %s", r.Name, r.Type, r.Value), Effect: "Kayıt silinir.", Cleaned: true})
		}
	}
	if doc.DNS != nil {
		mine := func(a netip.Addr) bool { return a == d.IPv4 || a == d.IPv6 }
		for _, a := range doc.DNS.Nameservers {
			if mine(a) {
				add(RetireDNS, RetireItem{Title: "Ağ çözücüsü " + a.String(), Effect: "Çözücü listeden çıkarılır.", Cleaned: true})
			}
		}
		for _, s := range doc.DNS.Split {
			if slices.ContainsFunc(s.Nameservers, mine) {
				add(RetireDNS, RetireItem{Title: "Bölünmüş DNS: " + s.Domain, Effect: "Bu cihazın adresi çözücülerden çıkarılır; başka çözücü kalmazsa alan silinir.", Cleaned: true})
			}
		}
	}
	if len(d.Aliases) > 0 {
		add(RetireDNS, RetireItem{Title: "Ek adlar: " + strings.Join(d.Aliases, ", "), Effect: "Cihazla birlikte kalkar.", Cleaned: true})
	}
}

func retireExit(doc *trust.Document, d trust.Device, add func(string, RetireItem)) {
	for _, c := range doc.ExitChains {
		if c.Entry == d.Name || c.Final == d.Name {
			add(RetireExit, RetireItem{Title: "Çıkış zinciri: " + c.Entry + " -> " + c.Final, Effect: "Zincir silinir.", Cleaned: true})
		}
	}
	if d.HasRole(trust.RoleExitNode) {
		add(RetireExit, RetireItem{Title: "Çıkış düğümü rolü", Effect: "Rol cihazla birlikte kalkar; onu kullanan cihazlar başka çıkışa geçmeli."})
	}
}
