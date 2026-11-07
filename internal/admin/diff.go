package admin

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Diff describes what a new document version changes. It is shown to the
// owner before every signature.
type Diff struct {
	FromVersion    uint64   `json:"from_version"`
	ToVersion      uint64   `json:"to_version"`
	AddedDevices   []string `json:"added_devices"`
	RemovedDevices []string `json:"removed_devices"`
	ChangedDevices []string `json:"changed_devices"`
	// DeviceChanges explains each changed device field, for example
	// "laptop: ad eski -> laptop" or "laptop: anahtarlar yenilendi".
	DeviceChanges  []string  `json:"device_changes"`
	AddedRules     []string  `json:"added_rules"`
	RemovedRules   []string  `json:"removed_rules"`
	OldExpiresAt   time.Time `json:"old_expires_at"`
	NewExpiresAt   time.Time `json:"new_expires_at"`
	SettingsChange []string  `json:"settings_changes"`
}

// ComputeDiff compares two document versions.
func ComputeDiff(prev, next *trust.Document) Diff {
	d := Diff{
		FromVersion:    prev.Version,
		ToVersion:      next.Version,
		OldExpiresAt:   prev.ExpiresAt,
		NewExpiresAt:   next.ExpiresAt,
		AddedDevices:   []string{},
		RemovedDevices: []string{},
		ChangedDevices: []string{},
		DeviceChanges:  []string{},
		AddedRules:     []string{},
		RemovedRules:   []string{},
		SettingsChange: []string{},
	}
	before := make(map[string]trust.Device, len(prev.Devices))
	for _, dev := range prev.Devices {
		before[dev.ID] = dev
	}
	after := make(map[string]trust.Device, len(next.Devices))
	for _, dev := range next.Devices {
		after[dev.ID] = dev
		old, ok := before[dev.ID]
		switch {
		case !ok:
			d.AddedDevices = append(d.AddedDevices, dev.Name)
		case !sameDevice(old, dev):
			d.ChangedDevices = append(d.ChangedDevices, dev.Name)
			d.DeviceChanges = append(d.DeviceChanges, deviceChanges(old, dev)...)
		}
	}
	for _, dev := range prev.Devices {
		if _, ok := after[dev.ID]; !ok {
			d.RemovedDevices = append(d.RemovedDevices, dev.Name)
		}
	}

	prevRules := ruleCounts(prev.Rules)
	nextRules := ruleCounts(next.Rules)
	for _, r := range next.Rules {
		key := RuleString(r)
		if prevRules[key] > 0 {
			prevRules[key]--
			continue
		}
		d.AddedRules = append(d.AddedRules, key)
	}
	for _, r := range prev.Rules {
		key := RuleString(r)
		if nextRules[key] > 0 {
			nextRules[key]--
			continue
		}
		d.RemovedRules = append(d.RemovedRules, key)
	}

	if prev.DisplayName != next.DisplayName {
		d.SettingsChange = append(d.SettingsChange, fmt.Sprintf("Ağ adı: %s -> %s", displayNameString(prev.DisplayName), displayNameString(next.DisplayName)))
	}
	if prev.DNSDomain != next.DNSDomain {
		d.SettingsChange = append(d.SettingsChange, fmt.Sprintf("DNS alanı: %s -> %s", prev.DNSDomain, next.DNSDomain))
	}
	if !sameCoordinator(prev.Coordinator, next.Coordinator) {
		d.SettingsChange = append(d.SettingsChange, "Koordinatör değişti")
	}
	if added, removed := inviteChanges(prev.Invites, next.Invites); added+removed > 0 {
		if added > 0 {
			d.SettingsChange = append(d.SettingsChange, fmt.Sprintf("%d yeni davet", added))
		}
		if removed > 0 {
			d.SettingsChange = append(d.SettingsChange, fmt.Sprintf("%d davet kaldırıldı", removed))
		}
	}
	d.SettingsChange = append(d.SettingsChange, groupChanges(prev.Groups, next.Groups)...)
	if a, b := exitUsersString(prev), exitUsersString(next); a != b {
		d.SettingsChange = append(d.SettingsChange, fmt.Sprintf("Çıkış düğümü kullanıcıları: %s -> %s", a, b))
	}
	if a, b := dnsString(prev.DNS), dnsString(next.DNS); a != b {
		d.SettingsChange = append(d.SettingsChange, fmt.Sprintf("Ağ DNS ayarları: %s -> %s", a, b))
	}
	d.SettingsChange = append(d.SettingsChange, zoneChanges(prev, next)...)
	d.SettingsChange = append(d.SettingsChange, dnsProfileChanges(prev, next)...) // #416, diff_dnsprofile.go
	if n := len(next.RetiredKeys) - len(prev.RetiredKeys); n > 0 {
		d.SettingsChange = append(d.SettingsChange, fmt.Sprintf("%d anahtar çifti emekliye ayrıldı", n))
	}
	// Recovery keys, root epoch, minimum version, ephemeral and
	// preauthorized devices, multi-use invites (membership.go).
	d.SettingsChange = append(d.SettingsChange, membershipChanges(prev, next)...)
	// Named addresses and policy tests (ADR-0120, policy_diff.go).
	d.SettingsChange = append(d.SettingsChange, policyExtChanges(prev, next)...)
	// Subnet routes, plain WireGuard exits, address strategy (ADR-0133).
	d.SettingsChange = append(d.SettingsChange, routingChanges(prev, next)...)
	// Internal certificate authority (ADR-0138, diff_ca.go).
	d.SettingsChange = append(d.SettingsChange, internalCAChanges(prev, next)...)
	// Version chain on or off (ADR-0144, chain.go).
	d.SettingsChange = append(d.SettingsChange, versionChainChanges(prev, next)...)
	d.SettingsChange = append(d.SettingsChange, p01Changes(prev, next)...) // ADR-0151
	d.SettingsChange = append(d.SettingsChange, g1Changes(prev, next)...)  // ADR-0172, ADR-0174, ADR-0177
	return d
}

// Lines renders the diff as Turkish text for the CLI.
func (d Diff) Lines() []string {
	lines := []string{fmt.Sprintf("Sürüm %d -> %d", d.FromVersion, d.ToVersion)}
	for _, n := range d.AddedDevices {
		lines = append(lines, "+ cihaz "+n)
	}
	for _, n := range d.RemovedDevices {
		lines = append(lines, "- cihaz "+n+" (iptal)")
	}
	for _, n := range d.ChangedDevices {
		lines = append(lines, "~ cihaz "+n)
	}
	for _, c := range d.DeviceChanges {
		lines = append(lines, "    "+c)
	}
	for _, r := range d.AddedRules {
		lines = append(lines, "+ kural "+r)
	}
	for _, r := range d.RemovedRules {
		lines = append(lines, "- kural "+r)
	}
	lines = append(lines, d.SettingsChange...)
	if !d.OldExpiresAt.Equal(d.NewExpiresAt) {
		lines = append(lines, fmt.Sprintf("Geçerlilik sonu: %s -> %s",
			d.OldExpiresAt.UTC().Format("2006-01-02"), d.NewExpiresAt.UTC().Format("2006-01-02")))
	}
	return lines
}

// RuleString renders a rule as "laptop -> masaustu tcp/3389". Deny rules
// start with "reddet:" and disabled rules end with "(kapalı)"; allow rules
// render exactly as before ADR-0021.
func RuleString(r trust.Rule) string {
	s := strings.Join(r.From, ",") + " -> " + strings.Join(r.To, ",") + " " + string(r.Protocol)
	if r.Service != "" {
		s = strings.Join(r.From, ",") + " -> " + strings.Join(r.To, ",") + " " + ServiceRuleDetail(r)
	} else if len(r.Ports) > 0 {
		s += "/" + strings.Join(r.Ports, ",")
	}
	if r.IsDeny() {
		s = "reddet: " + s
	}
	// ADR-0120 fields render only when set, so older rules look the same.
	s += ruleExtString(r)
	if r.Disabled {
		s += " (kapalı)"
	}
	return s
}

func ruleCounts(rules []trust.Rule) map[string]int {
	m := make(map[string]int, len(rules))
	for _, r := range rules {
		m[RuleString(r)]++
	}
	return m
}

func sameDevice(a, b trust.Device) bool {
	return a.Name == b.Name && a.SigningKey == b.SigningKey && a.WireGuardKey == b.WireGuardKey &&
		a.IPv4 == b.IPv4 && a.IPv6 == b.IPv6 && slices.Equal(a.Roles, b.Roles) && a.ExpiresAt.Equal(b.ExpiresAt) &&
		slices.Equal(a.Tags, b.Tags) && a.Icon == b.Icon
}

// deviceChanges lists what changed between two versions of one device.
func deviceChanges(a, b trust.Device) []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, b.Name+": "+fmt.Sprintf(format, args...)) }
	if a.Name != b.Name {
		add("ad %s -> %s (MagicDNS adı da değişir)", a.Name, b.Name)
	}
	if a.SigningKey != b.SigningKey || a.WireGuardKey != b.WireGuardKey {
		add("anahtarlar yenilendi")
	}
	if a.IPv4 != b.IPv4 || a.IPv6 != b.IPv6 {
		add("adres %s %s -> %s %s", a.IPv4, a.IPv6, b.IPv4, b.IPv6)
	}
	if !slices.Equal(a.Roles, b.Roles) {
		add("roller [%s] -> [%s]", joinRoles(a.Roles), joinRoles(b.Roles))
	}
	if !a.ExpiresAt.Equal(b.ExpiresAt) {
		add("üyelik bitişi %s -> %s", a.ExpiresAt.UTC().Format("2006-01-02 15:04"), b.ExpiresAt.UTC().Format("2006-01-02 15:04"))
	}
	if !slices.Equal(a.Tags, b.Tags) {
		add("etiketler [%s] -> [%s]", strings.Join(a.Tags, ","), strings.Join(b.Tags, ","))
	}
	if a.Icon != b.Icon { // #233, ADR-0232
		add("simge %s -> %s", iconString(a.Icon), iconString(b.Icon))
	}
	return out
}

func joinRoles(roles []trust.Role) string {
	s := make([]string, len(roles))
	for i, r := range roles {
		s[i] = string(r)
	}
	return strings.Join(s, ",")
}

func groupChanges(prev, next []trust.Group) []string {
	var out []string
	before := make(map[string][]string, len(prev))
	for _, g := range prev {
		before[g.Name] = g.Members
	}
	for _, g := range next {
		old, ok := before[g.Name]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("+ grup %s [%s]", g.Name, strings.Join(g.Members, ",")))
		case !slices.Equal(old, g.Members):
			out = append(out, fmt.Sprintf("~ grup %s [%s] -> [%s]", g.Name, strings.Join(old, ","), strings.Join(g.Members, ",")))
		}
		delete(before, g.Name)
	}
	for _, g := range prev {
		if _, gone := before[g.Name]; gone {
			out = append(out, "- grup "+g.Name)
		}
	}
	return out
}

func displayNameString(name string) string {
	if name == "" {
		return "yok"
	}
	return name
}

func exitUsersString(doc *trust.Document) string {
	users, set := doc.ExitUsersList()
	switch {
	case !set:
		return "herkes"
	case len(users) == 0:
		return "hiçbir cihaz"
	default:
		return strings.Join(users, ",")
	}
}

func dnsString(s *trust.DNSSettings) string {
	if s == nil {
		return "yok"
	}
	parts := []string{}
	if len(s.Nameservers) > 0 {
		parts = append(parts, "çözücüler "+joinAddrs(s.Nameservers))
	}
	for _, e := range s.Split {
		parts = append(parts, e.Domain+" => "+joinAddrs(e.Nameservers))
	}
	return strings.Join(parts, "; ")
}

func joinAddrs(addrs []netip.Addr) string {
	s := make([]string, len(addrs))
	for i, a := range addrs {
		s[i] = a.String()
	}
	return strings.Join(s, ",")
}

func inviteChanges(prev, next []trust.Invite) (added, removed int) {
	before := make(map[string]bool, len(prev))
	for _, inv := range prev {
		before[inv.ID] = true
	}
	for _, inv := range next {
		if !before[inv.ID] {
			added++
		}
		delete(before, inv.ID)
	}
	return added, len(before)
}

func sameCoordinator(a, b *trust.Coordinator) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
