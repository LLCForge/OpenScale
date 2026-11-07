package trust

import "fmt"

// WarnEmptyRange marks a range in a group, exit_users or via that holds no
// device and no approved subnet route (#277, ADR-0232).
const WarnEmptyRange = "empty_range"

// rangeWarnings reports range entries of groups, exit_users and via that
// currently cover nothing. Like the other policy warnings they never block
// a signature: a range may be planned for devices that join later.
func (doc *Document) rangeWarnings() []PolicyWarning {
	var out []PolicyWarning
	empty := func(e string, routes bool) bool {
		p, ok := doc.entryPrefix(e)
		if !ok {
			return false
		}
		for _, d := range doc.Devices {
			if (d.IPv4.IsValid() && p.Contains(d.IPv4)) || (d.IPv6.IsValid() && p.Contains(d.IPv6)) {
				return false
			}
			if routes {
				for _, r := range d.Routes {
					if r.Overlaps(p) {
						return false
					}
				}
			}
		}
		return true
	}
	for _, g := range doc.Groups {
		for _, m := range addrMembers(g.Members) {
			if empty(m, true) {
				out = append(out, PolicyWarning{Rule: -1, Code: WarnEmptyRange,
					Message: fmt.Sprintf("group:%s üyesi %s şu an hiçbir cihazı ve onaylı rotayı kapsamıyor.", g.Name, m)})
			}
		}
	}
	if doc.ExitUsers != nil {
		for _, e := range addrMembers(*doc.ExitUsers) {
			if empty(e, false) {
				out = append(out, PolicyWarning{Rule: -1, Code: WarnEmptyRange,
					Message: fmt.Sprintf("exit_users girdisi %s şu an hiçbir cihazı kapsamıyor.", e)})
			}
		}
	}
	for i, r := range doc.Rules {
		if r.Disabled {
			continue
		}
		for _, e := range addrMembers(r.Via) {
			if empty(e, false) {
				out = append(out, PolicyWarning{Rule: i, Code: WarnEmptyRange,
					Message: fmt.Sprintf("Kural %d aracı girdisi %s şu an hiçbir cihazı kapsamıyor.", i+1, e)})
			}
		}
	}
	return out
}
