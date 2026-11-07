package trust

// routedCoverage reports whether a rule that matches no device pair still
// reaches an approved subnet route (ADR-0133): a CIDR entry inside a
// router's LAN is not a device address, yet the router forwards to it. The
// rule covers something when one side matches a device other than the
// router and the other side overlaps that router's approved routes.
func (doc *Document) routedCoverage(r Rule) bool {
	from, to := doc.matchedDevices(r.From), doc.matchedDevices(r.trafficTo())
	for _, d := range doc.Devices {
		if len(d.Routes) == 0 {
			continue
		}
		if doc.entriesOverlap(r.trafficTo(), d.Routes) && hasOther(from, d.Name) {
			return true
		}
		if doc.entriesOverlap(r.From, d.Routes) && hasOther(to, d.Name) {
			return true
		}
	}
	return false
}

func hasOther(names []string, router string) bool {
	for _, n := range names {
		if n != router {
			return true
		}
	}
	return false
}
