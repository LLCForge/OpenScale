package trust

import "testing"

// A files rule opens the end-to-end transfer port in the same direction
// only; other services and other ports stay closed.
func TestFilesRuleOpensE2EPort(t *testing.T) {
	doc := &Document{Rules: []Rule{{From: []string{"laptop"}, To: []string{"nas"}, Service: ServiceFiles}}}
	cases := []struct {
		name    string
		r       Rule
		proto   int
		port    uint16
		matches bool
	}{
		{"files tcp 4044", doc.Rules[0], ipProtoTCP, FilesPort, true},
		{"files tcp 4054", doc.Rules[0], ipProtoTCP, FilesE2EPort, true},
		{"files udp 4054", doc.Rules[0], ipProtoUDP, FilesE2EPort, false},
		{"files tcp 4055", doc.Rules[0], ipProtoTCP, FilesE2EPort + 1, false},
		{"ssh tcp 4054", Rule{Service: ServiceSSH}, ipProtoTCP, FilesE2EPort, false},
		{"sync tcp 4054", Rule{Service: ServiceSync}, ipProtoTCP, FilesE2EPort, false},
	}
	for _, c := range cases {
		if got := protoMatches(c.r, c.proto, c.port); got != c.matches {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}
