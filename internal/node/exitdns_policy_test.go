package node

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/dnsblock"
)

func TestExitDNSPolicy(t *testing.T) {
	l, err := dnsblock.Parse(strings.NewReader("||ads.example^\n@@||ok.ads.example^\n"))
	if err != nil {
		t.Fatal(err)
	}
	SetExitDNSBlocklist(l)
	t.Cleanup(func() { SetExitDNSBlocklist(nil) })
	// The upstream is never reached for these names: a closed loopback port.
	f := newDNSForwarder(dnsUpstream{kind: upstreamUDP, addr: "127.0.0.1:9"}, nil)
	_, before, canaryBefore := ExitDNSPolicyStats()

	check := func(name string, edns int, wantEDE bool) {
		t.Helper()
		out, err := f.forward(context.Background(), dnsQuery(t, 42, name, dnsmessage.TypeA, edns))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(out); err != nil {
			t.Fatal(err)
		}
		if m.ID != 42 || m.RCode != dnsmessage.RCodeNameError || len(m.Answers) != 0 {
			t.Fatalf("%s: %+v", name, m.Header)
		}
		ede := false
		for _, a := range m.Additionals {
			if o, ok := a.Body.(*dnsmessage.OPTResource); ok {
				for _, opt := range o.Options {
					ede = ede || (opt.Code == optionEDE && len(opt.Data) == 2 && opt.Data[1] == edeBlocked)
				}
			}
		}
		if ede != wantEDE {
			t.Fatalf("%s: EDE %v", name, ede)
		}
	}
	check("ads.example.", 1232, true)
	check("x.ads.example.", 0, false)
	check("use-application-dns.net.", 1232, false)
	listed, after, canaryAfter := ExitDNSPolicyStats()
	if listed != 1 || after-before != 2 || canaryAfter-canaryBefore != 1 {
		t.Fatalf("stats %d %d %d", listed, after-before, canaryAfter-canaryBefore)
	}
	// An exception goes upstream (and fails there: nothing listens).
	cq, err := parseClientQuery(dnsQuery(t, 1, "ok.ads.example.", dnsmessage.TypeA, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := exitPolicyAnswer(cq); ok {
		t.Fatal("exception answered locally")
	}
}
