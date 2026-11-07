package node

import (
	"fmt"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/dnsblock"
)

// Exit node DNS policy (ADR-0102): the owner's local block list (#91) and
// the DoH canary (#94) are answered by the exit node itself; neither name
// reaches the upstream resolver.

// dohCanary is the name browsers ask before turning on DNS over HTTPS by
// themselves; NXDOMAIN tells them the network's resolver filters or must
// be used, so they keep queries in the tunnel. It is never resolved or
// contacted, only answered.
const dohCanary = "use-application-dns.net."

// optionEDE is the EDNS option of Extended DNS Errors; edeBlocked its
// code "Blocked" (RFC 8914 4.16).
const (
	optionEDE  = 15
	edeBlocked = 15
)

var (
	exitBlocklist atomic.Pointer[dnsblock.List]
	// Counters only; the names asked are never kept (ADR-0008).
	exitDNSBlockedCount atomic.Uint64
	exitDNSCanaryCount  atomic.Uint64
)

// SetExitDNSBlocklist installs l as the block list of every exit node
// forwarder in this process; nil removes it.
func SetExitDNSBlocklist(l *dnsblock.List) {
	if l == nil || l.Len() == 0 {
		exitBlocklist.Store(nil)
		return
	}
	exitBlocklist.Store(l)
}

// LoadExitDNSBlocklist reads the owner's block list file and installs it;
// "" removes the list.
func LoadExitDNSBlocklist(path string) (int, error) {
	if path == "" {
		SetExitDNSBlocklist(nil)
		return 0, nil
	}
	l, err := dnsblock.Load(path)
	if err != nil {
		return 0, err
	}
	SetExitDNSBlocklist(l)
	return l.Len(), nil
}

// ExitDNSPolicyStats reports the number of blocked names in force and how
// many queries the block list and the DoH canary answered.
func ExitDNSPolicyStats() (listed int, blocked, canary uint64) {
	return exitBlocklist.Load().Len(), exitDNSBlockedCount.Load(), exitDNSCanaryCount.Load()
}

// exitPolicyAnswer answers a member's query locally when policy says so.
// Per-device profiles and timed exceptions: exitPolicyAnswerFor (P05).
func exitPolicyAnswer(cq clientQuery) ([]byte, bool) {
	out, _, ok := exitPolicyAnswerFor(currentExitGuard(), exitClient{}, cq, time.Now())
	return out, ok
}

// nxdomainAnswer builds NXDOMAIN for cq; blocked adds the Extended DNS
// Error "Blocked" when the member speaks EDNS.
func nxdomainAnswer(cq clientQuery, blocked bool) ([]byte, error) {
	m := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: cq.id, Response: true, RecursionDesired: true, RecursionAvailable: true,
			RCode: dnsmessage.RCodeNameError,
		},
		Questions: []dnsmessage.Question{cq.question},
	}
	if cq.key.edns {
		var opt dnsmessage.ResourceHeader
		if err := opt.SetEDNS0(recEDNSSize, dnsmessage.RCodeSuccess, cq.key.do); err != nil {
			return nil, err
		}
		var body dnsmessage.OPTResource
		if blocked {
			body.Options = []dnsmessage.Option{{Code: optionEDE, Data: []byte{0, edeBlocked}}}
		}
		m.Additionals = []dnsmessage.Resource{{Header: opt, Body: &body}}
	}
	out, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("NXDOMAIN yanıtı kurulamadı: %w", err)
	}
	return out, nil
}
