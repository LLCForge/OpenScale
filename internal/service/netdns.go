package service

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/trust"
)

// Network-wide DNS on this device (ADR-0024, F-051, F-052, F-065).

const (
	// dnsCheckInterval is how often the applied DNS settings are compared
	// with the document, the exit node in use and the local choice.
	dnsCheckInterval = 5 * time.Second
	// dnsRetryAfter spaces out attempts after a failure, so a broken
	// system does not start PowerShell every few seconds.
	dnsRetryAfter = time.Minute
)

// NetworkDNSFor returns what this device applies from the document's dns
// section: the split domains always, the network-wide resolvers only while
// no exit node is in use (the exit node resolves then, ADR-0018). A nil
// document or section yields nothing to apply.
func NetworkDNSFor(doc *trust.Document, exitActive bool) osnet.NetworkDNS {
	if doc == nil {
		return osnet.NetworkDNS{}
	}
	out := osnet.NetworkDNS{Overlay: []netip.Prefix{doc.IPv4Prefix, doc.IPv6Prefix}, ExitActive: exitActive}
	if doc.MagicDNS != nil {
		// Search domains (F-053, ADR-0034).
		out.Search = append(out.Search, doc.MagicDNS.Search...)
	}
	if doc.DNS == nil {
		return out
	}
	if !exitActive {
		out.Nameservers = append(out.Nameservers, doc.DNS.Nameservers...)
	}
	for _, e := range doc.DNS.Split {
		out.Split = append(out.Split, osnet.SplitDomain{Domain: e.Domain, Nameservers: append([]netip.Addr{}, e.Nameservers...)})
	}
	return out
}

// DNSWatch keeps the network DNS settings applied while the tunnel runs.
// The service and 'openscale up' share it.
type DNSWatch struct {
	Magic osnet.DNSConfig
	// Document returns the current verified document.
	Document func() *trust.Document
	// ExitActive reports whether an exit node is in use now.
	ExitActive func() bool
	// Accept reports the local choice (F-065); false applies nothing.
	Accept func() bool
	// Apply replaces the OpenScale DNS settings (osnet.ConfigureNetworkDNS).
	Apply func(ctx context.Context, magic osnet.DNSConfig, n osnet.NetworkDNS) error
	// Report receives whether network DNS is applied and the last error.
	Report func(active bool, err error)
	Every  time.Duration
	Now    func() time.Time
	// Verify checks that the applied settings are still in place
	// (osnet.VerifyNetworkDNS, F-061); nil skips the check. VerifyEvery
	// spaces the checks (default 15 s).
	Verify      func(ctx context.Context, magic osnet.DNSConfig, n osnet.NetworkDNS) error
	VerifyEvery time.Duration
	// OnRepair is told when another program changed the settings; they
	// are applied again right away.
	OnRepair func(err error)
	// CatchAll asks for one catch-all rule on Windows (F-063).
	CatchAll func() bool
}

// dnsVerifyInterval is how often the applied settings are checked.
const dnsVerifyInterval = 15 * time.Second

// Run applies the settings whenever they change, until ctx ends. The
// MagicDNS rule must already be in place: an empty setting is applied
// only after a non-empty one, to remove it again.
func (w DNSWatch) Run(ctx context.Context) {
	every := w.Every
	if every <= 0 {
		every = dnsCheckInterval
	}
	now := w.Now
	if now == nil {
		now = time.Now
	}
	verifyEvery := w.VerifyEvery
	if verifyEvery <= 0 {
		verifyEvery = dnsVerifyInterval
	}
	applied := osnet.NetworkDNS{}.Key()
	var retryAt, verifiedAt time.Time
	lastWanted := applied
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		want := w.wanted()
		key := want.Key()
		if key != lastWanted {
			// A new setting is tried at once, even right after a failure.
			retryAt, lastWanted = time.Time{}, key
		}
		if key == applied && w.Verify != nil && now().Sub(verifiedAt) >= verifyEvery && !now().Before(retryAt) {
			verifiedAt = now()
			err := w.Verify(ctx, w.Magic, want)
			if ctx.Err() != nil {
				return
			}
			switch {
			case errors.Is(err, osnet.ErrDNSOverwritten):
				// Another program replaced the settings (F-061): apply
				// them again now.
				if w.OnRepair != nil {
					w.OnRepair(err)
				}
				applied = "\x00repair"
			case err != nil && w.Report != nil:
				w.Report(!want.Empty(), err)
			}
		}
		if key != applied && !now().Before(retryAt) {
			err := w.Apply(ctx, w.Magic, want)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				retryAt = now().Add(dnsRetryAfter)
			} else {
				applied = key
			}
			if w.Report != nil {
				w.Report(err == nil && !want.Empty(), err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w DNSWatch) wanted() osnet.NetworkDNS {
	exit := w.ExitActive != nil && w.ExitActive()
	n := NetworkDNSFor(w.Document(), exit)
	if w.Accept != nil && !w.Accept() {
		// Without the network's settings MagicDNS and the exit node's
		// routing stay (ADR-0034): only the document's DNS choices go.
		n.Nameservers, n.Split, n.Search = nil, nil, nil
	}
	n.CatchAll = w.CatchAll != nil && w.CatchAll()
	return n
}

// describeDNSErr turns a network DNS failure into Turkish for the panel.
func describeDNSErr(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, osnet.ErrNetworkDNSUnsupported):
		return "Ağ DNS ayarları bu sistemde uygulanamıyor; MagicDNS adları çalışmaya devam eder."
	}
	return "Ağ DNS ayarları uygulanamadı: " + err.Error()
}
