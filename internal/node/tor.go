package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/socks5"
)

// Tor for the coordinator connection (ADR-0044, #63). With TorSOCKS set the
// coordinator is reached only over the TCP transport (ADR-0032), through
// the Tor client already running on this system; the bind sends no UDP at
// all and every peer is relayed, so neither the coordinator nor the peers
// learn this device's address. Tor is never embedded or started here.

// torDialTimeout bounds building a Tor circuit and the preamble exchange.
const torDialTimeout = 60 * time.Second

// torTarget is the coordinator's TCP transport address handed to Tor: the
// TCPFallback setting (an onion address, for example) or the coordinator's
// host on the default TCP port. Names are not resolved here.
func (e *Engine) torTarget() (string, error) {
	if e.cfg.TCPFallback != "" {
		return e.cfg.TCPFallback, nil
	}
	doc := e.cfg.Store.Document()
	if doc.Coordinator == nil {
		return "", errors.New("no coordinator")
	}
	host, _, err := net.SplitHostPort(doc.Coordinator.Endpoint)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(control.DefaultTCPPort)), nil
}

// dialCoordinatorTor opens the TCP transport stream through Tor's SOCKS5
// port and exchanges the preamble.
func (e *Engine) dialCoordinatorTor(ctx context.Context) (net.Conn, error) {
	target, err := e.torTarget()
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, torDialTimeout)
	defer cancel()
	s, err := socks5.Dial(cctx, e.cfg.TorSOCKS, target, e.extras.torAuth, nil)
	if err != nil {
		return nil, fmt.Errorf("Tor üzerinden %s: %w", target, err)
	}
	if d, ok := cctx.Deadline(); ok {
		_ = s.SetDeadline(d)
	}
	if e.tcp != nil && e.tcp.camo != nil { // #613
		if s, err = e.tcp.camo(s); err != nil {
			return nil, fmt.Errorf("Tor üzerinden %s: TLS: %w", target, err)
		}
		if d, ok := cctx.Deadline(); ok {
			_ = s.SetDeadline(d)
		}
	}
	var perr error
	if e.tcp != nil {
		perr = e.tcp.preamble(s) // SPA knock when known (#614)
	} else if _, perr = io.WriteString(s, control.TCPMagic); perr == nil {
		perr = control.ReadMagic(s)
	}
	if perr != nil {
		_ = s.Close()
		return nil, fmt.Errorf("Tor üzerinden %s: %w", target, perr)
	}
	_ = s.SetDeadline(time.Time{})
	return s, nil
}

// TorActive reports whether the coordinator is reached through Tor.
func (e *Engine) TorActive() bool { return e.cfg.TorSOCKS != "" }
