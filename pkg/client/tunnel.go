package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Embedding over the running tunnel (F-144, ADR-0108). A Go program uses
// the OpenScale tunnel already running on this computer: it listens only
// on this device's tunnel address and dials other devices by name. It is
// not a node of its own (that would need a user-space TCP/IP stack, which
// ADR-0045 rejects); the signed rules and the packet filter still decide
// what reaches it.

const (
	dialTimeout     = 10 * time.Second
	maxForwardConns = 64
)

// TunnelAddr returns this device's tunnel IPv4 address.
func (c *Client) TunnelAddr(ctx context.Context) (netip.Addr, error) {
	st, err := c.Status(ctx)
	if err != nil {
		return netip.Addr{}, err
	}
	if st.Self == nil || !st.Running {
		return netip.Addr{}, errors.New("openscale: the tunnel is not running")
	}
	a, err := netip.ParseAddr(st.Self.IPv4)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("openscale: tunnel address: %w", err)
	}
	return a, nil
}

// ListenTunnel listens on port of this device's tunnel address only; it
// is never reachable from the LAN or the internet.
func (c *Client) ListenTunnel(ctx context.Context, port uint16) (net.Listener, error) {
	a, err := c.TunnelAddr(ctx)
	if err != nil {
		return nil, err
	}
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp4", netip.AddrPortFrom(a, port).String())
}

// DialDevice connects to port of the named device through the tunnel.
func (c *Client) DialDevice(ctx context.Context, name string, port uint16) (net.Conn, error) {
	if name == "" || port == 0 {
		return nil, errors.New("openscale: device name and port required")
	}
	st, err := c.Status(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range st.Peers {
		if p.Name != name {
			continue
		}
		a, err := netip.ParseAddr(p.IPv4)
		if err != nil {
			return nil, fmt.Errorf("openscale: %s has no tunnel address", name)
		}
		d := net.Dialer{Timeout: dialTimeout}
		return d.DialContext(ctx, "tcp4", net.JoinHostPort(a.String(), strconv.Itoa(int(port))))
	}
	return nil, fmt.Errorf("openscale: %s is not a peer of this device (no rule allows it or it does not exist)", name)
}

// Forward accepts connections on ln and copies each to target after
// allow accepted its source device (nil allows every device of the
// network). Connections from addresses that are no device are closed. It
// returns when ctx ends or ln fails.
func Forward(ctx context.Context, ln net.Listener, target string, r Resolver, allow func(Device) bool) error {
	if r == nil || target == "" {
		return errors.New("openscale: forward needs a resolver and a target")
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	sem := make(chan struct{}, maxForwardConns)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			forwardOne(ctx, conn, target, r, allow)
		}()
	}
}

func forwardOne(ctx context.Context, conn net.Conn, target string, r Resolver, allow func(Device) bool) {
	defer conn.Close()
	wctx, cancel := context.WithTimeout(ctx, identityTimeout)
	res, err := r.WhoIs(wctx, remoteIP(conn.RemoteAddr().String()))
	cancel()
	if err != nil || res.Device == nil || (allow != nil && !allow(*res.Device)) {
		return
	}
	d := net.Dialer{Timeout: dialTimeout}
	up, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(up, conn)
	go pipe(conn, up)
	select {
	case <-done:
		<-done
	case <-ctx.Done():
	}
}
