package sshd

import (
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const forwardDialTimeout = 10 * time.Second

type directTCPIPMsg struct {
	DestHost   string
	DestPort   uint32
	OriginHost string
	OriginPort uint32
}

// forwardTarget resolves the requested destination without DNS: only IP
// literals and "localhost" are accepted, so a forward can never trigger a
// name lookup that leaks to an outside resolver (ADR-0008).
func forwardTarget(host string, port uint32) (netip.AddrPort, bool) {
	if port == 0 || port > 65535 {
		return netip.AddrPort{}, false
	}
	if strings.EqualFold(host, "localhost") {
		return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)), true
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a.Unmap(), uint16(port)), true
}

func (s *Server) handleDirectTCPIP(c *serverConn, nc ssh.NewChannel) {
	if c.restr.restricted {
		// #669: a restricted account cannot forward ports.
		_ = nc.Reject(ssh.Prohibited, "bu hesap için port yönlendirme kapalı")
		return
	}
	if s.cfg.AuthorizeForward == nil {
		_ = nc.Reject(ssh.Prohibited, "port yönlendirme kapalı")
		return
	}
	var m directTCPIPMsg
	if err := ssh.Unmarshal(nc.ExtraData(), &m); err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, "geçersiz istek")
		return
	}
	dst, ok := forwardTarget(m.DestHost, m.DestPort)
	if !ok {
		_ = nc.Reject(ssh.Prohibited, "hedef yalnızca IP adresi veya localhost olabilir")
		return
	}
	if allowed, reason := s.cfg.AuthorizeForward(c.remote, c.user, dst); !allowed {
		s.log.Info("SSH port yönlendirmesi reddedildi", "user", c.user, "reason", reason)
		s.log.Debug("SSH port yönlendirmesi reddedildi", "dst", dst.String())
		_ = nc.Reject(ssh.Prohibited, "port yönlendirmeye izin verilmedi")
		return
	}
	d := net.Dialer{Timeout: forwardDialTimeout}
	target, err := d.Dial("tcp", dst.String())
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, "hedefe bağlanılamadı")
		return
	}
	defer target.Close()
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)

	// When either direction ends, both sides are closed. This gives up TCP
	// half-close but guarantees the forward cannot outlive its session
	// waiting on a silent target.
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = ch.Close()
			_ = target.Close()
		})
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-stop:
		case <-c.done:
			closeBoth()
		}
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer closeBoth()
		_, _ = io.Copy(target, ch)
	}()
	go func() {
		defer wg.Done()
		defer closeBoth()
		_, _ = io.Copy(ch, target)
	}()
	wg.Wait()
}
