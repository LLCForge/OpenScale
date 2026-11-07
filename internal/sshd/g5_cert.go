package sshd

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// Short-lived SSH user certificates (#668), command allow lists (#669)
// and the kill shortcut (#672); ADR-0203.
//
// The owner's administrator key (never the coordinator) signs a user
// certificate that is valid for at most ten minutes. A device that lists
// the authority in Config.UserCAs accepts such a certificate; with
// Config.RequireCertificate it accepts nothing else. The tunnel rule
// (Authorize) is still required: the certificate is a second, short
// lived proof, not a replacement for the signed network document. A
// certificate may carry the OpenSSH critical options "force-command"
// (the session runs only that command) and "source-address".

// MaxCertLifetime is the longest validity IssueUserCertificate grants and
// the default limit a server accepts.
const MaxCertLifetime = 10 * time.Minute

// certSkew is how far a certificate's start is moved back for clocks
// that are slightly behind; a server allows it on top of the lifetime.
const certSkew = time.Minute

// CertOptions are optional restrictions of a user certificate.
type CertOptions struct {
	// ForceCommand limits the session to this command.
	ForceCommand string
	// SourceAddress limits the certificate to these addresses or networks
	// (comma separated CIDR list, OpenSSH syntax).
	SourceAddress string
}

// IssueUserCertificate signs a certificate for pub that lets principal
// (the account on the target) sign in for ttl (at most MaxCertLifetime).
// ca is the owner's administrator key; it is used here and nowhere else.
func IssueUserCertificate(ca ssh.Signer, pub ssh.PublicKey, principal string, ttl time.Duration, opts CertOptions, random io.Reader, now time.Time) (*ssh.Certificate, error) {
	if ca == nil || pub == nil {
		return nil, errors.New("sshd: sertifika için yetkili ve açık anahtar zorunlu")
	}
	if _, isCert := pub.(*ssh.Certificate); isCert {
		return nil, errors.New("sshd: sertifika bir sertifikaya verilemez")
	}
	if !validUserName(principal) {
		return nil, errors.New("sshd: geçersiz hesap adı")
	}
	if ttl <= 0 || ttl > MaxCertLifetime {
		return nil, fmt.Errorf("sshd: sertifika süresi 1 sn ile %s arasında olmalı", MaxCertLifetime)
	}
	if len(opts.ForceCommand) > maxCommandLen || strings.ContainsRune(opts.ForceCommand, 0) {
		return nil, errors.New("sshd: zorunlu komut geçersiz")
	}
	if opts.SourceAddress != "" {
		for part := range strings.SplitSeq(opts.SourceAddress, ",") {
			if _, err := netip.ParsePrefix(strings.TrimSpace(part)); err != nil {
				if _, err := netip.ParseAddr(strings.TrimSpace(part)); err != nil {
					return nil, fmt.Errorf("sshd: kaynak adresi geçersiz: %q", part)
				}
			}
		}
	}
	if random == nil {
		random = rand.Reader
	}
	var serial [8]byte
	if _, err := io.ReadFull(random, serial[:]); err != nil {
		return nil, err
	}
	crit := map[string]string{}
	if opts.ForceCommand != "" {
		crit["force-command"] = opts.ForceCommand
	}
	if opts.SourceAddress != "" {
		crit["source-address"] = opts.SourceAddress
	}
	ext := map[string]string{"permit-pty": ""}
	if opts.ForceCommand == "" {
		// Port forwarding is still decided by the tunnel rule.
		ext["permit-port-forwarding"] = ""
	}
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          binary.BigEndian.Uint64(serial[:]),
		CertType:        ssh.UserCert,
		KeyId:           fmt.Sprintf("openscale:%s:%d", principal, now.Unix()),
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(now.Add(-certSkew / 2).Unix()),
		ValidBefore:     uint64(now.Add(ttl).Unix()),
		Permissions:     ssh.Permissions{CriticalOptions: crit, Extensions: ext},
	}
	if err := cert.SignCert(random, ca); err != nil {
		return nil, fmt.Errorf("sshd: sertifika imzalanamadı: %w", err)
	}
	return cert, nil
}

// certChecker builds the checker for cfg.UserCAs.
func (s *Server) certChecker() *ssh.CertChecker {
	cas := s.cfg.UserCAs
	return &ssh.CertChecker{
		SupportedCriticalOptions: []string{"force-command", "source-address"},
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			m := auth.Marshal()
			return slices.ContainsFunc(cas, func(ca ssh.PublicKey) bool { return bytes.Equal(ca.Marshal(), m) })
		},
		IsRevoked: s.cfg.CertRevoked,
		Clock:     s.cfg.Clock,
	}
}

// authenticateCert checks a user certificate and then the tunnel rule.
func (s *Server) authenticateCert(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, errDenied
	}
	perms, err := s.certChecker().Authenticate(meta, key)
	if err != nil {
		s.log.Info("SSH sertifikası reddedildi", "user", meta.User(), "reason", err.Error())
		return nil, errDenied
	}
	maxLife := s.cfg.MaxCertLifetime
	if maxLife <= 0 {
		maxLife = MaxCertLifetime
	}
	if cert.ValidBefore == ssh.CertTimeInfinity || cert.ValidBefore <= cert.ValidAfter ||
		time.Duration(cert.ValidBefore-cert.ValidAfter)*time.Second > maxLife+certSkew {
		s.log.Info("SSH sertifikası reddedildi: süresi kısa ömürlü sınırı aşıyor", "user", meta.User(), "key_id", cert.KeyId)
		return nil, errDenied
	}
	if _, err := s.authenticate(meta); err != nil {
		return nil, err
	}
	if perms.Extensions == nil {
		perms.Extensions = map[string]string{}
	}
	perms.Extensions[permCertKeyID] = cert.KeyId
	return perms, nil
}

// Permission keys set by authentication.
const (
	permCertKeyID = "openscale-cert-key-id"
)

// connRestriction is the command restriction of one connection (#669).
type connRestriction struct {
	restricted bool
	commands   []string
}

// restrictionFor combines the certificate's force-command and the
// Commands callback.
func (s *Server) restrictionFor(remote netip.Addr, user string, perms *ssh.Permissions) connRestriction {
	var r connRestriction
	if s.cfg.Commands != nil {
		if cmds, restricted := s.cfg.Commands(remote, user); restricted {
			r.restricted, r.commands = true, slices.Clone(cmds)
		}
	}
	if perms != nil {
		if fc, ok := perms.CriticalOptions["force-command"]; ok {
			if r.restricted && !slices.Contains(r.commands, fc) {
				// The rule and the certificate disagree: nothing runs.
				r.commands = nil
			} else {
				r.commands = []string{fc}
			}
			r.restricted = true
		}
	}
	return r
}

// commandAllowed reports whether command ("" for a shell) may run.
func (r connRestriction) commandAllowed(command string) bool {
	if !r.restricted {
		return true
	}
	if command == "" {
		return false
	}
	return slices.Contains(r.commands, command)
}

// killState is the block set by KillAll.
type killState struct {
	until atomic.Int64
}

// KillAll closes every connection and refuses new ones for block (#672).
func (s *Server) KillAll(block time.Duration) int {
	if block > 0 {
		s.kill.until.Store(time.Now().Add(block).UnixNano())
	}
	s.mu.Lock()
	n := len(s.conns)
	for c := range s.conns {
		c.close()
	}
	s.mu.Unlock()
	s.log.Warn("SSH oturumları yerel kısayolla kesildi", "connections", n, "block", block.String())
	return n
}

// LiftKillBlock removes the block set by KillAll.
func (s *Server) LiftKillBlock() { s.kill.until.Store(0) }

func (s *Server) killBlocked() bool {
	u := s.kill.until.Load()
	return u != 0 && time.Now().UnixNano() < u
}
