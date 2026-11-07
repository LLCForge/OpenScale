package admin

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/openscale/openscale/internal/trust"
)

// Short-lived SSH user certificates (#668, ADR-0179), signing side. The
// root key or an administrator key whose grant names "ssh.cert" signs an
// OpenSSH user certificate for a few minutes (default 10). The target's
// SSH server (G5) trusts the root key as certificate authority, and an
// administrator key only through the grant carried in the certificate's
// "openscale-admin-grant" extension, which it verifies with
// trust.CheckAdminGrant against its pinned root and current revocations.

// SSH certificate limits.
const (
	DefaultSSHCertLife = 10 * time.Minute
	MaxSSHCertLife     = time.Hour
	// SSHGrantExtension carries the encoded administrator grant.
	SSHGrantExtension = "openscale-admin-grant"
	// SSHNetworkExtension carries the network id.
	SSHNetworkExtension = "openscale-network"
	maxSSHPrincipals    = 8
	// sshClockSkew backdates the start for clocks slightly behind.
	sshClockSkew = time.Minute
)

// SSHCertRequest describes a certificate to sign.
type SSHCertRequest struct {
	UserKey    ssh.PublicKey
	Principals []string
	Lifetime   time.Duration
	// KeyID is shown in the target's logs.
	KeyID string
	// Forwarding allows port forwarding (extension permit-port-forwarding).
	Forwarding bool
}

// digestCryptoSigner adapts a token key (pure Ed25519 over the message)
// to crypto.Signer for x/crypto/ssh.
type digestCryptoSigner struct{ s trust.DigestSigner }

func (d digestCryptoSigner) Public() crypto.PublicKey { return d.s.PublicKey() }
func (d digestCryptoSigner) Sign(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("ed25519 signs the message itself")
	}
	return d.s.SignMessage(msg)
}

// SignSSHUserCertWithKey signs with a software key (root or admin).
func SignSSHUserCertWithKey(ca ed25519.PrivateKey, networkID string, grant *trust.SignedGrant, req SSHCertRequest, now time.Time) (*ssh.Certificate, error) {
	signer, err := ssh.NewSignerFromSigner(ca)
	if err != nil {
		return nil, err
	}
	return signSSHCert(signer, ca.Public().(ed25519.PublicKey), networkID, grant, req, now)
}

// SignSSHUserCertWith signs with a key on a hardware token.
func SignSSHUserCertWith(ca trust.DigestSigner, networkID string, grant *trust.SignedGrant, req SSHCertRequest, now time.Time) (*ssh.Certificate, error) {
	signer, err := ssh.NewSignerFromSigner(digestCryptoSigner{ca})
	if err != nil {
		return nil, err
	}
	return signSSHCert(signer, ca.PublicKey(), networkID, grant, req, now)
}

func signSSHCert(signer ssh.Signer, caPub ed25519.PublicKey, networkID string, grant *trust.SignedGrant, req SSHCertRequest, now time.Time) (*ssh.Certificate, error) {
	if req.UserKey == nil {
		return nil, errors.New("user key is missing")
	}
	if len(req.Principals) == 0 || len(req.Principals) > maxSSHPrincipals {
		return nil, fmt.Errorf("1-%d principals are allowed", maxSSHPrincipals)
	}
	for _, p := range req.Principals {
		if p == "" || len(p) > 32 || p == "root" {
			return nil, fmt.Errorf("principal %q is not allowed (root needs a rule with allow_root on the target)", p)
		}
	}
	life := req.Lifetime
	if life == 0 {
		life = DefaultSSHCertLife
	}
	if life < 0 || life > MaxSSHCertLife {
		return nil, fmt.Errorf("certificate lifetime must be at most %s", MaxSSHCertLife)
	}
	ext := map[string]string{"permit-pty": "", SSHNetworkExtension: networkID}
	if req.Forwarding {
		ext["permit-port-forwarding"] = ""
	}
	if grant != nil {
		g := grant.Grant
		if string(g.Key[:]) != string(caPub) {
			return nil, trust.ErrAdminMismatch
		}
		if !g.Allows(trust.AdminOpSSHCert) {
			return nil, fmt.Errorf("%w: operation %q", trust.ErrAdminScope, trust.AdminOpSSHCert)
		}
		if g.NetworkID != networkID {
			return nil, trust.ErrWrongNetwork
		}
		if !now.Before(g.NotAfter) {
			return nil, trust.ErrAdminExpired
		}
		if end := now.Add(life); end.After(g.NotAfter) {
			life = g.NotAfter.Sub(now)
		}
		ext[SSHGrantExtension] = string(grant.Encoded)
	}
	var serial [8]byte
	if _, err := rand.Read(serial[:]); err != nil {
		return nil, err
	}
	cert := &ssh.Certificate{
		Key:             req.UserKey,
		Serial:          binary.BigEndian.Uint64(serial[:]),
		CertType:        ssh.UserCert,
		KeyId:           req.KeyID,
		ValidPrincipals: slices.Clone(req.Principals),
		ValidAfter:      uint64(now.Add(-sshClockSkew).Unix()), //nolint:gosec // current time is positive
		ValidBefore:     uint64(now.Add(life).Unix()),          //nolint:gosec // current time is positive
		Permissions:     ssh.Permissions{Extensions: ext},
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}
	return cert, nil
}
