package admin

import (
	"path/filepath"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Version chain on the owner's side (#343, ADR-0144). Once turned on, every
// prepared version names the signed payload digest of network.json, the
// version it is made from.

// SetVersionChain returns a Change that turns the version chain on or off.
// Members older than ADR-0144 reject chained documents; see the ADR.
func SetVersionChain(on bool) Change {
	return func(doc *trust.Document) error {
		doc.SetVersionChain(on)
		return nil
	}
}

// SetVersionChain turns the version chain on or off and signs the result.
func (n *Network) SetVersionChain(passphrase []byte, on bool, now time.Time) (*Plan, error) {
	return n.Apply(passphrase, now, SetVersionChain(on))
}

// linkVersionChainLocked points a chained next version at the signed
// network.json it follows. Called with n.mu held.
func (n *Network) linkVersionChainLocked(next *trust.Document) error {
	if !next.VersionChainEnabled() {
		return nil
	}
	env, onDisk, err := readEnvelope(filepath.Join(n.dir, documentFile), n.sealed.RootPublicKey())
	if err != nil {
		return err
	}
	if onDisk.Version != n.doc.Version {
		n.doc = onDisk
		return ErrConcurrentChange
	}
	next.LinkVersionChain(env)
	return nil
}

// versionChainChanges describes turning the chain on or off for the diff.
func versionChainChanges(prev, next *trust.Document) []string {
	switch a, b := prev.VersionChainEnabled(), next.VersionChainEnabled(); {
	case !a && b:
		return []string{"Sürüm zinciri: açıldı (eski cihazlar bu sürümü reddeder)"}
	case a && !b:
		return []string{"Sürüm zinciri: kapatıldı"}
	}
	return nil
}

// chainForked reports whether doc's prev_digest names a different version
// than prev (signed as prevEnv). Gaps and unchained versions are not forks;
// VerifyHistory reports gaps separately.
func chainForked(prevEnv trust.Envelope, prev, doc *trust.Document) bool {
	i, err := trust.VerifyChain([]trust.Envelope{prevEnv, {}}, []*trust.Document{prev, doc})
	return err != nil || i >= 0
}
