package admin

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Offline (air-gapped) owner device (#29, ADR-0126). The root key lives
// only on a machine that is never connected; every owner command runs
// there. What leaves it on a USB stick is public and signed: network.json
// and transitions.json. On an online member the owner drops them into the
// directory the service watches as its network directory (node
// NetworkDir); the service verifies them like any document and publishes
// them to the coordinator. Nothing secret ever crosses, and nothing on the
// online side can sign.

// transferFiles are the only files an air-gap transfer carries.
var transferFiles = []string{documentFile, transitionsFile}

// ActiveInterface is a network interface that is up and has an address
// other than loopback.
type ActiveInterface struct {
	Name  string
	Addrs []string
}

// OfflineCheck lists the interfaces that would let this machine reach a
// network. An empty result is what an air-gapped owner device should show;
// link-local addresses count, since a cable is a connection.
func OfflineCheck() ([]ActiveInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []ActiveInterface
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		var list []string
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() {
				list = append(list, ipn.IP.String())
			}
		}
		if len(list) > 0 {
			out = append(out, ActiveInterface{Name: ifc.Name, Addrs: list})
		}
	}
	return out, nil
}

// ExportTransfer copies the signed, public files of the network directory
// to outDir (a USB stick). Files are verified before they are copied and
// never overwrite anything in outDir. It returns the copied names.
func (n *Network) ExportTransfer(outDir string) ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if inside(n.dir, outDir) {
		return nil, errors.New("the transfer directory must be outside the network directory")
	}
	if _, _, err := readEnvelope(filepath.Join(n.dir, documentFile), n.sealed.RootPublicKey()); err != nil {
		return nil, err
	}
	if _, err := readTransitions(n.dir); err != nil {
		return nil, err
	}
	var copied []string
	for _, name := range transferFiles {
		data, err := securefile.ReadPrivate(filepath.Join(n.dir, name), trust.MaxEnvelopeSize)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return copied, err
		}
		if err := securefile.WriteNew(filepath.Join(outDir, name), data); err != nil {
			return copied, fmt.Errorf("write %s: %w", name, err)
		}
		copied = append(copied, name)
	}
	return copied, nil
}

// ImportTransfer verifies the files of a transfer directory against the
// root key the online device trusts (its pinned anchor, or a root the
// stored transitions lead to) and installs them into relayDir, the
// network directory the online service watches. An older document never
// replaces a newer one.
func ImportTransfer(srcDir, relayDir string, root ed25519.PublicKey) (*trust.Document, error) {
	data, err := securefile.ReadLimited(filepath.Join(srcDir, documentFile), trust.MaxEnvelopeSize)
	if err != nil {
		return nil, fmt.Errorf("read transferred document: %w", err)
	}
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return nil, err
	}
	var transitions []byte
	roots := []ed25519.PublicKey{root}
	if t, err := securefile.ReadLimited(filepath.Join(srcDir, transitionsFile), trust.MaxEnvelopeSize); err == nil {
		transitions = t
		if err := os.MkdirAll(relayDir, 0o700); err != nil {
			return nil, err
		}
		// Roots reached by verified transitions from the trusted root.
		tmp, err := os.MkdirTemp(relayDir, ".transfer-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp)
		if err := securefile.WriteNew(filepath.Join(tmp, transitionsFile), t); err != nil {
			return nil, err
		}
		roots = followTransitions(tmp, root)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	doc, err := verifyWithRoots(env, roots)
	if err != nil {
		return nil, err
	}
	dst := filepath.Join(relayDir, documentFile)
	if old, err := securefile.ReadLimited(dst, trust.MaxEnvelopeSize); err == nil {
		if oldEnv, err := trust.UnmarshalEnvelope(old); err == nil {
			if oldDoc, err := verifyWithRoots(oldEnv, roots); err == nil &&
				(oldDoc.RootEpoch > doc.RootEpoch || (oldDoc.RootEpoch == doc.RootEpoch && oldDoc.Version > doc.Version)) {
				return nil, fmt.Errorf("the transferred document (version %d) is older than the one in place (version %d)", doc.Version, oldDoc.Version)
			}
		}
	}
	if err := os.MkdirAll(relayDir, 0o700); err != nil {
		return nil, err
	}
	if transitions != nil {
		if err := securefile.Replace(filepath.Join(relayDir, transitionsFile), transitions); err != nil {
			return nil, err
		}
	}
	if err := securefile.Replace(dst, data); err != nil {
		return nil, err
	}
	return doc, nil
}

// followTransitions returns the trusted root and every root that verified
// rotations in dir lead to from it, newest last. Recovery transitions need
// the pinned recovery keys and are applied by the member itself.
func followTransitions(dir string, root ed25519.PublicKey) []ed25519.PublicKey {
	roots := []ed25519.PublicKey{root}
	list, err := readTransitions(dir)
	if err != nil {
		return roots
	}
	for changed := true; changed; {
		changed = false
		for _, st := range list {
			cur := roots[len(roots)-1]
			t, err := trust.VerifyRootTransition(st, cur, nil)
			if err != nil {
				continue
			}
			next := ed25519.PublicKey(append([]byte(nil), t.NewRoot[:]...))
			if !next.Equal(cur) {
				roots = append(roots, next)
				changed = true
			}
		}
		if len(roots) > trust.MaxRootTransitions+1 {
			break
		}
	}
	return roots
}
