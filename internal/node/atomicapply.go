package node

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// All-or-nothing document application (#199, ADR-0095).
//
// apply works in three steps: prepare (find this device, resolve the
// coordinator, compute the peers), validate (the peer set below) and
// commit (WireGuard peers, then the filter, the exit node and the MagicDNS
// view). Nothing is changed before the WireGuard step; if that step fails
// half way (wireguard-go applies UAPI lines one by one), the peers are put
// back exactly as they were and apply returns before the filter and the
// routes change, so the device keeps running the previous document
// completely. The document stays stored (it is valid and signed, and the
// rollback state may not move back); the next sync tries to apply it
// again. Two exceptions are deliberate and fail closed: a document that
// no longer lists this device clears everything, and an exit node whose
// routes cannot be set is not used (the kill switch keeps internet traffic
// blocked, ADR-0023) rather than routing to an exit the new document may
// have removed.

// errPeersRolledBack wraps a WireGuard failure after which the previous
// peers were restored.
var errPeersRolledBack = errors.New("the previous WireGuard peers were restored")

// validatePeerSet rejects a peer set WireGuard would accept but route
// wrongly: an address prefix given to two peers silently moves to the
// last one.
func validatePeerSet(want map[trust.Key]wgconf.Peer) error {
	owner := map[netip.Prefix]trust.Key{}
	for key, p := range want {
		if key != p.PublicKey || p.PublicKey == (trust.Key{}) {
			return errors.New("peer set: invalid public key")
		}
		if p.Keepalive < 0 || p.Keepalive > 65535 {
			return errors.New("peer set: keepalive out of range")
		}
		for _, pfx := range p.AllowedIPs {
			if !pfx.IsValid() || pfx != pfx.Masked() {
				return fmt.Errorf("peer set: invalid allowed address %s", pfx)
			}
			if other, dup := owner[pfx]; dup && other != key {
				return fmt.Errorf("peer set: %s is assigned to two peers", pfx)
			}
			owner[pfx] = key
		}
	}
	return nil
}

// savedPeer is one peer as IpcGet reported it.
type savedPeer struct {
	key       trust.Key
	psk       string
	endpoint  string
	keepalive string
	allowed   []string
}

// parsePeerConfig reads the configuration part of IpcGet output: what is
// needed to set every peer back as it was.
func parsePeerConfig(raw string) (map[trust.Key]*savedPeer, error) {
	peers := map[trust.Key]*savedPeer{}
	var cur *savedPeer
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			b, err := hex.DecodeString(v)
			if err != nil || len(b) != trust.KeySize {
				return nil, errors.New("parse public_key")
			}
			var key trust.Key
			copy(key[:], b)
			cur = &savedPeer{key: key}
			peers[key] = cur
		case "preshared_key", "endpoint", "persistent_keepalive_interval", "allowed_ip":
			if cur == nil {
				continue
			}
			switch k {
			case "preshared_key":
				cur.psk = v
			case "endpoint":
				cur.endpoint = v
			case "persistent_keepalive_interval":
				cur.keepalive = v
			case "allowed_ip":
				cur.allowed = append(cur.allowed, v)
			}
		}
	}
	return peers, sc.Err()
}

// restoreUAPI returns UAPI lines that turn the peers in current back into
// saved: peers added since are removed, the others get their key, endpoint,
// keepalive and addresses back. Unchanged peers keep their sessions.
func restoreUAPI(saved, current map[trust.Key]*savedPeer) string {
	var b strings.Builder
	for key := range current {
		if _, ok := saved[key]; !ok {
			b.WriteString(wgconf.Remove(key))
		}
	}
	for key, p := range saved {
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(key[:]))
		if p.psk != "" {
			fmt.Fprintf(&b, "preshared_key=%s\n", p.psk)
		}
		if p.endpoint != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", p.endpoint)
		}
		if p.keepalive != "" {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%s\n", p.keepalive)
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, a := range p.allowed {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a)
		}
	}
	return b.String()
}

// rollbackPeers puts the peers back to before (the IpcGet output taken
// before the failed IpcSet) and returns cause wrapped.
func (e *Engine) rollbackPeers(before string, cause error) error {
	saved, err := parsePeerConfig(before)
	if err != nil {
		return fmt.Errorf("update wireguard peers: %w (restore impossible: %v)", cause, err)
	}
	raw, err := e.dev.IpcGet()
	if err != nil {
		return fmt.Errorf("update wireguard peers: %w (restore impossible: %v)", cause, err)
	}
	current, err := parsePeerConfig(raw)
	if err != nil {
		return fmt.Errorf("update wireguard peers: %w (restore impossible: %v)", cause, err)
	}
	if err := e.dev.IpcSet(restoreUAPI(saved, current)); err != nil {
		e.logger.Error("restoring the previous WireGuard peers failed", "error", err.Error())
		return fmt.Errorf("update wireguard peers: %w (restore failed: %v)", cause, err)
	}
	e.logger.Warn("new document not applied; previous peers restored", "error", cause.Error())
	return fmt.Errorf("update wireguard peers: %w: %w", cause, errPeersRolledBack)
}

// applyDoc applies doc and remembers a version whose application was
// rolled back, so sync retries it.
func (e *Engine) applyDoc(ctx context.Context, doc *trust.Document) error {
	err := e.apply(ctx, doc)
	e.mu.Lock()
	switch {
	case err == nil:
		e.applyFailed = 0
	case errors.Is(err, errPeersRolledBack):
		e.applyFailed = doc.Version
	}
	e.mu.Unlock()
	return err
}

// retryFailedApply applies the stored document again when its first
// application was rolled back.
func (e *Engine) retryFailedApply(ctx context.Context) {
	e.mu.Lock()
	failed := e.applyFailed
	e.mu.Unlock()
	if failed == 0 {
		return
	}
	doc := e.cfg.Store.Document()
	if doc.Version < failed {
		return
	}
	if err := e.applyDoc(ctx, doc); err != nil {
		e.logger.Warn("apply document (retry)", "version", doc.Version, "error", err.Error())
		return
	}
	e.logger.Info("document applied after an earlier failure", "version", doc.Version)
}
