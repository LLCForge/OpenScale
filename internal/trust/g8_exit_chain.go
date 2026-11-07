package trust

import (
	"errors"
	"fmt"
	"slices"
)

// Signed two-hop exit (#618, ADR-0222). An exit chain names an entry exit
// node that does not send members' internet traffic out itself but hands it,
// translated to its own overlay address, to a second exit node inside the
// tunnel. Members choose the entry as usual; the final exit sees only the
// entry. The chain is signed by the root key so a coordinator cannot add,
// redirect or remove it.
//
// The field is optional and omitted when empty, so documents without it
// encode exactly as before. An older client rejects a document that carries
// it (strict decoding): raise min_client_version to a version with #618
// before signing a chain. Roles, expiry and exit_users are checked at run
// time by the entry node, which fails closed (drops members' internet
// traffic) while the chain cannot be used.

// MaxExitChains bounds the chains in a document.
const MaxExitChains = 16

// ExitChain sends the entry exit node's member internet traffic through
// the final exit node.
type ExitChain struct {
	Entry string `json:"entry"`
	Final string `json:"final"`
}

// ErrExitChain is wrapped by every exit chain validation error.
var ErrExitChain = errors.New("exit_chains")

// validateExitChains checks the chains strictly: valid distinct names, one
// chain per entry, and exactly two hops (no final is also an entry).
func validateExitChains(chains []ExitChain) error {
	if chains == nil {
		return nil
	}
	if len(chains) == 0 {
		return fmt.Errorf("%w: boş liste; alanı çıkarın", ErrExitChain)
	}
	if len(chains) > MaxExitChains {
		return fmt.Errorf("%w: en fazla %d zincir", ErrExitChain, MaxExitChains)
	}
	entries := map[string]bool{}
	finals := map[string]bool{}
	for _, c := range chains {
		if !isValidLabel(c.Entry) || !isValidLabel(c.Final) {
			return fmt.Errorf("%w: geçersiz cihaz adı", ErrExitChain)
		}
		if c.Entry == c.Final {
			return fmt.Errorf("%w: giriş ve son çıkış aynı olamaz (%s)", ErrExitChain, c.Entry)
		}
		if entries[c.Entry] {
			return fmt.Errorf("%w: %s için birden fazla zincir", ErrExitChain, c.Entry)
		}
		entries[c.Entry] = true
		finals[c.Final] = true
	}
	for e := range entries {
		if finals[e] {
			return fmt.Errorf("%w: %s hem giriş hem son çıkış; zincir yalnızca iki sıçramalı olabilir", ErrExitChain, e)
		}
	}
	return nil
}

// ExitChainOf returns the final exit node of the chain whose entry is
// name.
func (doc *Document) ExitChainOf(name string) (final string, ok bool) {
	for _, c := range doc.ExitChains {
		if c.Entry == name {
			return c.Final, true
		}
	}
	return "", false
}

// SetExitChain sets the chain for entry; an empty final removes it. Both
// devices must exist and hold the exit node role when the chain is set.
func (doc *Document) SetExitChain(entry, final string) error {
	chains := slices.DeleteFunc(slices.Clone(doc.ExitChains), func(c ExitChain) bool { return c.Entry == entry })
	if final != "" {
		for _, n := range []string{entry, final} {
			d, ok := doc.DeviceByName(n)
			if !ok {
				return fmt.Errorf("%w: %s", ErrUnknownDevice, n)
			}
			if !d.HasRole(RoleExitNode) {
				return fmt.Errorf("%w: %s bir çıkış düğümü değil", ErrExitChain, n)
			}
		}
		chains = append(chains, ExitChain{Entry: entry, Final: final})
	}
	if len(chains) == 0 {
		chains = nil
	}
	old := doc.ExitChains
	doc.ExitChains = chains
	if err := doc.Validate(); err != nil {
		doc.ExitChains = old
		return err
	}
	return nil
}
