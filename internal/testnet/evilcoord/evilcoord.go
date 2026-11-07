// Package evilcoord is a malicious coordinator for tests (#571). The trust
// model says the coordinator is not trusted (ADR-0003): it may withhold
// documents, serve old ones, show different devices different versions,
// forge or alter documents, lie about endpoints and tamper with relayed
// packets. Coordinator models each of those behaviours on the document
// path; the data-path behaviours (spoofed endpoints, tampering relay) are
// in relay.go. Tests feed what it serves to the device's own acceptance
// code and require every attack to be refused.
//
// It is test-only code: nothing in the product imports it.
package evilcoord

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Behavior is one way the coordinator misbehaves.
type Behavior int

// Behaviours of a malicious coordinator.
const (
	// Honest serves the newest document.
	Honest Behavior = iota
	// Withhold keeps serving the version that was current when it started
	// (freeze attack): devices must notice once it expires.
	Withhold
	// Rollback serves the oldest document it has seen.
	Rollback
	// SplitView serves the newest document to some devices and an older
	// one to the others.
	SplitView
	// Forge serves a document it signed with its own key.
	Forge
	// Tamper changes the signed payload and keeps the root's signature.
	Tamper
	// Strip removes the signature.
	Strip
	// Foreign serves a validly signed document of another network.
	Foreign
)

func (b Behavior) String() string {
	switch b {
	case Honest:
		return "honest"
	case Withhold:
		return "withhold"
	case Rollback:
		return "rollback"
	case SplitView:
		return "split-view"
	case Forge:
		return "forge"
	case Tamper:
		return "tamper"
	case Strip:
		return "strip"
	case Foreign:
		return "foreign"
	}
	return fmt.Sprintf("behavior(%d)", int(b))
}

// All lists every malicious behaviour (Honest excluded).
var All = []Behavior{Withhold, Rollback, SplitView, Forge, Tamper, Strip, Foreign}

// Coordinator stores what an honest coordinator would hold, the encoded
// envelopes the owner published, and serves them according to its
// behaviour. Methods are safe for concurrent use.
type Coordinator struct {
	mu       sync.Mutex
	behavior Behavior
	history  [][]byte
	frozen   int
	// favoured devices get the newest document under SplitView.
	favoured map[string]bool
	// attacker is the coordinator's own signing key (Forge).
	attacker ed25519.PrivateKey
	// foreign is a validly signed document of another network (Foreign).
	foreign []byte
}

// New returns an honest coordinator. foreign may be nil; Foreign then
// falls back to Forge.
func New(foreign []byte) (*Coordinator, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Coordinator{attacker: priv, foreign: foreign, favoured: map[string]bool{}, frozen: -1}, nil
}

// Publish stores a new envelope from the owner, as the real coordinator
// does on upload.
func (c *Coordinator) Publish(env []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.history = append(c.history, bytes.Clone(env))
}

// SetBehavior switches the behaviour. Withhold freezes at the current
// newest document.
func (c *Coordinator) SetBehavior(b Behavior) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.behavior = b
	c.frozen = len(c.history) - 1
}

// Favour makes device receive the newest document under SplitView.
func (c *Coordinator) Favour(device string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.favoured[device] = true
}

// Serve returns the envelope the coordinator sends to device.
func (c *Coordinator) Serve(device string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.history) == 0 {
		return nil, errors.New("nothing published")
	}
	newest := c.history[len(c.history)-1]
	switch c.behavior {
	case Honest:
		return bytes.Clone(newest), nil
	case Withhold:
		return bytes.Clone(c.history[max(c.frozen, 0)]), nil
	case Rollback:
		return bytes.Clone(c.history[0]), nil
	case SplitView:
		if c.favoured[device] {
			return bytes.Clone(newest), nil
		}
		return bytes.Clone(c.history[0]), nil
	case Forge:
		return c.forge(newest)
	case Tamper:
		return tamper(newest)
	case Strip:
		return strip(newest)
	case Foreign:
		if c.foreign != nil {
			return bytes.Clone(c.foreign), nil
		}
		return c.forge(newest)
	}
	return nil, fmt.Errorf("unknown behaviour %d", c.behavior)
}

// forge re-signs the newest document, with a higher version and a rule
// that opens every device to every other, with the coordinator's own key.
func (c *Coordinator) forge(newest []byte) ([]byte, error) {
	doc, err := decodeUnverified(newest)
	if err != nil {
		return nil, err
	}
	doc.Version += 10
	doc.IssuedAt = time.Now().UTC().Truncate(time.Second)
	doc.Rules = append(doc.Rules, trust.Rule{From: []string{trust.RuleWildcard}, To: []string{trust.RuleWildcard}, Protocol: trust.ProtocolAny, Ports: []string{}})
	env, err := trust.SignDocument(doc, c.attacker)
	if err != nil {
		return nil, err
	}
	return trust.MarshalEnvelope(env)
}

// tamper raises the version inside the signed payload.
func tamper(newest []byte) ([]byte, error) {
	env, err := trust.UnmarshalEnvelope(newest)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(env.Payload, &raw); err != nil {
		return nil, err
	}
	var v uint64
	if err := json.Unmarshal(raw["version"], &v); err != nil {
		return nil, err
	}
	raw["version"] = json.RawMessage(fmt.Sprint(v + 10))
	payload, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	env.Payload = payload
	return trust.MarshalEnvelope(env)
}

// strip zeroes the signature.
func strip(newest []byte) ([]byte, error) {
	env, err := trust.UnmarshalEnvelope(newest)
	if err != nil {
		return nil, err
	}
	env.Signature = make([]byte, len(env.Signature))
	return trust.MarshalEnvelope(env)
}

// decodeUnverified reads a document the way an attacker can: without the
// root's private key, only the public payload.
func decodeUnverified(data []byte) (*trust.Document, error) {
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return nil, err
	}
	var doc trust.Document
	if err := json.Unmarshal(env.Payload, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}
