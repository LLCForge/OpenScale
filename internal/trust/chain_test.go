package trust

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func chainNext(t *testing.T, doc *Document, prev Envelope) *Document {
	t.Helper()
	next, err := doc.Next(testNow, DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	next.LinkVersionChain(prev)
	return next
}

func TestVersionChainAbsentEncodesAsBefore(t *testing.T) {
	f := newFixture(t)
	env := f.sign(t, f.doc)
	if bytes.Contains(env.Payload, []byte("prev_digest")) {
		t.Fatal("a document without the chain must not carry prev_digest")
	}
	// Turning the chain off removes the field again.
	next, _ := f.doc.Next(testNow, DefaultValidity)
	next.SetVersionChain(true)
	next.LinkVersionChain(env)
	next.SetVersionChain(false)
	payload, err := DocumentPayload(next)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte("prev_digest")) {
		t.Fatal("a chain turned off must not carry prev_digest")
	}
}

func TestVersionChainValidate(t *testing.T) {
	f := newFixture(t)
	v1 := f.sign(t, f.doc)
	next, _ := f.doc.Next(testNow, DefaultValidity)

	next.SetVersionChain(true)
	if err := next.Validate(); err == nil {
		t.Fatal("an unlinked placeholder must not validate")
	}
	next.LinkVersionChain(v1)
	if err := next.Validate(); err != nil {
		t.Fatalf("linked: %v", err)
	}
	for _, bad := range []string{
		strings.ToUpper(DocumentDigest(v1)),
		DocumentDigest(v1)[:63],
		DocumentDigest(v1) + "0",
		strings.Repeat("g", 64),
	} {
		next.PrevDigest = bad
		if err := next.Validate(); err == nil {
			t.Fatalf("prev_digest %q must not validate", bad)
		}
	}
	first := *f.doc
	first.PrevDigest = DocumentDigest(v1)
	if err := first.Validate(); err == nil {
		t.Fatal("version 1 must not carry prev_digest")
	}
}

func TestStateRefusesForkedHistory(t *testing.T) {
	f := newFixture(t)
	state := &State{Anchor: f.anchor}
	v1 := f.sign(t, f.doc)
	if _, err := state.Accept(v1, testNow); err != nil {
		t.Fatal(err)
	}
	v2doc := chainNext(t, f.doc, v1)
	v2doc.SetVersionChain(true)
	v2doc.LinkVersionChain(v1)
	v2 := f.sign(t, v2doc)
	if _, err := state.Accept(v2, testNow); err != nil {
		t.Fatalf("linked v2: %v", err)
	}

	// The root signs a second v2 that devices never saw and builds v3 on it.
	other, _ := f.doc.Next(testNow, 30*24*time.Hour)
	other.SetVersionChain(true)
	other.LinkVersionChain(v1)
	otherEnv := f.sign(t, other)
	forked := chainNext(t, other, otherEnv)
	if _, err := state.Accept(f.sign(t, forked), testNow); !errors.Is(err, ErrForkedHistory) {
		t.Fatalf("forked v3 error = %v, want ErrForkedHistory", err)
	}
	if state.HighestVersion != 2 {
		t.Fatalf("state advanced to %d", state.HighestVersion)
	}

	// The real v3 is accepted; a member that skipped versions cannot check
	// the link and accepts v4.
	v3doc := chainNext(t, v2doc, v2)
	v3 := f.sign(t, v3doc)
	if _, err := state.Accept(v3, testNow); err != nil {
		t.Fatalf("linked v3: %v", err)
	}
	v4 := f.sign(t, chainNext(t, v3doc, v3))
	behind := &State{Anchor: f.anchor}
	if _, err := behind.Accept(v1, testNow); err != nil {
		t.Fatal(err)
	}
	if _, err := behind.Accept(v4, testNow); err != nil {
		t.Fatalf("skipping member: %v", err)
	}
}

func TestVerifyChain(t *testing.T) {
	f := newFixture(t)
	v1 := f.sign(t, f.doc)
	d2 := chainNext(t, f.doc, v1)
	d2.SetVersionChain(true)
	d2.LinkVersionChain(v1)
	v2 := f.sign(t, d2)
	d3 := chainNext(t, d2, v2)
	v3 := f.sign(t, d3)
	if i, err := VerifyChain([]Envelope{v1, v2, v3}, []*Document{f.doc, d2, d3}); err != nil || i != -1 {
		t.Fatalf("intact chain: %d %v", i, err)
	}
	d3.PrevDigest = DocumentDigest(v1)
	v3bad := f.sign(t, d3)
	if i, _ := VerifyChain([]Envelope{v1, v2, v3bad}, []*Document{f.doc, d2, d3}); i != 2 {
		t.Fatalf("forked index = %d, want 2", i)
	}
	if _, err := VerifyChain([]Envelope{v1}, nil); err == nil {
		t.Fatal("mismatched lengths must fail")
	}
}

func TestPrevDigestDecodesStrictly(t *testing.T) {
	f := newFixture(t)
	v1 := f.sign(t, f.doc)
	d2 := chainNext(t, f.doc, v1)
	d2.SetVersionChain(true)
	d2.LinkVersionChain(v1)
	payload, err := DocumentPayload(d2)
	if err != nil {
		t.Fatal(err)
	}
	var back Document
	if err := decodeStrict(payload, &back); err != nil {
		t.Fatal(err)
	}
	if back.PrevDigest != DocumentDigest(v1) {
		t.Fatal("prev_digest lost in round trip")
	}
	again, _ := json.Marshal(&back)
	if !bytes.Equal(again, payload) {
		t.Fatal("re-encoding changed the payload")
	}
}

func FuzzValidatePrevDigest(f *testing.F) {
	f.Add("")
	f.Add(strings.Repeat("0", 64))
	f.Add(strings.Repeat("ab", 32))
	f.Add(strings.Repeat("AB", 32))
	f.Fuzz(func(t *testing.T, s string) {
		doc := &Document{Version: 2, PrevDigest: s}
		err := doc.validatePrevDigest()
		if err == nil && s != "" {
			if len(s) != 64 || strings.ToLower(s) != s || s == chainPlaceholder {
				t.Fatalf("accepted %q", s)
			}
		}
		if s == "" && err != nil {
			t.Fatal("empty must be accepted")
		}
	})
}
