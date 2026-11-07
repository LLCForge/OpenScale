package coordinator

import (
	"bytes"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/control"
)

// The coordinator stores and forwards sealed blobs byte for byte, only
// between visible peers, pushes them only to devices that announced they
// read them, and tells devices which online peers are plain-only.
func TestSealedStoreAndForward(t *testing.T) {
	r := newExtRig(t)
	blob := bytes.Repeat([]byte{0xA5}, 200)

	// Before b announces the feature it is subscribed but old.
	r.do(r.b, control.Message{T: control.TypeCaps})
	r.do(r.a, control.Message{T: control.TypeCaps, Features: []string{control.FeatureSealed}})
	list := r.do(r.a, control.Message{T: control.TypePeerSealed})
	if list.T != control.TypePeerSealed || len(list.PeerSealed) != 1 || list.PeerSealed[0].ID != r.b.ID || !list.PeerSealed[0].Old || list.PeerSealed[0].Cap {
		t.Fatalf("listing with an old peer = %+v", list)
	}
	// A blob for an old device is kept but never pushed: it could not
	// decode the message.
	if resp := r.do(r.a, control.Message{T: control.TypeSealed, Target: r.b.ID, Sealed: blob}); !resp.Complete {
		t.Fatalf("put = %+v", resp)
	}
	if p := r.pushed(); len(p) != 0 {
		t.Fatalf("pushed to an old device: %+v", p)
	}

	// b upgrades: it announces the feature and gets pushes.
	r.do(r.b, control.Message{T: control.TypeCaps, Features: []string{control.FeatureSealed}})
	blob2 := bytes.Repeat([]byte{0x5A}, control.MaxSealed)
	if resp := r.do(r.a, control.Message{T: control.TypeSealed, Target: r.b.ID, Sealed: blob2}); !resp.Complete {
		t.Fatalf("put = %+v", resp)
	}
	p := r.pushed()[r.b.IPv4]
	if len(p) != 1 || p[0].T != control.TypeSealed || p[0].Target != r.a.ID || !bytes.Equal(p[0].Sealed, blob2) {
		t.Fatalf("push = %+v", p)
	}
	list = r.do(r.b, control.Message{T: control.TypePeerSealed})
	if len(list.PeerSealed) != 1 || list.PeerSealed[0].ID != r.a.ID || !list.PeerSealed[0].Cap || !bytes.Equal(list.PeerSealed[0].Sealed, blob2) {
		t.Fatalf("listing = %+v", list)
	}

	// c sees nobody: it can neither post to nor read about a or b.
	if resp := r.do(r.c, control.Message{T: control.TypeSealed, Target: r.a.ID, Sealed: blob}); resp.T != control.TypeError {
		t.Fatalf("c posted to a: %+v", resp)
	}
	if list := r.do(r.c, control.Message{T: control.TypePeerSealed}); list.Total != 0 || len(list.PeerSealed) != 0 {
		t.Fatalf("c listing = %+v", list)
	}
	if resp := r.do(r.a, control.Message{T: control.TypeSealed, Target: r.c.ID, Sealed: blob}); resp.T != control.TypeError {
		t.Fatalf("a posted to an invisible peer: %+v", resp)
	}
	if resp := r.do(r.a, control.Message{T: control.TypeSealed, Target: r.b.ID}); resp.T != control.TypeError {
		t.Fatalf("empty blob accepted: %+v", resp)
	}
	if resp := r.do(r.a, control.Message{T: control.TypePeerSealed, Offset: 5}); resp.T != control.TypeError {
		t.Fatalf("offset past the end accepted: %+v", resp)
	}

	// Rate limit per device and second.
	limited := false
	for i := 0; i < maxSealedPerSecond+1; i++ {
		if resp := r.do(r.a, control.Message{T: control.TypeSealed, Target: r.b.ID, Sealed: blob}); resp.T == control.TypeError {
			limited = true
		}
	}
	r.pushed()
	if !limited {
		t.Fatal("no rate limit")
	}

	// Blobs expire.
	r.now = r.now.Add(sealedTTL + time.Second)
	r.do(r.b, control.Message{T: control.TypeCaps, Features: []string{control.FeatureSealed}})
	r.do(r.a, control.Message{T: control.TypeCaps, Features: []string{control.FeatureSealed}})
	list = r.do(r.b, control.Message{T: control.TypePeerSealed})
	if len(list.PeerSealed) != 1 || len(list.PeerSealed[0].Sealed) != 0 || !list.PeerSealed[0].Cap {
		t.Fatalf("expired blob still listed: %+v", list)
	}
	r.s.ext.prune(r.s.cfg.Store.Document(), r.now.Add(control.SubscriptionTTL+time.Second))
	if r.s.ext.seal.total != 0 || len(r.s.ext.seal.caps) != 0 {
		t.Fatalf("prune left %d blobs, %d marks", r.s.ext.seal.total, len(r.s.ext.seal.caps))
	}
}

// The mailbox stays bounded when one device floods it.
func TestSealedMailboxBounds(t *testing.T) {
	x := newSealedState()
	now := time.Now()
	for i := 0; i < maxSealedPerTarget+10; i++ {
		now = now.Add(time.Second) // new second: no rate limit
		if !x.store(string(rune('A'+i%26))+string(rune('a'+i/26)), "rcv", []byte{1}, now) {
			t.Fatalf("store %d refused", i)
		}
	}
	if n := len(x.box["rcv"]); n != maxSealedPerTarget || x.total != maxSealedPerTarget {
		t.Fatalf("mailbox holds %d (total %d)", n, x.total)
	}
}

func TestFeaturesListSealed(t *testing.T) {
	r := newExtRig(t)
	caps := r.do(r.a, control.Message{T: control.TypeCaps})
	found := false
	for _, f := range caps.Features {
		found = found || f == control.FeatureSealed
	}
	if !found {
		t.Fatalf("caps = %+v", caps.Features)
	}
}
