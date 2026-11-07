package node

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

var (
	extSelf  = netip.MustParseAddr("100.80.0.2")
	extCoord = netip.MustParseAddr("100.80.0.1")
)

// fakeCoordinator answers control requests in memory. old makes it behave
// like a coordinator from before the extensions: unknown types get an
// error, and any extension field would make it drop the request.
type fakeCoordinator struct {
	t       *testing.T
	old     bool
	doc     []byte
	gz      []byte
	seen    []string
	brokenZ bool
}

func (f *fakeCoordinator) engine() *Engine {
	e := &Engine{cfg: Config{Now: time.Now}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	e.client = newClient(func(pkt []byte) bool {
		info, err := packet.Parse(pkt)
		if err != nil {
			f.t.Fatal(err)
		}
		req, err := control.Decode(info.Payload)
		if err != nil {
			f.t.Fatal(err)
		}
		f.seen = append(f.seen, req.T)
		resp := f.answer(req, string(info.Payload))
		resp.ID = req.ID
		out, err := control.Encode(resp)
		if err != nil {
			f.t.Fatal(err)
		}
		reply, err := packet.BuildUDP4(extCoord, extSelf, control.Port, clientPort, out)
		if err != nil {
			f.t.Fatal(err)
		}
		e.client.intercept(reply)
		return true
	})
	e.client.setAddrs(extSelf, extCoord)
	return e
}

func (f *fakeCoordinator) answer(req control.Message, raw string) control.Message {
	if f.old {
		for _, field := range []string{`"features"`, `"cands"`, `"pcands"`, `"target"`} {
			if strings.Contains(raw, field) {
				f.t.Errorf("extension field %s sent to an old coordinator", field)
			}
		}
	}
	chunk := func(t string, data []byte) control.Message {
		end := min(req.Offset+control.ChunkSize, len(data))
		return control.Message{T: t, Version: req.Version, Offset: req.Offset, Total: len(data), Data: data[req.Offset:end]}
	}
	switch {
	case req.T == control.TypeDoc:
		return chunk(control.TypeDoc, f.doc)
	case req.T == control.TypePeers:
		return control.Message{T: control.TypePeers}
	case f.old:
		return control.Message{T: control.TypeError, Error: "unknown message type"}
	case req.T == control.TypeCaps:
		return control.Message{T: control.TypeCaps, Features: []string{control.FeatureDocGzip, control.FeatureCandidates}}
	case req.T == control.TypeDocGzip && f.brokenZ:
		return control.Message{T: control.TypeDocGzip, Offset: req.Offset, Total: 3, Data: []byte{1, 2, 3}}
	case req.T == control.TypeDocGzip:
		return chunk(control.TypeDocGzip, f.gz)
	case req.T == control.TypePeerCandidates:
		return control.Message{T: control.TypePeerCandidates}
	}
	return control.Message{T: control.TypeError, Error: "unknown message type"}
}

func gz(t *testing.T, data []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func helloFor(doc []byte) control.Message {
	sum := sha256.Sum256(doc)
	return control.Message{T: control.TypeHello, Version: 5, Size: len(doc), Digest: hex.EncodeToString(sum[:])}
}

// Against an old coordinator the device learns "no extensions" from one
// immediate error and then talks exactly the old protocol.
func TestOldCoordinatorKeepsOldProtocol(t *testing.T) {
	doc := bytes.Repeat([]byte(`{"belge":"içerik"}`), 200)
	f := &fakeCoordinator{t: t, old: true, doc: doc}
	e := f.engine()
	ctx := context.Background()
	start := time.Now()
	e.refreshCaps(ctx)
	if time.Since(start) > time.Second {
		t.Fatal("caps against an old coordinator waited for a timeout")
	}
	if !e.caps.old || len(e.CoordinatorFeatures()) != 0 {
		t.Fatalf("caps = %+v", e.caps)
	}
	got, err := e.fetchDocument(ctx, helloFor(doc))
	if err != nil || !bytes.Equal(got, doc) {
		t.Fatalf("fetch: %v", err)
	}
	e.reportCandidates(ctx)
	if _, err := e.fetchPeers(ctx, &trust.Document{}); err != nil {
		t.Fatal(err)
	}
	if err := e.callPeer(ctx, "x"); err == nil {
		t.Fatal("call sent to an old coordinator")
	}
	for _, typ := range f.seen {
		if typ != control.TypeCaps && typ != control.TypeDoc && typ != control.TypePeers {
			t.Fatalf("sent %q to an old coordinator", typ)
		}
	}
	// Asked again only after a while.
	n := len(f.seen)
	e.refreshCaps(ctx)
	if len(f.seen) != n {
		t.Fatal("old coordinator asked for caps on every sync")
	}
}

func TestCompressedDocumentAndFallback(t *testing.T) {
	doc := bytes.Repeat([]byte(`{"belge":"içerik"}`), 400)
	f := &fakeCoordinator{t: t, doc: doc, gz: gz(t, doc)}
	e := f.engine()
	ctx := context.Background()
	e.refreshCaps(ctx)
	got, err := e.fetchDocument(ctx, helloFor(doc))
	if err != nil || !bytes.Equal(got, doc) {
		t.Fatalf("compressed fetch: %v", err)
	}
	docRequests := 0
	for _, typ := range f.seen {
		if typ == control.TypeDoc {
			docRequests++
		}
	}
	if docRequests != 0 {
		t.Fatal("plain transfer used although compressed works")
	}
	f.brokenZ = true
	got, err = e.fetchDocument(ctx, helloFor(doc))
	if err != nil || !bytes.Equal(got, doc) {
		t.Fatalf("fallback fetch: %v", err)
	}
}

// A hostile coordinator cannot make the device inflate more than the
// announced size, nor slip in other content.
func TestInflateDocumentBounds(t *testing.T) {
	doc := []byte(strings.Repeat("a", 1000))
	hello := helloFor(doc)
	if _, err := inflateDocument(gz(t, doc), hello); err != nil {
		t.Fatal(err)
	}
	bomb := gz(t, make([]byte, 50<<20))
	if _, err := inflateDocument(bomb, hello); err == nil {
		t.Fatal("bomb accepted")
	}
	other := []byte(strings.Repeat("b", 1000))
	if _, err := inflateDocument(gz(t, other), hello); err == nil {
		t.Fatal("other content accepted")
	}
	if _, err := inflateDocument([]byte("not gzip"), hello); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestPushHandling(t *testing.T) {
	e := &Engine{cfg: Config{Now: time.Now}, syncWake: make(chan struct{}, 1)}
	// A notice for an older or equal version does nothing; a newer one wakes
	// the sync loop once per notifyMinInterval.
	e.onPushVersion(control.Message{T: control.TypeNotify, Version: 3}, 3)
	select {
	case <-e.syncWake:
		t.Fatal("woken for an old version")
	default:
	}
	e.onPushVersion(control.Message{T: control.TypeNotify, Version: 4}, 3)
	e.onPushVersion(control.Message{T: control.TypeNotify, Version: 5}, 3)
	select {
	case <-e.syncWake:
	default:
		t.Fatal("not woken for a newer version")
	}
	select {
	case <-e.syncWake:
		t.Fatal("woken twice within the rate limit")
	default:
	}
}
