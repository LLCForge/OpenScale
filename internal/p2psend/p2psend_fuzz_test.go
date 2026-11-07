package p2psend

import (
	"bytes"
	"crypto/rand"
	"net/netip"
	"testing"
)

// Fuzz tests for the end-to-end file format (#654, ADR-0209). Every byte a
// receiver or relay reads before authentication goes through these.

func fuzzID(f *testing.F) Identity {
	var priv [32]byte
	priv[0] = 7
	id, err := NewIdentity(priv)
	if err != nil {
		f.Fatal(err)
	}
	return id
}

func FuzzParseFileHello(f *testing.F) {
	id := fuzzID(f)
	sender, _ := GenerateIdentity(rand.Reader)
	e, keys, _ := senderSession(sender, id.Public, rand.Reader)
	hb, _ := encodeHeader(header{V: 1, ID: "00112233445566778899aabbccddeeff", Name: "a.txt", Size: 3,
		SHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Chunk: ChunkSize})
	sealed, _ := seal(&keys.header, domainHeader, 0, hb, []byte(magic))
	f.Add(encodeFileHello(fileHello{sender: sender.Public, ephemeral: e, sealed: sealed}))
	f.Add([]byte(magic + "F\x01"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = ParseFileHello(b)
		_ = OpenHeader(id, b, 1<<30)
	})
}

func FuzzParseLayer(f *testing.F) {
	id := fuzzID(f)
	other, _ := GenerateIdentity(rand.Reader)
	dest := netip.MustParseAddrPort("100.64.0.9:41642")
	onion, _ := BuildOnion([]Hop{{Key: id.Public, Addr: dest}, {Key: other.Public, Addr: dest}}, dest, Key{1}, rand.Reader)
	f.Add(onion)
	f.Add([]byte(magic + "R\x01"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseLayer(id, b)
		_, _ = parseLayerPlain(Key{}, b)
	})
}

func FuzzDecodeHeader(f *testing.F) {
	f.Add([]byte(`{"v":1,"id":"00112233445566778899aabbccddeeff","name":"x","size":1,"sha256":"` + string(bytes.Repeat([]byte("a"), 64)) + `","chunk":65536}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := decodeHeader(b)
		if err != nil {
			return
		}
		if h.validate(1<<40) == nil {
			if numChunks(h.Size) == 0 {
				t.Fatal("zero chunks")
			}
			if _, err := encodeHeader(h); err != nil && len(h.Name) < 512 {
				t.Fatalf("valid header does not encode: %v", err)
			}
		}
	})
}

func FuzzReplyFrame(f *testing.F) {
	var k [32]byte
	var buf bytes.Buffer
	_ = (&replyChannel{key: &k}).write(&buf, reply{Status: statusAccept, Offset: 3})
	f.Add(buf.Bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = (&replyChannel{key: &k}).read(bytes.NewReader(b))
	})
}
