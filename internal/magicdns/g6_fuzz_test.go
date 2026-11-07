package magicdns

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// FuzzAnswerStream covers DNS over TCP (#654, ADR-0209): the stream path
// has no 512-byte limit, so answers must stay bounded by the 64 KiB TCP
// message size and remain valid messages.
func FuzzAnswerStream(f *testing.F) {
	f.Add([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	f.Add(seedPTR)
	doc := testDoc()
	f.Fuzz(func(t *testing.T, data []byte) {
		out := AnswerStream(doc, data)
		if len(out) > 0xffff {
			t.Fatalf("answer exceeds a TCP DNS message: %d", len(out))
		}
		if out != nil && Handles(doc, data) {
			var m dnsmessage.Message
			if err := m.Unpack(out); err != nil {
				t.Fatalf("handled query answered with an invalid message: %v", err)
			}
		}
	})
}
