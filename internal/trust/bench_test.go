package trust

import (
	"crypto/rand"
	"fmt"
	"testing"
)

// BenchmarkAcceptDocument is the document verification case of the
// performance gate (#576): signature, strict decoding, validation and the
// rollback state of a 64-device document.
func BenchmarkAcceptDocument(b *testing.B) {
	pub, priv, err := GenerateRootKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	id, err := NewNetworkID(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	ula, err := RandomULAPrefix(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	doc, err := NewDocument(id, DefaultDNSDomain, DefaultIPv4Prefix, ula, testNow, DefaultValidity)
	if err != nil {
		b.Fatal(err)
	}
	for i := range 64 {
		s, err := GenerateDeviceSecrets(rand.Reader, testNow)
		if err != nil {
			b.Fatal(err)
		}
		env, _, err := s.NewEnrollmentRequest(fmt.Sprintf("d%d", i), testNow)
		if err != nil {
			b.Fatal(err)
		}
		req, err := OpenEnrollmentRequest(env, testNow)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := doc.AddDevice(req, fmt.Sprintf("d%d", i), nil, testNow, DefaultDeviceLife); err != nil {
			b.Fatal(err)
		}
	}
	env, err := SignDocument(doc, priv)
	if err != nil {
		b.Fatal(err)
	}
	anchor := Anchor{RootKey: pub, NetworkID: id}
	b.ReportAllocs()
	for b.Loop() {
		s := State{Anchor: anchor}
		if _, err := s.Accept(env, testNow); err != nil {
			b.Fatal(err)
		}
	}
}
