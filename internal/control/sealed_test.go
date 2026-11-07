package control

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSealedFieldsBounds(t *testing.T) {
	good := []Message{
		{T: TypeSealed, Target: "00112233445566778899aabbccddeeff", Sealed: bytes.Repeat([]byte{1}, MaxSealed)},
		{T: TypePeerSealed, Total: 2, Next: 2, PeerSealed: []PeerSealed{{ID: "a", Sealed: []byte{1, 2}, Cap: true}, {ID: "b", Old: true}}},
	}
	for _, m := range good {
		data, err := Encode(m)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(data)
		if err != nil {
			t.Fatalf("%s: %v", m.T, err)
		}
		if !bytes.Equal(got.Sealed, m.Sealed) || len(got.PeerSealed) != len(m.PeerSealed) {
			t.Fatalf("round trip %+v", got)
		}
	}
	bad := []Message{
		{T: TypeSealed, Sealed: make([]byte, MaxSealed+1)},
		{T: TypePeerSealed, PeerSealed: []PeerSealed{{ID: ""}}},
		{T: TypePeerSealed, PeerSealed: []PeerSealed{{ID: strings.Repeat("f", 65)}}},
		{T: TypePeerSealed, PeerSealed: []PeerSealed{{ID: "a", Cap: true, Old: true}}},
		{T: TypePeerSealed, PeerSealed: []PeerSealed{{ID: "a", Sealed: make([]byte, MaxSealed+1)}}},
		{T: TypePeerSealed, PeerSealed: make([]PeerSealed, PeersPerPage+1)},
	}
	for i, m := range bad {
		m.V = ProtocolVersion
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(data); err == nil {
			t.Errorf("bad message %d accepted", i)
		}
	}
}

// An old device decodes strictly: a message with a sealed field fails to
// decode, which is why the coordinator pushes TypeSealed only to devices
// that announced FeatureSealed.
func TestSealedFieldsAreNewFields(t *testing.T) {
	data, err := Encode(Message{T: TypeSealed, Target: "x", Sealed: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"seal"`) {
		t.Fatalf("encoded %s", data)
	}
	plain, err := Encode(Message{T: TypeCandidates, Cands: []string{"192.0.2.1:1"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), `"seal`) {
		t.Fatalf("sealed key leaked into an old message type: %s", plain)
	}
}
