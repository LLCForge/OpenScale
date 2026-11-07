package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// oldMessage is the message as protocol version 1 knew it before the
// extensions (ADR-0025, ADR-0026). Old coordinators and devices decode with
// exactly these fields and refuse unknown ones.
type oldMessage struct {
	V        int    `json:"v"`
	T        string `json:"t"`
	ID       uint32 `json:"id"`
	Version  uint64 `json:"version,omitempty"`
	Digest   string `json:"digest,omitempty"`
	Size     int    `json:"size,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	Offset   int    `json:"offset,omitempty"`
	Total    int    `json:"total,omitempty"`
	Data     []byte `json:"data,omitempty"`
	Peers    []struct {
		ID       string `json:"id"`
		Endpoint string `json:"endpoint"`
	} `json:"peers,omitempty"`
	Next      int    `json:"next,omitempty"`
	Complete  bool   `json:"complete,omitempty"`
	Error     string `json:"error,omitempty"`
	Sig       []byte `json:"sig,omitempty"`
	InviteSig []byte `json:"isig,omitempty"`
}

func oldDecode(data []byte) (oldMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m oldMessage
	if err := dec.Decode(&m); err != nil {
		return m, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return m, errors.New("trailing data")
	}
	return m, nil
}

// The requests a new device sends before it knows the coordinator's
// features carry only old fields, so an old coordinator decodes them and
// answers "unknown message type" at once instead of dropping them.
func TestProbeRequestsDecodeOnOldPeers(t *testing.T) {
	for _, m := range []Message{
		{T: TypeCaps, ID: 7},
		{T: TypeDocGzip, ID: 8, Version: 3, Offset: 700},
	} {
		data, err := Encode(m)
		if err != nil {
			t.Fatal(err)
		}
		got, err := oldDecode(data)
		if err != nil {
			t.Fatalf("%s: old decoder refused it: %v", m.T, err)
		}
		if got.T != m.T || got.ID != m.ID {
			t.Fatalf("%s: decoded %+v", m.T, got)
		}
	}
	// Messages without extension fields encode exactly as before.
	data, err := Encode(Message{T: TypeHello, ID: 1, Version: 2, Digest: "ab"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "features") || strings.Contains(string(data), "cands") {
		t.Fatalf("empty extensions leaked into %s", data)
	}
	if _, err := oldDecode(data); err != nil {
		t.Fatal(err)
	}
}

func TestExtensionBounds(t *testing.T) {
	long := strings.Repeat("a", MaxCandidateLen+1)
	bad := []Message{
		{T: TypeCandidates, Cands: make([]string, MaxCandidates+1)},
		{T: TypeCandidates, Cands: []string{long}},
		{T: TypeCandidates, Cands: []string{""}},
		{T: TypeCaps, Features: []string{""}},
		{T: TypeCall, Target: strings.Repeat("f", 65)},
		{T: TypePeerCandidates, PeerCands: []PeerCandidates{{ID: ""}}},
		{T: TypePeerCandidates, PeerCands: []PeerCandidates{{ID: "x", Endpoint: long}}},
	}
	for i, m := range bad {
		m.V = ProtocolVersion
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(data); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	good := Message{T: TypePeerCandidates, PeerCands: []PeerCandidates{{ID: "00112233445566778899aabbccddeeff", Endpoint: "203.0.113.5:41641",
		Cands: []string{"192.168.1.20:41641", "[2001:db8::1]:41641"}}}}
	data, err := Encode(good)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data)
	if err != nil || len(got.PeerCands) != 1 || len(got.PeerCands[0].Cands) != 2 {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if EncodedSize(good) != len(data) {
		t.Fatalf("EncodedSize = %d, want %d", EncodedSize(good), len(data))
	}
}

func FuzzDecode(f *testing.F) {
	for _, m := range []Message{
		{T: TypeHello, Version: 1},
		{T: TypeCandidates, Cands: []string{"192.168.1.2:41641"}},
		{T: TypePeerCandidates, PeerCands: []PeerCandidates{{ID: "a", Cands: []string{"[::1]:1"}}}},
		{T: TypeCaps, Features: []string{FeatureCall}},
	} {
		data, _ := Encode(m)
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Decode(data)
		if err != nil {
			return
		}
		if len(m.Cands) > MaxCandidates || len(m.PeerCands) > PeersPerPage || len(m.Features) > MaxFeatures || len(m.Data) > ChunkSize {
			t.Fatalf("bounds not enforced: %+v", m)
		}
		if _, err := Encode(m); err != nil && len(data) <= MaxDatagram {
			// A decoded message re-encodes; only escaping may grow it.
			if !strings.Contains(err.Error(), "datagram limit") {
				t.Fatalf("re-encode: %v", err)
			}
		}
	})
}
