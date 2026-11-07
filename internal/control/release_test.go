package control

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// preReleaseMessage is Message as released before ADR-0225, without File,
// Release, Source and Checked.
type preReleaseMessage struct {
	V         int              `json:"v"`
	T         string           `json:"t"`
	ID        uint32           `json:"id"`
	Version   uint64           `json:"version,omitempty"`
	Digest    string           `json:"digest,omitempty"`
	Size      int              `json:"size,omitempty"`
	Endpoint  string           `json:"endpoint,omitempty"`
	Offset    int              `json:"offset,omitempty"`
	Total     int              `json:"total,omitempty"`
	Data      []byte           `json:"data,omitempty"`
	Peers     []PeerEndpoint   `json:"peers,omitempty"`
	Next      int              `json:"next,omitempty"`
	Complete  bool             `json:"complete,omitempty"`
	Error     string           `json:"error,omitempty"`
	Sig       []byte           `json:"sig,omitempty"`
	InviteSig []byte           `json:"isig,omitempty"`
	Features  []string         `json:"features,omitempty"`
	Cands     []string         `json:"cands,omitempty"`
	PeerCands []PeerCandidates `json:"pcands,omitempty"`
	Target    string           `json:"target,omitempty"`
}

func preReleaseDecode(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m preReleaseMessage
	return dec.Decode(&m)
}

// The compatibility rule of ADR-0225: old peers decode strictly, so the new
// fields must stay out of every message an old peer can receive.
func TestReleaseFieldsAndOldPeers(t *testing.T) {
	// An old coordinator can decode the announcement request (and answers
	// "unknown message type").
	req, err := Encode(Message{T: TypeRelease, ID: 7})
	if err != nil || preReleaseDecode(req) != nil {
		t.Fatalf("announcement request not readable by an old coordinator: %s %v", req, err)
	}
	// Messages old devices receive carry none of the new fields.
	for _, m := range []Message{{T: TypeHello, Version: 3, Digest: strings.Repeat("a", 64)}, {T: TypeCaps, Features: []string{FeatureRelease}}, {T: TypeNotify, Version: 4}} {
		data, _ := Encode(m)
		if err := preReleaseDecode(data); err != nil {
			t.Fatalf("%s: %v", m.T, err)
		}
	}
	// The reply really would be refused by an old decoder: that is why it
	// is only sent in answer to TypeRelease.
	reply, err := Encode(Message{T: TypeRelease, Release: "1.0.1", File: "openscale-1.0.1.release.json", Digest: strings.Repeat("b", 64), Size: 10, Source: "github.com/LLCForge/OpenScale", Checked: 1})
	if err != nil {
		t.Fatal(err)
	}
	if preReleaseDecode(reply) == nil {
		t.Fatal("old decoder accepted unknown fields; the compatibility reasoning changed")
	}
	if m, err := Decode(reply); err != nil || m.Release != "1.0.1" || m.Source == "" {
		t.Fatalf("%+v %v", m, err)
	}
}

func TestReleaseFieldValidation(t *testing.T) {
	for _, name := range []string{"../x", "a/b", `a\b`, ".hidden", "-x", "a..b", strings.Repeat("a", MaxReleaseFileName+1), "ü.deb"} {
		if ValidReleaseFileName(name) {
			t.Errorf("accepted %q", name)
		}
		if data, err := json.Marshal(Message{V: ProtocolVersion, T: TypeReleaseFile, File: name}); err == nil {
			if _, err := Decode(data); err == nil {
				t.Errorf("decoded file %q", name)
			}
		}
	}
	for _, name := range []string{"openscale-1.0.0-beta.2.release.json", "openscale_1.0.0~beta.2_amd64.deb", "openscale-windows-amd64.exe.gz"} {
		if !ValidReleaseFileName(name) {
			t.Errorf("refused %q", name)
		}
	}
	for _, m := range []Message{{T: TypeRelease, Release: "1.0 0"}, {T: TypeRelease, Checked: -1}, {T: TypeRelease, Source: strings.Repeat("s", MaxReleaseSource+1)}} {
		m.V = ProtocolVersion
		data, _ := json.Marshal(m)
		if _, err := Decode(data); err == nil {
			t.Errorf("decoded %+v", m)
		}
	}
}
