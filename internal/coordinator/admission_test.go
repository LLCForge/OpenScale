package coordinator

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

func TestParseAdmissionPolicyStrict(t *testing.T) {
	good := `{"version":1,"allow":[{"from":["laptop","tag:aile"],"to":["*"]}]}`
	if _, err := ParseAdmissionPolicy([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		``,
		`{"version":2,"allow":[]}`,
		`{"version":1,"allow":[{"from":[],"to":["*"]}]}`,
		`{"version":1,"allow":[{"from":["tag:"],"to":["*"]}]}`,
		`{"version":1,"allow":[{"from":["a b"],"to":["*"]}]}`,
		`{"version":1,"allow":[],"extra":true}`,
		`{"version":1,"allow":[]} {}`,
	} {
		if _, err := ParseAdmissionPolicy([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestRelayAdmissionNarrowsAndFailsClosed(t *testing.T) {
	a, b, c := dev(1, "a", "100.80.0.2"), dev(2, "b", "100.80.0.3"), dev(3, "c", "100.80.0.4")
	c.Tags = []string{"aile"}
	doc := &trust.Document{Version: 1, Devices: []trust.Device{a, b, c},
		Rules: []trust.Rule{{From: []string{"a"}, To: []string{"b", "c"}, Protocol: trust.ProtocolAny}}}
	now := time.Now()
	r := newRelayer(docStore{doc}, func() time.Time { return now }, 0, 0)

	path := filepath.Join(t.TempDir(), RelayAdmissionFile)
	if _, err := loadRelayAdmission(path, nil, now); err == nil {
		t.Fatal("missing file accepted at start")
	}
	if err := securefile.WriteNew(path, []byte(`{"version":1,"allow":[{"from":["a"],"to":["tag:aile"]}]}`)); err != nil {
		t.Fatal(err)
	}
	adm, err := loadRelayAdmission(path, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	r.admit = adm.allow

	if _, _, ok := r.forward(a.IPv4, relayPayload(c, 100)); !ok {
		t.Fatal("a -> c (tag:aile) refused")
	}
	if _, _, ok := r.forward(a.IPv4, relayPayload(b, 100)); ok {
		t.Fatal("a -> b relayed although the file does not allow it")
	}
	// The file never widens the document: c -> a has no rule.
	if _, _, ok := r.forward(c.IPv4, relayPayload(a, 100)); ok {
		t.Fatal("file widened the document")
	}

	// The file disappears: after the recheck interval nothing is relayed.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	now = now.Add(admissionRecheck)
	if _, _, ok := r.forward(a.IPv4, relayPayload(c, 100)); ok {
		t.Fatal("relayed after the admission file vanished")
	}
	// A corrupt file also denies.
	if err := securefile.WriteNew(path, []byte(`{"version":1,"allow":[`)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(admissionRecheck)
	if _, _, ok := r.forward(a.IPv4, relayPayload(c, 100)); ok {
		t.Fatal("relayed with a corrupt admission file")
	}
	if err := securefile.Replace(path, []byte(`{"version":1,"allow":[{"from":["*"],"to":["*"]}]}`)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(admissionRecheck)
	if _, _, ok := r.forward(a.IPv4, relayPayload(b, 100)); !ok {
		t.Fatal("repaired file not picked up")
	}
}
