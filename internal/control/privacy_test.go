package control

import (
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/version"
)

// reviewedKeys are the JSON keys of Message that were reviewed for #48
// (ADR-0008): none carries the software version, the operating system,
// the architecture or the host name. "version" is the signed document's
// version number, not the program's. A new field fails this test until it
// is reviewed and added here.
var reviewedKeys = []string{
	"v", "t", "id", "version", "digest", "size", "endpoint", "offset", "total", "data",
	"peers", "next", "complete", "error", "sig", "isig", "features", "cands", "pcands", "target",
	// ADR-0225: "rel" is the version the coordinator announces (the device
	// sends none); "file" names the release file a device fetches when it
	// updates, which tells the owner's coordinator the device's platform at
	// that moment only (accepted in ADR-0225).
	"file", "rel",
	// ADR-0225: the coordinator's upstream source and its last check, sent
	// by the coordinator only.
	"src", "chk",
	// ADR-0230: an opaque blob end-to-end encrypted for one peer, and the
	// per-peer list of such blobs; neither carries anything readable.
	"seal", "pseal",
}

func jsonKeys(t reflect.Type) []string {
	var keys []string
	for f := range t.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			keys = append(keys, "!"+f.Name)
			continue
		}
		keys = append(keys, name)
	}
	return keys
}

func TestMessageFieldsReviewedForMetadata(t *testing.T) {
	for _, k := range jsonKeys(reflect.TypeFor[Message]()) {
		if !slices.Contains(reviewedKeys, k) {
			t.Errorf("control.Message key %q is not reviewed for software/OS disclosure (#48, ADR-0008)", k)
		}
	}
	if f, ok := reflect.TypeFor[Message]().FieldByName("Version"); !ok || f.Type.Kind() != reflect.Uint64 {
		t.Error(`"version" must stay the numeric document version`)
	}
	for _, typ := range []reflect.Type{reflect.TypeFor[PeerEndpoint](), reflect.TypeFor[PeerCandidates]()} {
		for _, k := range jsonKeys(typ) {
			if !slices.Contains([]string{"id", "endpoint", "cands"}, k) {
				t.Errorf("%s key %q is not reviewed (#48)", typ, k)
			}
		}
	}
}

// TestHandshakeCarriesNoSoftwareVersion encodes the messages a device and
// the coordinator exchange first and checks that neither the program
// version nor the operating system appears in them.
func TestHandshakeCarriesNoSoftwareVersion(t *testing.T) {
	msgs := []Message{
		{T: TypeHello, Version: 7, Digest: strings.Repeat("ab", 32)},
		{T: TypeCaps, Features: []string{FeatureCandidates, FeatureCall, FeatureNotify, FeatureDocGzip}},
		{T: TypePeers, Version: 7, Total: 1, Peers: []PeerEndpoint{{ID: "dev", Endpoint: "198.51.100.1:41641"}}},
	}
	forbidden := []string{runtime.GOOS, runtime.GOARCH, "openscale", "go1."}
	if v := version.String(); v != "" && v != "0" {
		forbidden = append(forbidden, v)
	}
	for _, m := range msgs {
		data, err := Encode(m)
		if err != nil {
			t.Fatal(err)
		}
		low := strings.ToLower(string(data))
		for _, f := range forbidden {
			if f != "" && strings.Contains(low, strings.ToLower(f)) {
				t.Errorf("%s message contains %q: %s", m.T, f, data)
			}
		}
	}
}
