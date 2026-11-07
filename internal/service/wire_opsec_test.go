package service

import (
	"testing"
	"time"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/obfs"
	"github.com/openscale/openscale/internal/panel"
)

type fakeOpsec struct{ chain node.ChainStatus }

func (fakeOpsec) ObfsStatus() node.ObfsStatus {
	return node.ObfsStatus{Mode: "auto", TLS: true, Buckets: []int{256}, Stats: obfs.Stats{Wrapped: 7}}
}
func (fakeOpsec) G3Alerts() []node.G3Alert {
	return []node.G3Alert{{Kind: "exit_mitm", Peer: "vps", Text: "x", At: time.Unix(5, 0)}}
}
func (fakeOpsec) ExitCanaryResults() []node.CanaryResult {
	return []node.CanaryResult{{Address: "a:443", Status: "ok"}}
}
func (f fakeOpsec) ExitChainStatus() node.ChainStatus { return f.chain }
func (fakeOpsec) LostStatus() node.LostStatus         { return node.LostStatus{Lost: true} }

func TestOpsecViewWiring(t *testing.T) {
	v := opsecViewFrom(fakeOpsec{chain: node.ChainStatus{Entry: "ev", Final: "vps", Ready: true}})
	if v.Obfs.Mode != "auto" || !v.Obfs.TLS || v.Obfs.Wrapped != 7 || len(v.Alerts) != 1 || len(v.Canary) != 1 || !v.Lost.Lost {
		t.Fatalf("%+v", v)
	}
	// A valid plan that the engine does not route yet is not "ready".
	if v.Chain.Ready || v.Chain.Reason == "" {
		t.Fatalf("chain %+v", v.Chain)
	}
	if v.Quarantine == nil {
		t.Fatal("quarantine must be an empty list, not null")
	}
	r := newIdleRuntime(t)
	var _ panel.OpsecApp = r
	if _, err := r.Opsec(); err == nil {
		t.Fatal("no tunnel accepted")
	}
	if _, err := r.ReleaseQuarantine(""); err == nil {
		t.Fatal("empty peer accepted")
	}
}
