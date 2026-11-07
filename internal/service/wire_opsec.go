package service

import (
	"errors"
	"strings"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
)

// The panel's opsec screen (ADR-0186..0191, panel.OpsecApp) reads the
// running tunnel's state. The settings themselves come from opsec.json in
// the device directory, which the engine loads when it starts.

var errOpsecNoTunnel = errors.New("tünel çalışmıyor")

var _ panel.OpsecApp = (*Runtime)(nil)

// Opsec implements panel.OpsecApp.
func (r *Runtime) Opsec() (panel.OpsecView, error) {
	e := r.currentEngine()
	if e == nil {
		return panel.OpsecView{}, errOpsecNoTunnel
	}
	return opsecView(e), nil
}

// opsecSource is what opsecView reads; *node.Engine implements it.
type opsecSource interface {
	ObfsStatus() node.ObfsStatus
	G3Alerts() []node.G3Alert
	ExitCanaryResults() []node.CanaryResult
	ExitChainStatus() node.ChainStatus
	LostStatus() node.LostStatus
}

func opsecView(e *node.Engine) panel.OpsecView {
	v := opsecViewFrom(e)
	for _, q := range e.Quarantined() {
		v.Quarantine = append(v.Quarantine, panel.OpsecQuarantine{Peer: q.Peer, Reason: q.Reason, Since: q.Since, Until: q.Until})
	}
	return v
}

func opsecViewFrom(s opsecSource) panel.OpsecView {
	var v panel.OpsecView
	o := s.ObfsStatus()
	v.Obfs.Mode, v.Obfs.TLS, v.Obfs.Buckets, v.Obfs.Jitter, v.Obfs.Wrapped = o.Mode, o.TLS, o.Buckets, o.Jitter, o.Stats.Wrapped
	v.Quarantine = []panel.OpsecQuarantine{}
	v.Alerts = []panel.OpsecAlert{}
	for _, a := range s.G3Alerts() {
		v.Alerts = append(v.Alerts, panel.OpsecAlert{Kind: a.Kind, Peer: a.Peer, Text: a.Text, At: a.At})
	}
	v.Canary = []panel.OpsecCanary{}
	for _, c := range s.ExitCanaryResults() {
		v.Canary = append(v.Canary, panel.OpsecCanary{Address: c.Address, Status: c.Status, ViaExit: c.ViaExit, At: c.At})
	}
	c := s.ExitChainStatus()
	v.Chain.Entry, v.Chain.Final, v.Chain.Ready, v.Chain.Reason = c.Entry, c.Final, c.Ready && c.Wired, c.Reason
	if c.Ready && !c.Wired && c.Reason == "" {
		v.Chain.Reason = "Çift sıçrama planı geçerli ama bu sürümde trafik henüz giriş düğümünden geçirilmiyor."
	}
	l := s.LostStatus()
	v.Lost.Lost, v.Lost.Since = l.Lost, l.Since
	return v
}

// ReleaseQuarantine implements panel.OpsecApp.
func (r *Runtime) ReleaseQuarantine(peer string) (bool, error) {
	peer = strings.TrimSpace(peer)
	if peer == "" || len(peer) > 256 {
		return false, errors.New("geçersiz cihaz")
	}
	e := r.currentEngine()
	if e == nil {
		return false, errOpsecNoTunnel
	}
	return e.ReleaseQuarantine(peer), nil
}
