package service

import (
	"sync"

	"github.com/openscale/openscale/internal/panel"
)

// Settings that restart the connection (#799). Changing any tunnel option
// restarts the tunnel (DiagSetPrefs, tunnelEqualIgnoringLog) except the
// log level; MTU and forced relay restart it through SetAdvanced; the
// relay and TCP limits of a coordinator on this computer restart that
// coordinator, which cuts off every device using it; "connected" turns
// the tunnel off. The panel marks these settings and asks again before
// changing one from a session that may itself run through the tunnel.

// restartAlways are the keys outside the tunnel options that restart.
var restartAlways = map[string]bool{
	"connected": true, "mtu": true, "force-relay": true,
	"relay-rate": true, "relay-burst": true,
	"coordinator-tcp-listen": true, "coordinator-tcp-max-conns": true, "coordinator-tcp-max-conns-per-ip": true,
}

// restartNever are tunnel options applied without a restart.
var restartNever = map[string]bool{"log-level": true}

var restartKeys = sync.OnceValue(func() map[string]bool {
	out := map[string]bool{}
	for _, p := range prefSpecs {
		if restartNever[p.key] {
			continue
		}
		var probe tunnelOptions
		// Only whether the key is a tunnel option matters, not the value.
		if handled, _ := applyTunnelPref(&probe, p.key, p.def); handled || restartAlways[p.key] {
			out[p.key] = true
		}
	}
	return out
})

// restartsConnection reports whether changing key restarts the connection.
func restartsConnection(key string) bool { return restartKeys()[key] }

// PrefMeta implements panel.PrefMetaSource.
func (r *Runtime) PrefMeta() []panel.PrefMeta {
	out := []panel.PrefMeta{}
	for _, p := range prefSpecs {
		if restartsConnection(p.key) {
			out = append(out, panel.PrefMeta{Key: p.key, Description: p.desc, RestartsConnection: true})
		}
	}
	return out
}

var _ panel.PrefMetaSource = (*Runtime)(nil)
