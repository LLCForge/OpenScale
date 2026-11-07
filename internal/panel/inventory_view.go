package panel

import (
	"strings"
	"time"

	"github.com/openscale/openscale/internal/sysinfo"
)

// UpstreamView is an exit node's upstream exit (ADR-0142) as the panel
// shows it: the provider profile's label, the routing mode ("tunnel",
// "blocked", "direct" or "off") and the last handshake. Display data from
// the exit node's own report; nil when it uses no upstream exit.
type UpstreamView struct {
	Label         string     `json:"label"`
	Mode          string     `json:"mode"`
	LastHandshake *time.Time `json:"lastHandshake,omitempty"`
	// Kind is "tor", "warp", "mullvad" or "wireguard"; "" when the exit
	// node's report predates the kind field ("xk").
	Kind string `json:"kind,omitempty"`
}

// UpstreamOf reads the upstream exit from a system report.
func UpstreamOf(in sysinfo.Info) *UpstreamView {
	if in.UpstreamMode == "" {
		return nil
	}
	v := &UpstreamView{Label: in.UpstreamLabel, Mode: in.UpstreamMode, Kind: in.UpstreamKind}
	if in.UpstreamHandshake > 0 {
		t := time.Unix(in.UpstreamHandshake, 0).UTC()
		v.LastHandshake = &t
	}
	return v
}

// osLabel is the operating system as the device list shows it, from the
// detailed inventory (ADR-0143): "Windows 11 Pro 26H2 (26300.9818)",
// "Debian GNU/Linux 13 (trixie) · 6.12.113", "macOS 15.1 (24B83)". ""
// without an inventory; the panel then shows the base report's name.
func osLabel(goos string, d *sysinfo.Detail) string {
	if d == nil || d.OS.Name == "" {
		return ""
	}
	o := d.OS
	label := o.Name
	if o.Version != "" && !strings.Contains(label, o.Version) {
		label += " " + o.Version
	}
	switch goos {
	case "linux", "android", "freebsd", "openbsd", "netbsd":
		if k := shortKernel(o.Kernel); k != "" {
			label += " · " + k
		}
	default:
		if o.Build != "" && !strings.Contains(label, o.Build) {
			label += " (" + o.Build + ")"
		}
	}
	return label
}

// shortKernel keeps the version numbers of a kernel release
// ("6.12.113+deb13-amd64" gives "6.12.113").
func shortKernel(k string) string {
	if i := strings.IndexAny(k, "+-_ "); i > 0 {
		return k[:i]
	}
	return k
}

// panelDetail is the copy of an inventory the panel API returns. The MAC
// vendor prefix stays on the admin device: the panel never shows MAC
// addresses (ADR-0008), not even their first half.
func panelDetail(d *sysinfo.Detail) *sysinfo.Detail {
	if d == nil {
		return nil
	}
	out := *d
	if len(d.NICs) > 0 {
		out.NICs = make([]sysinfo.NIC, len(d.NICs))
		for i, n := range d.NICs {
			n.OUI, n.RandomMAC = "", false
			out.NICs[i] = n
		}
	}
	return &out
}
