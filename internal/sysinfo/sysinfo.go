// Package sysinfo describes the local computer for the owner's panel: OS,
// processor, memory, disk and uptime. It is sent only to admin devices
// through the tunnel (ADR-0015) and holds no user data.
package sysinfo

import (
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openscale/openscale/internal/posture"
	"github.com/openscale/openscale/internal/version"
)

// MaxEncoded bounds the encoded report so it fits in one control datagram.
const MaxEncoded = 640

const maxText = 64

// Info is a snapshot of the computer. JSON keys are short to fit one
// datagram.
type Info struct {
	Version   string `json:"v"`
	OS        string `json:"os"`
	OSName    string `json:"on"`
	Arch      string `json:"a"`
	CPU       string `json:"c"`
	Cores     int    `json:"n"`
	MemTotal  uint64 `json:"mt"`
	MemFree   uint64 `json:"mf"`
	DiskTotal uint64 `json:"dt"`
	DiskFree  uint64 `json:"df"`
	Uptime    int64  `json:"u"`
	// PublicIP is the address the coordinator sees this computer at.
	PublicIP string `json:"ip,omitempty"`
	// Synced is true while this computer reaches its coordinator.
	Synced bool  `json:"s"`
	Time   int64 `json:"t"`
	// SSHHostKey is the SHA256 fingerprint of the embedded SSH server's
	// host key (ADR-0030), so the owner can check it before the first
	// connection. Empty when the server never ran here.
	SSHHostKey string `json:"hk,omitempty"`
	// WakeMAC is the MAC address of the LAN card that can wake this
	// computer (ADR-0031). It reaches only admin devices and is never
	// stored by the coordinator.
	WakeMAC string `json:"wm,omitempty"`
	// Environment detection (F-172, #322; env.go): Virt is the container
	// or virtual machine kind ("" on bare metal), Model the vendor and
	// product name, Pkg how OpenScale was installed. Dropped first when the
	// report would not fit one datagram.
	Virt  string `json:"vm,omitempty"`
	Model string `json:"md,omitempty"`
	Pkg   string `json:"pk,omitempty"`
	// Listen lists the TCP ports listening on a non-loopback address
	// (F-220, listen.go). Shortened, then dropped, when the report would
	// not fit one datagram.
	Listen []uint16 `json:"lp,omitempty"`
	// Posture is the device's own security posture statement (ADR-0109,
	// #105) in posture.Report.Encode form; never proof of security.
	// Dropped with the environment when the report would not fit.
	Posture string `json:"ps,omitempty"`
	// PostureExt is the extended posture statement (ADR-0207, #604,
	// #608) in posture.Extended.Encode form: Secure Boot, TPM, screen
	// lock. It is a separate field because older devices reject unknown
	// keys inside Posture; they ignore this one. Dropped with Posture.
	PostureExt string `json:"pe,omitempty"`
	// DetailVer and DetailID announce the detailed inventory (ADR-0143):
	// its format version and a content identifier. An admin device that
	// reads this version fetches the inventory in chunks only when the
	// identifier changed. Old admins ignore both fields.
	DetailVer int    `json:"xv,omitempty"`
	DetailID  string `json:"xd,omitempty"`
	// UpstreamLabel, UpstreamMode and UpstreamHandshake describe the
	// upstream exit of an exit node (ADR-0142, upstream.go): the provider
	// profile's display label, the routing mode and the last handshake
	// (Unix seconds). Dropped before the inventory announcement when the
	// report would not fit one datagram.
	UpstreamLabel     string `json:"xu,omitempty"`
	UpstreamMode      string `json:"xm,omitempty"`
	UpstreamHandshake int64  `json:"xh,omitempty"`
	// UpstreamKind is what members exit through: "tor", "warp",
	// "mullvad" or "wireguard" (upstream.Status.Kind). Dropped with the
	// other upstream fields. "xd" is the inventory identifier above.
	UpstreamKind string `json:"xk,omitempty"`
	// Detail is the detailed inventory itself: attached locally by
	// Collect, or by the admin device after fetching it. Encode never
	// sends it and Decode never accepts it; it travels separately.
	Detail *Detail `json:"x,omitempty"`
}

// Collect gathers the local information. Fields that cannot be read stay
// zero; it never fails.
func Collect(now time.Time) Info {
	in := Info{
		Version: version.Version,
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		Cores:   runtime.NumCPU(),
		Time:    now.Unix(),
	}
	collect(&in)
	collectEnv(&in)
	in.Listen = ListeningPorts()
	in.Posture = posture.Cached().Encode()
	in.PostureExt = posture.CachedExtended().Encode()
	if d, id := cachedDetail(now); d != nil {
		in.Detail, in.DetailVer, in.DetailID = d, DetailVersion, id
	}
	applyExtra(&in)
	applyUpstream(&in)
	return in
}

// Encode returns the compact JSON form, refusing anything over MaxEncoded.
func (in Info) Encode() ([]byte, error) {
	in.Detail = nil
	in.sanitize()
	data, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxEncoded && len(in.Listen) > maxListenCompact {
		// Listening ports are optional too (F-220): keep the lowest.
		in.Listen = in.Listen[:maxListenCompact]
		if data, err = json.Marshal(in); err != nil {
			return nil, err
		}
	}
	if len(data) > MaxEncoded && in.PostureExt != "" {
		// The extended posture goes first (ADR-0207).
		in.PostureExt = ""
		if data, err = json.Marshal(in); err != nil {
			return nil, err
		}
	}
	if len(data) > MaxEncoded && (in.Virt != "" || in.Model != "" || in.Pkg != "" || in.Posture != "") {
		// The environment and posture are optional; the rest of the
		// report is not.
		in.Virt, in.Model, in.Pkg, in.Posture = "", "", "", ""
		if data, err = json.Marshal(in); err != nil {
			return nil, err
		}
	}
	if len(data) > MaxEncoded && len(in.Listen) > 0 {
		in.Listen = nil
		if data, err = json.Marshal(in); err != nil {
			return nil, err
		}
	}
	if len(data) > MaxEncoded && in.UpstreamMode != "" {
		in.UpstreamLabel, in.UpstreamMode, in.UpstreamHandshake, in.UpstreamKind = "", "", 0, ""
		if data, err = json.Marshal(in); err != nil {
			return nil, err
		}
	}
	if len(data) > MaxEncoded && in.DetailID != "" {
		in.DetailVer, in.DetailID = 0, ""
		if data, err = json.Marshal(in); err != nil {
			return nil, err
		}
	}
	if len(data) > MaxEncoded {
		return nil, errors.New("system report too large")
	}
	return data, nil
}

// Decode parses a report received from another computer. The values are
// only displayed; text fields are cleaned again.
func Decode(data []byte) (Info, error) {
	var in Info
	if len(data) > MaxEncoded {
		return in, errors.New("system report too large")
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return in, err
	}
	in.Detail = nil // fetched separately and checked by DecodeDetail
	in.sanitize()
	return in, nil
}

func (in *Info) sanitize() {
	in.sanitizeExtra()
	in.sanitizeUpstream()
	if in.DetailVer < 0 || in.DetailVer > 1000 || !ValidDetailID(in.DetailID) {
		in.DetailVer, in.DetailID = 0, ""
	}
	if in.Detail != nil {
		in.Detail.sanitize()
	}
	if _, err := posture.Decode(in.Posture); err != nil {
		in.Posture = ""
	}
	if _, err := posture.DecodeExtended(in.PostureExt); err != nil {
		in.PostureExt = ""
	}
	in.Listen = normalizePorts(in.Listen)
	for _, p := range []*string{&in.Version, &in.OS, &in.OSName, &in.Arch, &in.CPU, &in.PublicIP, &in.Virt, &in.Model, &in.Pkg} {
		*p = cleanText(*p)
	}
	if in.Cores < 0 || in.Cores > 4096 {
		in.Cores = 0
	}
	if in.Uptime < 0 {
		in.Uptime = 0
	}
}

// cleanText removes control characters, collapses spaces and truncates.
func cleanText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxText {
		s = s[:maxText]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}
