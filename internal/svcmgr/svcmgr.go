// Package svcmgr installs and controls the OpenScale service the same way
// on Windows and Linux (F-148, #307): "openscale service install, start,
// stop, restart, status, uninstall".
//
// On Windows there is one service (ADR-0014) that runs the tunnel, the
// panel and, when its state lives on this computer, the coordinator. On
// Linux there are two systemd units, openscale-device and
// openscale-coordinator (ADR-0018). Installation parameters are saved in
// /etc/openscale/<role>.json, which "up" and "coordinator run" read with
// --config, and a drop-in points the unit at that file; so a later
// "service install" with other parameters, or a package upgrade, keeps
// them.
package svcmgr

import (
	"errors"
	"fmt"
	"strings"
)

// Role is which Linux unit a command acts on.
type Role string

const (
	RoleDevice      Role = "device"
	RoleCoordinator Role = "coordinator"
)

// ParseRole accepts device (default) and coordinator.
func ParseRole(s string) (Role, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "device", "cihaz":
		return RoleDevice, nil
	case "coordinator", "koordinatör", "koordinator":
		return RoleCoordinator, nil
	}
	return "", fmt.Errorf("rol %q geçersiz; device veya coordinator yazın", s)
}

// Unit is the systemd unit of a role.
func (r Role) Unit() string { return "openscale-" + string(r) + ".service" }

// Options are the parameters of "service install".
type Options struct {
	Role Role
	// StateDir, ListenPort and Interface are saved as the unit's
	// parameters; zero values use the defaults below.
	StateDir   string
	ListenPort int
	Interface  string
	// TCPListen is the coordinator's TCP transport address (ADR-0032).
	TCPListen string
	// NoStart installs and enables nothing that runs; the owner starts it.
	NoStart bool
}

// Defaults of a Linux installation; the same as deploy/linux.
const (
	DefaultDeviceStateDir      = "/var/lib/openscale/device"
	DefaultCoordinatorStateDir = "/var/lib/openscale/coordinator"
	DefaultDevicePort          = 41821
	DefaultCoordinatorPort     = 41820
	DefaultInterface           = "OpenScale"
)

// Result tells the CLI what Install did.
type Result struct {
	// Binary is the program the service runs.
	Binary string
	// Started is true when the service was started.
	Started bool
	// Notes are things the owner should know (Turkish, one line each).
	Notes []string
}

// Status is the state of a service.
type Status struct {
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
	Enabled   bool   `json:"enabled"`
	State     string `json:"state"`
	Binary    string `json:"binary,omitempty"`
	// Detail is the service's own status line (sd_notify STATUS on Linux).
	Detail string `json:"detail,omitempty"`
	PID    int    `json:"pid,omitempty"`
}

// Errors.
var (
	ErrUnsupported = errors.New("servis yönetimi bu işletim sisteminde desteklenmiyor; Windows veya systemd kullanan Linux gerekir")
	ErrNeedsRoot   = errors.New("bu işlem root yetkisi ister")
	ErrNeedsAdmin  = errors.New("bu işlem yönetici yetkisi ister (Yönetici: PowerShell)")
)

// validInterface mirrors the interface name rule of the tunnel commands.
func validInterface(name string) bool {
	if name == "" || len(name) > 15 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return name != "." && name != ".."
}

// validStateDir accepts absolute, clean paths without characters a unit
// file or a shell would treat specially.
func validStateDir(dir string) bool {
	if len(dir) < 2 || len(dir) > 255 || dir[0] != '/' || strings.Contains(dir, "/../") || strings.HasSuffix(dir, "/..") {
		return false
	}
	return !strings.ContainsAny(dir, " \t\r\n\"'`$;&|\\%*?")
}

// normalize fills defaults and checks the options.
func (o Options) normalize() (Options, error) {
	if o.Role == "" {
		o.Role = RoleDevice
	}
	switch o.Role {
	case RoleDevice:
		if o.StateDir == "" {
			o.StateDir = DefaultDeviceStateDir
		}
		if o.ListenPort == 0 {
			o.ListenPort = DefaultDevicePort
		}
		if o.Interface == "" {
			o.Interface = DefaultInterface
		}
		if o.TCPListen != "" {
			return o, errors.New("--tcp-listen yalnızca koordinatör için")
		}
	case RoleCoordinator:
		if o.StateDir == "" {
			o.StateDir = DefaultCoordinatorStateDir
		}
		if o.ListenPort == 0 {
			o.ListenPort = DefaultCoordinatorPort
		}
		if o.Interface != "" {
			return o, errors.New("--interface yalnızca cihaz için")
		}
	default:
		return o, fmt.Errorf("rol %q geçersiz", o.Role)
	}
	if !validStateDir(o.StateDir) {
		return o, fmt.Errorf("durum klasörü %q mutlak ve özel karakter içermeyen bir yol olmalı", o.StateDir)
	}
	if o.ListenPort < 1 || o.ListenPort > 65535 {
		return o, errors.New("dinleme portu 1 ile 65535 arasında olmalı")
	}
	if o.Role == RoleDevice && !validInterface(o.Interface) {
		return o, fmt.Errorf("arayüz adı %q geçersiz (en fazla 15 karakter: harf, rakam, - _ .)", o.Interface)
	}
	return o, nil
}
