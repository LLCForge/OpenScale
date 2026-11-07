//go:build !linux && !windows

package osnet

import "errors"

// SubnetRouter is not implemented on this system yet: routes of other
// devices' subnets are not added and this device cannot be a router.
type SubnetRouter struct{}

// NewSubnetRouter returns the system's subnet router.
func NewSubnetRouter() *SubnetRouter { return &SubnetRouter{} }

// RouterSupported reports whether this system can be a subnet router.
func RouterSupported() bool { return false }

// RouterStatus is a short status line for diagnostics.
func (r *SubnetRouter) RouterStatus() string { return "desteklenmiyor" }

// Apply fails for anything but the empty configuration.
func (r *SubnetRouter) Apply(cfg RouteConfig) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	if cfg.Empty() {
		return nil
	}
	if len(cfg.Own) > 0 {
		return ErrRouterUnsupported
	}
	return errors.New("alt ağ rotaları bu işletim sisteminde henüz eklenemiyor")
}

// Close is a no-op.
func (r *SubnetRouter) Close() error { return nil }
