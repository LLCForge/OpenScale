//go:build !linux

package cli

import "github.com/openscale/openscale/internal/osnet"

// cmdSplitTunnelRun is Linux only (ADR-0134).
func cmdSplitTunnelRun(*Env, []string) error { return osnet.ErrSplitTunnelUnsupported }
