//go:build openscale_noservices

package service

import "context"

// Built with the openscale_noservices tag (#300, ADR-0139): the tunnel
// services (publishing, internal CA issuer, identity provider) are not in
// the binary at all.

type p18State struct{}

func (a *Apps) runP18(ctx context.Context) {}
