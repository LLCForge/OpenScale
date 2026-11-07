// Package peercred finds the process at the other end of a loopback TCP
// connection and checks it against a policy (ADR-0050, F-123, #160). The
// local management API of the service and of "openscale up" accepts its
// token only from an authorized process: an elevated administrator or
// SYSTEM on Windows; root, the tunnel's own user or the openscale group
// on Linux. Elsewhere the token alone decides, as before.
package peercred

import (
	"errors"
	"fmt"
	"net/netip"
)

// Identity is what the system says about the calling process.
type Identity struct {
	// PID is the process (Windows; 0 on Linux, where the socket owner is
	// known but not the process).
	PID int
	// UID is the socket owner's user id (Linux; -1 on Windows).
	UID int
	// Admin: an elevated administrator token or SYSTEM (Windows), root
	// (Linux).
	Admin bool
	// Self: the same user as the server process.
	Self bool
	// Groups are the user's group ids (Linux).
	Groups []string
}

// Policy says who may use the local API besides the token.
type Policy struct {
	// Admins allows elevated administrators, SYSTEM and root.
	Admins bool
	// SameUser allows processes of the user that runs the server.
	SameUser bool
	// Group allows members of this Unix group (operators, F-097).
	Group string
}

// Errors.
var (
	// ErrUnsupported: this system cannot tell who is calling; the caller
	// falls back to the token alone.
	ErrUnsupported = errors.New("peer lookup is not supported on this system")
	// ErrNotFound: the connection is not in the system's table.
	ErrNotFound = errors.New("connection not found in the system table")
	// ErrDenied: the caller is not allowed by the policy.
	ErrDenied = errors.New("caller is not allowed to use the local API")
)

// parseLoopback parses a host:port that must be a loopback address.
func parseLoopback(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ap = netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
	if !ap.Addr().IsLoopback() {
		return netip.AddrPort{}, fmt.Errorf("%s is not a loopback address", s)
	}
	return ap, nil
}

// Check finds the process behind remote (the client's address as the
// server sees it) connected to local (the server's address) and applies
// p. It returns nil when the caller is allowed or when this system cannot
// tell (ErrUnsupported is never returned).
func (p Policy) Check(remote, local string) error {
	client, err := parseLoopback(remote)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}
	server, err := parseLoopback(local)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}
	id, err := Lookup(client, server)
	if errors.Is(err, ErrUnsupported) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}
	if p.allows(id) {
		return nil
	}
	return fmt.Errorf("%w (pid %d, uid %d)", ErrDenied, id.PID, id.UID)
}

func (p Policy) allows(id Identity) bool {
	switch {
	case p.Admins && id.Admin:
		return true
	case p.SameUser && id.Self:
		return true
	case p.Group != "" && groupMember(p.Group, id.Groups):
		return true
	}
	return false
}
