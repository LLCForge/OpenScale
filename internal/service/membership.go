package service

import (
	"context"
	"errors"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

// Membership extensions of the desktop service (ADR-0028); they implement
// panel.MembershipApp through the running tunnel.

var errMembershipNoTunnel = errors.New("tunnel is not running")

func (r *Runtime) runningEngine() (*node.Engine, error) {
	r.mu.Lock()
	e := r.engine
	r.mu.Unlock()
	if e == nil {
		return nil, errMembershipNoTunnel
	}
	return e, nil
}

// Leaves implements panel.MembershipApp.
func (r *Runtime) Leaves(ctx context.Context) ([]trust.SignedLeave, error) {
	e, err := r.runningEngine()
	if err != nil {
		return nil, err
	}
	return e.Leaves(ctx)
}

// CloneAlerts implements panel.MembershipApp.
func (r *Runtime) CloneAlerts(ctx context.Context) ([]control.CloneAlert, error) {
	e, err := r.runningEngine()
	if err != nil {
		return nil, err
	}
	return e.CloneAlerts(ctx)
}

// RejectPending implements panel.MembershipApp.
func (r *Runtime) RejectPending(ctx context.Context, inviteID, deviceID string) error {
	e, err := r.runningEngine()
	if err != nil {
		return err
	}
	return e.RejectPending(ctx, inviteID, deviceID)
}

// LeaveNetwork implements panel.MembershipApp (F-106): the signed leave
// request goes to the coordinator, then this computer forgets its
// membership and key. The owner's computer cannot leave its own network.
func (r *Runtime) LeaveNetwork(ctx context.Context) (string, error) {
	r.mu.Lock()
	admin := r.network != nil
	r.mu.Unlock()
	if admin {
		return "", ErrResetAdmin
	}
	e, err := r.runningEngine()
	if err != nil {
		return "", err
	}
	line, _, err := e.RequestLeave(ctx)
	if err != nil {
		return "", err
	}
	if err := r.ResetDevice(); err != nil {
		return line, err
	}
	return line, nil
}

// The panel finds these methods through an interface check at run time;
// this keeps them from silently drifting apart.
var _ panel.MembershipApp = (*Runtime)(nil)
