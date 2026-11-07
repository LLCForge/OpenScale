package node

import (
	"context"
	"errors"

	"github.com/openscale/openscale/internal/control"
)

// ReleaseCall sends a release mirror request (ADR-0225) to the coordinator
// inside the tunnel. Only TypeRelease and TypeReleaseFile are allowed: the
// automatic updater (internal/autoupdate) gets no other access to the
// control channel.
func (e *Engine) ReleaseCall(ctx context.Context, req control.Message) (control.Message, error) {
	if req.T != control.TypeRelease && req.T != control.TypeReleaseFile {
		return control.Message{}, errors.New("not a release request")
	}
	resp, err := e.client.call(ctx, req)
	if err != nil {
		return resp, err
	}
	if resp.T != req.T {
		return control.Message{}, errors.New("coordinator sent an unexpected reply")
	}
	return resp, nil
}
