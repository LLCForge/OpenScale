package updater

import (
	"context"

	"github.com/openscale/openscale/internal/svcmgr"
)

// Platform is where the installed program and its service live.
type Platform struct {
	// Exe is the installed program.
	Exe string
	// DataDir is the service's data directory (Windows) or the parent of
	// the state directories (Linux).
	DataDir string
	// StateDir holds the journal, the marker and the installed manifest.
	StateDir string
	// Services are the units the program runs.
	Services []Service
	// ReadMarker is set where the service reports its version on start.
	ReadMarker func() (Marker, error)
}

// managedService adapts svcmgr to Service.
type managedService struct{ role svcmgr.Role }

func (s managedService) Name() string { return "openscale-" + string(s.role) }

func (s managedService) Stop(ctx context.Context) error  { return svcmgr.Stop(ctx, s.role) }
func (s managedService) Start(ctx context.Context) error { return svcmgr.Start(ctx, s.role) }

func (s managedService) Status(ctx context.Context) (ServiceState, error) {
	st, err := svcmgr.Get(ctx, s.role)
	if err != nil {
		return ServiceState{}, err
	}
	return ServiceState{Installed: st.Installed, Running: st.Running, PID: st.PID}, nil
}
