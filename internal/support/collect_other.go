//go:build !windows && !linux && !darwin

package support

import "context"

// Other systems have no collector yet; every request answers
// ErrUnsupported.

type systemCollector struct{}

func (systemCollector) Processes(context.Context) ([]Process, error)   { return nil, ErrUnsupported }
func (systemCollector) Services(context.Context) ([]Service, error)    { return nil, ErrUnsupported }
func (systemCollector) Events(context.Context) ([]Event, error)        { return nil, ErrUnsupported }
func (systemCollector) Disks(context.Context) ([]Disk, error)          { return nil, ErrUnsupported }
func (systemCollector) Startup(context.Context) ([]StartupItem, error) { return nil, ErrUnsupported }
func (systemCollector) Kill(context.Context, int, string) error        { return ErrUnsupported }
