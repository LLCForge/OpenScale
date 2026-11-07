//go:build linux && (!cgo || nopipewire)

package rdesk

import "os"

// openPipeWire: this build has no PipeWire bridge (CGO_ENABLED=0 or the
// nopipewire tag), so Wayland sessions cannot be watched (ADR-0236).
func openPipeWire(*os.File, []uint32) (pipewireFrames, error) { return nil, ErrWaylandNeedsCgo }
