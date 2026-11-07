//go:build !linux && !windows

package osnet

import "runtime"

// CurrentOSBuild only knows the family here; without a version a change
// is never reported.
func CurrentOSBuild() OSBuild { return OSBuild{Family: runtime.GOOS} }
