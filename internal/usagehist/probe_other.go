//go:build !windows && !unix

package usagehist

import "time"

func processCPU() (time.Duration, bool) { return 0, false }

func batteryState() Battery { return Battery{} }
