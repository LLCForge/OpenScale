//go:build !windows

package winapp

// LimitServiceResources does nothing here: Linux uses the systemd unit.
func LimitServiceResources(l ResourceLimits) ResourceLimits {
	l.Applied = false
	recordLimits(l)
	return l
}
