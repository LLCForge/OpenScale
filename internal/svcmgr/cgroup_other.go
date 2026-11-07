//go:build !linux

package svcmgr

// CurrentCgroupLimits is Linux only.
func CurrentCgroupLimits() (CgroupLimits, bool) { return CgroupLimits{}, false }
