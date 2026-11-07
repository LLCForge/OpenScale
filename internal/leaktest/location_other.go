//go:build !windows

package leaktest

func platformTimeZone() string { return "" }

func platformRegion() string { return "" }
