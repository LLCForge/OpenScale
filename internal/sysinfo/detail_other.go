//go:build !windows && !linux && !darwin

package sysinfo

// Other systems (FreeBSD, OpenBSD) report only what newDetail knows.

func collectDetail(*Detail) {}

func collectLight(*Detail) {}
