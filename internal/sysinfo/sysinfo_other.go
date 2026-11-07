//go:build !windows && !linux && !darwin

package sysinfo

func collect(*Info) {}
