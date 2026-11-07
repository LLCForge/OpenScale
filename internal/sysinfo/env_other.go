//go:build !windows && !linux

package sysinfo

func collectEnv(*Info) {}
