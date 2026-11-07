//go:build !windows && !linux

package diskguard

func freeBytes(string) (uint64, error) { return 0, ErrUnsupported }

func isDiskFullOS(error) bool { return false }
