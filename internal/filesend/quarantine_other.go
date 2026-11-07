//go:build !windows && !darwin && !linux

package filesend

import "time"

func markQuarantine(string, string, time.Time) error { return ErrQuarantineUnsupported }

func isQuarantined(string) bool { return false }
