//go:build !linux

package sdnotify

// Notify does nothing outside Linux: there is no systemd to tell.
func Notify(string) (bool, error) { return false, nil }
