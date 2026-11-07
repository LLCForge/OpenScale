//go:build !linux && !windows

package posture

func collect() Report { return Report{} }

func isWireless(name string) bool { return wirelessByName(name) }

// DiskEncryption is not checked on this system.
func DiskEncryption() State { return Unknown }

// VolumeEncryption is not checked on this system.
func VolumeEncryption() map[string]State { return nil }

// DeviceEncryption is not checked on this system.
func DeviceEncryption(string) State { return Unknown }
