//go:build !windows && !linux

package updater

import "errors"

// DefaultPlatform is not available: no service manager support here.
func DefaultPlatform() (Platform, error) {
	return Platform{}, errors.New("bu işletim sisteminde güncelleme uygulama desteklenmiyor; programı elle değiştirin")
}

// DefaultRootKeyFile has no default here.
func DefaultRootKeyFile() string { return "" }

// RequirePrivileges always fails here.
func RequirePrivileges() error { _, err := DefaultPlatform(); return err }
