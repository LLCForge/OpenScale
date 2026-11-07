//go:build !windows

package wintunembed

import "errors"

// ErrDriverNotLoaded means no Wintun driver is running now.
var ErrDriverNotLoaded = errors.New("Wintun sürücüsü yüklü değil")

// DriverVersion is Windows only.
func DriverVersion() (string, error) { return "", ErrUnsupported }

// DeleteDriver is Windows only.
func DeleteDriver() error { return ErrUnsupported }
