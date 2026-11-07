//go:build !windows

package winapp

import "errors"

// verifyPanelWindowProcess: forwarding to an open window exists only on
// Windows.
func verifyPanelWindowProcess(uint32) error {
	return errors.New("pencere doğrulaması bu sistemde yok")
}
