//go:build !linux

package srvaudit

import "errors"

// Audit is Linux only: coordinators and exit node servers run Linux.
func Audit(Options) (Report, error) {
	return Report{}, errors.New("sunucu denetimi yalnızca Linux sunucularda çalışır")
}
