//go:build windows

package winapp

import "golang.org/x/sys/windows/svc/mgr"

// serviceStartType: the service starts at boot, before anyone signs in
// (ADR-0014, ADR-0194).
const serviceStartType = mgr.StartAutomatic
