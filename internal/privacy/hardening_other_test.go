//go:build !unix && !windows

package privacy

import "testing"

func verifyHardened(t *testing.T) { t.Skip("no crash dumps on this platform") }
