//go:build unix && !linux

package privacy

import (
	"testing"

	"golang.org/x/sys/unix"
)

func verifyHardened(t *testing.T) {
	t.Helper()
	var r unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &r); err != nil || r.Cur != 0 {
		t.Fatalf("RLIMIT_CORE = %d, %v; want 0", r.Cur, err)
	}
}
