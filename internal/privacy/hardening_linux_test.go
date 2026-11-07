//go:build linux

package privacy

import "testing"

func verifyHardened(t *testing.T) {
	t.Helper()
	d, err := dumpable()
	if err != nil || d != 0 {
		t.Fatalf("PR_GET_DUMPABLE = %d, %v; want 0", d, err)
	}
	cur, max, err := coreLimit()
	if err != nil || cur != 0 || max != 0 {
		t.Fatalf("RLIMIT_CORE = %d/%d, %v; want 0/0", cur, max, err)
	}
}
