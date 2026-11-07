//go:build windows

package privacy

import "testing"

func verifyHardened(t *testing.T) {
	t.Helper()
	if currentErrorMode()&semNoGPFaultErrorBox == 0 {
		t.Fatalf("error mode %#x lacks SEM_NOGPFAULTERRORBOX", currentErrorMode())
	}
	flags, ok := werFlags()
	if !ok {
		t.Skip("WerGetFlags unavailable")
	}
	if flags&werNoHeap == 0 {
		t.Fatalf("WER flags %#x lack NOHEAP", flags)
	}
}
