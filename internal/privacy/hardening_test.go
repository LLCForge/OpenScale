package privacy

import "testing"

func TestTracebackWarning(t *testing.T) {
	for _, v := range []string{"crash", "CRASH", " wer "} {
		if tracebackWarning(v) == "" {
			t.Errorf("no warning for GOTRACEBACK=%q", v)
		}
	}
	for _, v := range []string{"", "single", "all", "none", "system"} {
		if w := tracebackWarning(v); w != "" {
			t.Errorf("unexpected warning for GOTRACEBACK=%q: %s", v, w)
		}
	}
}

// TestHardenProcess changes only the test process: the dump limits it
// sets die with it.
func TestHardenProcess(t *testing.T) {
	st := HardenProcess()
	if len(st.Measures) == 0 && len(st.Warnings) > 0 && !st.CoreDumpsDisabled {
		verifyHardened(t) // skips where the platform has no dumps
	}
	if !st.CoreDumpsDisabled {
		t.Fatalf("crash dumps still enabled: %+v", st)
	}
	if len(st.Measures) == 0 {
		t.Fatal("no measure reported")
	}
	verifyHardened(t)
	// A second call must be harmless.
	if again := HardenProcess(); !again.CoreDumpsDisabled {
		t.Fatalf("second call failed: %+v", again)
	}
}
