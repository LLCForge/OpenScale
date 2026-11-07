package cli

import (
	"errors"
	"strings"
	"testing"
)

// The real WFP calls are never made in tests; the operations are faked.
func withKillSwitchOps(t *testing.T, ops killSwitchOps) {
	t.Helper()
	saved := killSwitch
	killSwitch = ops
	t.Cleanup(func() { killSwitch = saved })
}

func TestKillSwitchOff(t *testing.T) {
	removed := 0
	ops := killSwitchOps{
		supported: func() bool { return true },
		elevated:  func() bool { return false },
		remove:    func() error { removed++; return nil },
		installed: func() (bool, error) { return true, nil },
	}
	withKillSwitchOps(t, ops)
	h := newHarness(t)
	h.run(exitError, "killswitch", "off")
	if removed != 0 || !strings.Contains(h.stderr.String(), "yönetici") {
		t.Fatalf("must ask for administrator rights first: removed=%d stderr=%q", removed, h.stderr.String())
	}

	ops.elevated = func() bool { return true }
	withKillSwitchOps(t, ops)
	out := h.run(exitOK, "killswitch", "off")
	if removed != 1 || !strings.Contains(out, "kaldırıldı") {
		t.Fatalf("removed=%d out=%q", removed, out)
	}

	ops.remove = func() error { return errors.New("BFE yanıt vermedi") }
	withKillSwitchOps(t, ops)
	h.run(exitError, "killswitch", "off")
	if !strings.Contains(h.stderr.String(), "BFE yanıt vermedi") {
		t.Fatalf("error not shown: %q", h.stderr.String())
	}
	h.run(exitUsage, "killswitch", "off", "fazla")
}

func TestKillSwitchStatus(t *testing.T) {
	on := true
	ops := killSwitchOps{
		supported: func() bool { return true },
		elevated:  func() bool { return true },
		remove:    func() error { return nil },
		installed: func() (bool, error) { return on, nil },
	}
	withKillSwitchOps(t, ops)
	h := newHarness(t)
	if out := h.run(exitOK, "killswitch", "status"); !strings.Contains(out, "Kill switch kurulu:") {
		t.Fatalf("status on: %q", out)
	}
	on = false
	if out := h.run(exitOK, "killswitch", "status"); !strings.Contains(out, "kurulu değil") {
		t.Fatalf("status off: %q", out)
	}

	ops.supported = func() bool { return false }
	ops.remove = func() error { t.Fatal("nothing to remove on this system"); return nil }
	withKillSwitchOps(t, ops)
	if out := h.run(exitOK, "killswitch", "status"); !strings.Contains(out, "yok") {
		t.Fatalf("unsupported status: %q", out)
	}
	if out := h.run(exitOK, "killswitch", "off"); !strings.Contains(out, "kaldırılacak bir şey yok") {
		t.Fatalf("unsupported off: %q", out)
	}
}
