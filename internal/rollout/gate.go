package rollout

import "time"

// Device side. The decision combines what the device trusts (its ring and
// the ring sizes from its own signed document, its own clock) with what the
// coordinator announces (untrusted: which ring is open, a halt, the soak
// times, which are clamped).

// Gate is one decision's input.
type Gate struct {
	// Ring is this device's ring (RingOf its own signed tags).
	Ring string
	// Canary and Early count the members of those rings in this device's
	// signed document.
	Canary, Early int
	// Ann is the coordinator's progress for the announced release; nil
	// when the coordinator sent none (an older coordinator).
	Ann *Announcement
	// FirstSeen is when this device first saw the announced digest.
	FirstSeen time.Time
	Now       time.Time
}

// Wait reasons of Decision.
const (
	// WaitNone: install now.
	WaitNone = ""
	// WaitHalted: the coordinator halted the release.
	WaitHalted = "halted"
	// WaitRing: the coordinator has not opened this device's ring.
	WaitRing = "ring"
	// WaitFloor: the local floor since first sight has not passed.
	WaitFloor = "floor"
)

// Decision says whether the device may install now.
type Decision struct {
	Wait string
	// NotBefore is the end of the local floor (zero when there is none).
	NotBefore time.Time
}

// Install reports whether the device may install now.
func (d Decision) Install() bool { return d.Wait == WaitNone }

// Floor returns the local minimum wait for ring since first sight: the
// soak times of the earlier rings that have members.
func Floor(ring string, canary, early int, canarySoak, earlySoak time.Duration) time.Duration {
	var f time.Duration
	if Index(ring) >= 1 && canary > 0 {
		f += canarySoak
	}
	if Index(ring) >= 2 && early > 0 {
		f += earlySoak
	}
	return f
}

// Decide applies the coordinator's progress and the local floor.
func Decide(g Gate) Decision {
	ring := g.Ring
	if Index(ring) < 0 {
		ring = RingMain
	}
	canarySoak, earlySoak := DefaultCanarySoak, DefaultEarlySoak
	if g.Ann != nil {
		canarySoak, earlySoak = ClampSoak(g.Ann.CanarySoak), ClampSoak(g.Ann.EarlySoak)
	}
	var d Decision
	if f := Floor(ring, g.Canary, g.Early, canarySoak, earlySoak); f > 0 && !g.FirstSeen.IsZero() {
		d.NotBefore = g.FirstSeen.Add(f)
	}
	switch {
	case g.Ann != nil && g.Ann.Halted:
		d.Wait = WaitHalted
	case g.Ann != nil && Index(g.Ann.Open) < Index(ring):
		d.Wait = WaitRing
	case !d.NotBefore.IsZero() && g.Now.Before(d.NotBefore):
		d.Wait = WaitFloor
	}
	return d
}
