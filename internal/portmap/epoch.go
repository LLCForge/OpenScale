package portmap

import "time"

// epochState tracks a PCP or NAT-PMP server's "seconds since start of
// epoch" to notice when the gateway lost its mappings (rebooted), as RFC
// 6887 §8.5 and RFC 6886 §3.6 describe.
type epochState struct {
	valid  bool
	server uint32
	client time.Time
}

// observe records an epoch value seen at now and reports whether it shows
// the gateway lost its state since the previous value. The first value
// only sets the reference.
func (e *epochState) observe(server uint32, now time.Time) (reset bool) {
	defer func() {
		e.valid, e.server, e.client = true, server, now
	}()
	if !e.valid {
		return false
	}
	// Time going backwards by more than a second (packet reordering may
	// account for one second).
	if uint64(server)+1 < uint64(e.server) {
		return true
	}
	if server < e.server {
		return false
	}
	cdelta := int64(now.Sub(e.client) / time.Second)
	if cdelta < 0 {
		cdelta = 0
	}
	sdelta := int64(server - e.server)
	// Both clocks must advance alike, within 1/16 plus two seconds.
	if cdelta+2 < sdelta-sdelta/16 || sdelta+2 < cdelta-cdelta/16 {
		return true
	}
	return false
}

// forget drops the reference (a new gateway).
func (e *epochState) forget() { *e = epochState{} }
