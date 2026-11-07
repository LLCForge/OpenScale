package member

import "github.com/openscale/openscale/internal/trust"

// pinStoredG1 pins, from the stored envelope, the newest root-signed base
// a delegated administrator's document was built on (ADR-0172). Without it
// a reloaded member would accept an administrator document built on an
// older root version. Called with s.doc and s.envelope set.
func (s *Store) pinStoredG1() {
	if len(s.envelope) == 0 || s.doc == nil {
		return
	}
	env, err := trust.UnmarshalEnvelope(s.envelope)
	if err != nil {
		return
	}
	s.state.PinStored(env, s.doc)
}
