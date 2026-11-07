package control

// Sealed endpoint candidates (ADR-0230, #38): a device's direct-connection
// candidates travel to one peer encrypted with a key only the two devices
// can derive from their WireGuard static keys. The coordinator stores and
// forwards an opaque blob; it never sees the addresses inside.
//
// Compatibility. Decode refuses unknown fields, so the new fields (Sealed,
// PeerSealed) appear only in TypeSealed and TypePeerSealed messages:
//   - a device sends them only after the coordinator listed FeatureSealed
//     in its caps reply; an old coordinator never sees them;
//   - a device announces that it understands them by listing FeatureSealed
//     in the Features of its own TypeCaps request (a field every
//     coordinator already decodes and ignores); the coordinator pushes a
//     TypeSealed message only to devices that did, so an old device never
//     receives one.
const (
	// TypeSealed hands the coordinator a blob for one peer: Target is the
	// peer's device id, Sealed the blob. The reply has Complete set. The
	// coordinator pushes the same message to the peer (Target then names
	// the sender) when the peer is subscribed and announced the feature.
	TypeSealed = "seal"
	// TypePeerSealed pages through what the coordinator holds for this
	// device: one PeerSealed entry per visible peer that has a blob for it
	// or whose capability is known. Request: Offset. Reply: PeerSealed,
	// Total, Next, like TypePeerCandidates.
	TypePeerSealed = "pseal"
	// FeatureSealed is listed by coordinators that store and forward
	// sealed candidates, and by devices (in their caps request) that
	// understand pushed TypeSealed messages.
	FeatureSealed = "seal"
)

// MaxSealed bounds one sealed blob. A blob for the maximum number of
// candidates (node/sealedcands.go) is well below it.
const MaxSealed = 320

// PeerSealed is one entry of a TypePeerSealed reply.
type PeerSealed struct {
	ID string `json:"id"`
	// Sealed is the newest blob this peer left for the requesting device.
	Sealed []byte `json:"seal,omitempty"`
	// Cap: the peer announced FeatureSealed recently. Old: the peer is
	// online (subscribed or handshaking) without announcing it, so it can
	// only read plain candidates. Neither: nothing is known (offline).
	Cap bool `json:"cap,omitempty"`
	Old bool `json:"old,omitempty"`
}

func validSealedFields(m Message) bool {
	if len(m.Sealed) > MaxSealed || len(m.PeerSealed) > PeersPerPage {
		return false
	}
	for _, p := range m.PeerSealed {
		if p.ID == "" || len(p.ID) > maxNameLen || len(p.Sealed) > MaxSealed || (p.Cap && p.Old) {
			return false
		}
	}
	return true
}
