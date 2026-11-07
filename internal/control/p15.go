package control

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"time"
)

// Coordinator and relay scaling (ADR-0111): device-signed relay sessions
// (#151) and the device-to-device document exchange (#25) with the
// coordinator integrity comparison (#154).

// Relay sessions (#151). A device that sees FeatureRelaySession in a caps
// reply opens a session before it relays: Data carries the RelaySession
// payload and Sig its Ed25519ctx signature by the device's signing key from
// the document. From then on the coordinator relays this device's packets
// only while a session is valid.
const (
	TypeRelaySession    = "rsess"
	FeatureRelaySession = "rsess"
	// RelaySessionContext is the Ed25519ctx context of session signatures.
	RelaySessionContext = "openscale/relay-session/v1"
	// RelaySessionMaxLife bounds how far ahead a session may end;
	// RelaySessionSkew is the clock difference tolerated on top of it.
	RelaySessionMaxLife = 10 * time.Minute
	RelaySessionSkew    = 5 * time.Minute
	// relaySessionVersion is the payload format version.
	relaySessionVersion = 1
	// RelaySessionLen is the payload size: version, device id,
	// coordinator WireGuard key, end time (Unix seconds).
	RelaySessionLen = 1 + RelayIDLen + 32 + 8
)

// RelaySession authorizes the coordinator with key Coordinator to relay
// packets sent by Device until Expires. Which peers it may reach is decided
// by the document, never by the session.
type RelaySession struct {
	Device      [RelayIDLen]byte
	Coordinator [32]byte
	Expires     time.Time
}

// Marshal encodes the session payload.
func (s RelaySession) Marshal() []byte {
	b := make([]byte, 0, RelaySessionLen)
	b = append(b, relaySessionVersion)
	b = append(b, s.Device[:]...)
	b = append(b, s.Coordinator[:]...)
	return binary.BigEndian.AppendUint64(b, uint64(s.Expires.Unix())) //nolint:gosec // times after 1970
}

// ParseRelaySession decodes a session payload strictly.
func ParseRelaySession(b []byte) (RelaySession, error) {
	if len(b) != RelaySessionLen || b[0] != relaySessionVersion {
		return RelaySession{}, errors.New("invalid relay session")
	}
	var s RelaySession
	copy(s.Device[:], b[1:1+RelayIDLen])
	copy(s.Coordinator[:], b[1+RelayIDLen:1+RelayIDLen+32])
	sec := binary.BigEndian.Uint64(b[1+RelayIDLen+32:])
	if sec == 0 || sec > 1<<40 {
		return RelaySession{}, errors.New("invalid relay session time")
	}
	s.Expires = time.Unix(int64(sec), 0) //nolint:gosec // bounded above
	return s, nil
}

// SignRelaySession returns the payload and its signature.
func SignRelaySession(key ed25519.PrivateKey, s RelaySession) (payload, sig []byte, err error) {
	payload = s.Marshal()
	sig, err = key.Sign(nil, payload, &ed25519.Options{Context: RelaySessionContext})
	if err != nil {
		return nil, nil, err
	}
	return payload, sig, nil
}

// VerifyRelaySession checks the signature with the device's public signing
// key and decodes the payload. The caller checks device, coordinator and
// time.
func VerifyRelaySession(pub ed25519.PublicKey, payload, sig []byte) (RelaySession, error) {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return RelaySession{}, errors.New("invalid relay session signature")
	}
	s, err := ParseRelaySession(payload)
	if err != nil {
		return RelaySession{}, err
	}
	if ed25519.VerifyWithOptions(pub, payload, sig, &ed25519.Options{Context: RelaySessionContext}) != nil {
		return RelaySession{}, errors.New("invalid relay session signature")
	}
	return s, nil
}

// Device-to-device document exchange (#25) and coordinator views (#154).
// Devices send these to each other inside the tunnel, from clientPort to
// GossipPort; replies come back like any control reply. Old devices never
// answer: their packet filter drops the request.
const (
	// 4040-4050 are taken (control, info, relay, post-quantum, services).
	GossipPort = 4039
	// TypeGossipHello announces Version, Digest and Size of the sender's
	// document; Data carries the sender's coordinator views. The reply
	// carries the same for the answering device.
	TypeGossipHello = "ghello"
	// TypeGossipDoc fetches a chunk of the answering device's document,
	// like TypeDoc.
	TypeGossipDoc = "gdoc"
)

// Coordinator views (#154): what each coordinator last told a device.
const (
	coordViewVersion = 1
	// MaxCoordViews is the most views one message carries (the primary
	// plus trust.MaxExtraCoordinators).
	MaxCoordViews = 9
	// CoordKeyPrefixLen is how much of the coordinator key a view carries.
	CoordKeyPrefixLen = 8
	coordViewLen      = CoordKeyPrefixLen + 8 + 32 + 4
)

// CoordView is the document version and digest a coordinator served, and
// how many seconds ago (capped) the device last heard it.
type CoordView struct {
	Key     [CoordKeyPrefixLen]byte
	Version uint64
	Digest  [32]byte
	AgeSec  uint32
}

// EncodeCoordViews encodes at most MaxCoordViews views.
func EncodeCoordViews(views []CoordView) ([]byte, error) {
	if len(views) > MaxCoordViews {
		return nil, errors.New("too many coordinator views")
	}
	b := make([]byte, 0, 2+len(views)*coordViewLen)
	b = append(b, coordViewVersion, byte(len(views)))
	for _, v := range views {
		b = append(b, v.Key[:]...)
		b = binary.BigEndian.AppendUint64(b, v.Version)
		b = append(b, v.Digest[:]...)
		b = binary.BigEndian.AppendUint32(b, v.AgeSec)
	}
	return b, nil
}

// ParseCoordViews decodes views strictly: exact length, known format, no
// duplicate keys, versions at least 1.
func ParseCoordViews(b []byte) ([]CoordView, error) {
	if len(b) == 0 {
		return nil, nil
	}
	if len(b) < 2 || b[0] != coordViewVersion {
		return nil, errors.New("invalid coordinator views")
	}
	n := int(b[1])
	if n > MaxCoordViews || len(b) != 2+n*coordViewLen {
		return nil, errors.New("invalid coordinator views length")
	}
	out := make([]CoordView, 0, n)
	seen := make(map[[CoordKeyPrefixLen]byte]bool, n)
	for i := 0; i < n; i++ {
		p := b[2+i*coordViewLen:]
		var v CoordView
		copy(v.Key[:], p[:CoordKeyPrefixLen])
		v.Version = binary.BigEndian.Uint64(p[CoordKeyPrefixLen:])
		copy(v.Digest[:], p[CoordKeyPrefixLen+8:CoordKeyPrefixLen+40])
		v.AgeSec = binary.BigEndian.Uint32(p[CoordKeyPrefixLen+40:])
		if v.Version == 0 || seen[v.Key] {
			return nil, errors.New("invalid coordinator view")
		}
		seen[v.Key] = true
		out = append(out, v)
	}
	return out, nil
}
