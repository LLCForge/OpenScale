// Package control defines the coordinator control protocol (ADR-0013):
// small JSON datagrams sent inside the WireGuard tunnel to the
// coordinator's overlay IPv4 address on Port.
package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	// Port is the UDP port of the control service inside the tunnel.
	Port = 4040
	// ProtocolVersion is carried in every message.
	ProtocolVersion = 1
	// MaxDatagram bounds every encoded message.
	MaxDatagram = 1200
	// ChunkSize is the number of document bytes per doc/put message.
	ChunkSize = 700
	// PeersPerPage bounds the peers listed in one response.
	PeersPerPage = 8
)

// Message types.
const (
	TypeHello = "hello"
	TypeDoc   = "doc"
	TypePut   = "put"
	TypePeers = "peers"
	TypeError = "error"
	// TypeEnroll carries a signed invite enrollment from a new device
	// (ADR-0014); only accepted from invite peers.
	TypeEnroll = "enroll"
	// TypePending lists pending invite enrollments; only answered for
	// devices with the admin role.
	TypePending = "pending"
	// TypeInfo asks for a system report (internal/sysinfo). Admin devices
	// send it to the coordinator and, on InfoPort, to other devices.
	TypeInfo = "info"
	// TypeInfoDetail fetches one chunk of the detailed inventory announced
	// in a system report (ADR-0143): the request carries the announced
	// identifier in Digest and the byte Offset; the reply carries the
	// chunk in Data, the compressed size in Total and the identifier
	// actually served in Digest. Only sent to devices whose report
	// announced it, so old devices never see it.
	TypeInfoDetail = "infod"

	// Extensions (ADR-0025, ADR-0026). Old coordinators answer them with
	// "unknown message type" because the request carries only fields they
	// know; new fields appear only in requests and replies of these types,
	// so an old peer never has to decode one.

	// TypeCaps asks the coordinator for its Features. It also subscribes
	// this device to pushed messages (TypeNotify, TypeCall) for SubscriptionTTL.
	TypeCaps = "caps"
	// TypeCandidates reports this device's endpoint candidates (Cands).
	TypeCandidates = "cand"
	// TypePeerCandidates pages through the peers' observed endpoints and
	// candidates (PeerCands), like TypePeers.
	TypePeerCandidates = "pcand"
	// TypeCall asks the coordinator to make Target probe this device now
	// (simultaneous hole punching). Pushed to Target with this device's id
	// in Target and its candidates in Cands.
	TypeCall = "call"
	// TypeNotify is pushed when the document version changes (Version,
	// Digest, Size, as in a hello reply). It is only a hint to sync now.
	TypeNotify = "notify"
	// TypeDocGzip is TypeDoc for the gzip-compressed envelope: Total is the
	// compressed size; the device checks the decompressed digest.
	TypeDocGzip = "docz"
)

// Feature names returned in a TypeCaps reply.
const (
	FeatureCandidates = "cand"
	FeatureCall       = "call"
	FeatureNotify     = "notify"
	FeatureDocGzip    = "docz"
)

// PushPort is the device-side UDP port, inside the tunnel, that receives
// messages pushed by the coordinator (from Port). Old devices drop every
// packet from the coordinator that is not a reply they wait for.
const PushPort = 40405

// Limits of the extension fields.
const (
	// MaxCandidates bounds the candidates of one device.
	MaxCandidates = 8
	// MaxCandidateLen bounds one candidate ("[v6]:port" is at most 47).
	MaxCandidateLen = 64
	// MaxFeatures bounds the features list.
	MaxFeatures = 16
	maxNameLen  = 64
	// SubscriptionTTL is how long a TypeCaps request keeps a device
	// subscribed to pushed messages.
	SubscriptionTTL = 3 * time.Minute
)

// InfoPort is the UDP port, inside the tunnel, on which a device answers
// TypeInfo requests from admin devices. It never reaches the OS.
const InfoPort = 4041

// Relay datagrams (ADR-0017) travel inside the tunnel between a device and
// the coordinator on RelayPort. The payload is a 16-byte device id (the
// destination when sent to the coordinator, the source when delivered)
// followed by one end-to-end WireGuard packet.
const (
	RelayPort       = 4042
	RelayIDLen      = 16
	RelayMaxPayload = RelayIDLen + 2048
)

// signatureSize is the size of an Ed25519 signature.
const signatureSize = 64

// Message is both request and response; unused fields are omitted.
type Message struct {
	V        int            `json:"v"`
	T        string         `json:"t"`
	ID       uint32         `json:"id"`
	Version  uint64         `json:"version,omitempty"`
	Digest   string         `json:"digest,omitempty"`
	Size     int            `json:"size,omitempty"`
	Endpoint string         `json:"endpoint,omitempty"`
	Offset   int            `json:"offset,omitempty"`
	Total    int            `json:"total,omitempty"`
	Data     []byte         `json:"data,omitempty"`
	Peers    []PeerEndpoint `json:"peers,omitempty"`
	Next     int            `json:"next,omitempty"`
	Complete bool           `json:"complete,omitempty"`
	Error    string         `json:"error,omitempty"`
	// Sig and InviteSig are the device and invite signatures of an
	// enrollment carried in Data.
	Sig       []byte `json:"sig,omitempty"`
	InviteSig []byte `json:"isig,omitempty"`

	// Extension fields (ADR-0025, ADR-0026); see the extension types.
	Features  []string         `json:"features,omitempty"`
	Cands     []string         `json:"cands,omitempty"`
	PeerCands []PeerCandidates `json:"pcands,omitempty"`
	Target    string           `json:"target,omitempty"`

	// Release mirror fields (ADR-0225, release.go): only in TypeRelease and
	// TypeReleaseFile messages, which old peers never receive.
	File    string `json:"file,omitempty"`
	Release string `json:"rel,omitempty"`
	// Source and Checked tell where the coordinator's mirror follows
	// releases from ("github.com/owner/repo", set by the owner) and when it
	// last looked (Unix seconds); only in TypeRelease replies.
	Source  string `json:"src,omitempty"`
	Checked int64  `json:"chk,omitempty"`

	// Sealed candidate fields (ADR-0230, sealed.go): only in TypeSealed and
	// TypePeerSealed messages, which old peers never receive.
	Sealed     []byte       `json:"seal,omitempty"`
	PeerSealed []PeerSealed `json:"pseal,omitempty"`
}

// PeerCandidates is a peer's observed endpoint and reported candidates.
type PeerCandidates struct {
	ID       string   `json:"id"`
	Endpoint string   `json:"endpoint,omitempty"`
	Cands    []string `json:"cands,omitempty"`
}

// PeerEndpoint is the observed public endpoint of a peer device.
type PeerEndpoint struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
}

// Encode marshals m and enforces the datagram size limit.
func Encode(m Message) ([]byte, error) {
	m.V = ProtocolVersion
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("encode control message: %w", err)
	}
	if len(data) > MaxDatagram {
		return nil, errors.New("control message exceeds the datagram limit")
	}
	return data, nil
}

// Decode strictly unmarshals a datagram.
func Decode(data []byte) (Message, error) {
	if len(data) > MaxDatagram {
		return Message{}, errors.New("control message too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Message
	if err := dec.Decode(&m); err != nil {
		return Message{}, fmt.Errorf("decode control message: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Message{}, errors.New("trailing data in control message")
	}
	if m.V != ProtocolVersion {
		return Message{}, fmt.Errorf("unsupported control protocol version %d", m.V)
	}
	if m.Offset < 0 || m.Total < 0 || m.Size < 0 || m.Next < 0 || len(m.Peers) > PeersPerPage || len(m.Data) > ChunkSize ||
		len(m.Sig) > signatureSize || len(m.InviteSig) > signatureSize {
		return Message{}, errors.New("control message field out of range")
	}
	if !validExtensions(m) {
		return Message{}, errors.New("control message extension out of range")
	}
	return m, nil
}

func validExtensions(m Message) bool {
	if len(m.Features) > MaxFeatures || len(m.Target) > maxNameLen || len(m.PeerCands) > PeersPerPage || !validCands(m.Cands) || !validReleaseFields(m) || !validSealedFields(m) {
		return false
	}
	for _, f := range m.Features {
		if f == "" || len(f) > maxNameLen {
			return false
		}
	}
	for _, p := range m.PeerCands {
		if p.ID == "" || len(p.ID) > maxNameLen || len(p.Endpoint) > MaxCandidateLen || !validCands(p.Cands) {
			return false
		}
	}
	return true
}

func validCands(c []string) bool {
	if len(c) > MaxCandidates {
		return false
	}
	for _, s := range c {
		if s == "" || len(s) > MaxCandidateLen {
			return false
		}
	}
	return true
}

// EncodedSize returns the encoded size of m, or MaxDatagram+1 when it
// cannot be encoded; pages are filled up to the datagram limit with it.
func EncodedSize(m Message) int {
	m.V = ProtocolVersion
	data, err := json.Marshal(m)
	if err != nil {
		return MaxDatagram + 1
	}
	return len(data)
}
