package portmap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// PCP (RFC 6887): MAP and ANNOUNCE opcodes for UDP over IPv4.

const (
	pcpVersion     = 2
	pcpOpAnnounce  = 0
	pcpOpMap       = 1
	pcpResponseBit = 0x80
	pcpHeaderLen   = 24
	pcpMapLen      = 36
	pcpNonceLen    = 12
	protoUDP       = 17
	// pcpMaxPacket is the largest PCP message (RFC 6887 §7).
	pcpMaxPacket = 1100
)

// PCP result codes (RFC 6887 §7.4).
const (
	pcpSuccess              = 0
	pcpUnsuppVersion        = 1
	pcpNotAuthorized        = 2
	pcpMalformedRequest     = 3
	pcpUnsuppOpcode         = 4
	pcpUnsuppOption         = 5
	pcpMalformedOption      = 6
	pcpNetworkFailure       = 7
	pcpNoResources          = 8
	pcpUnsuppProtocol       = 9
	pcpUserExQuota          = 10
	pcpCannotProvideExt     = 11
	pcpAddressMismatch      = 12
	pcpExcessiveRemotePeers = 13
)

var pcpResultNames = map[uint8]string{
	pcpUnsuppVersion: "UNSUPP_VERSION", pcpNotAuthorized: "NOT_AUTHORIZED", pcpMalformedRequest: "MALFORMED_REQUEST",
	pcpUnsuppOpcode: "UNSUPP_OPCODE", pcpUnsuppOption: "UNSUPP_OPTION", pcpMalformedOption: "MALFORMED_OPTION",
	pcpNetworkFailure: "NETWORK_FAILURE", pcpNoResources: "NO_RESOURCES", pcpUnsuppProtocol: "UNSUPP_PROTOCOL",
	pcpUserExQuota: "USER_EX_QUOTA", pcpCannotProvideExt: "CANNOT_PROVIDE_EXTERNAL", pcpAddressMismatch: "ADDRESS_MISMATCH",
	pcpExcessiveRemotePeers: "EXCESSIVE_REMOTE_PEERS",
}

// errNATPMPOnly means a PCP request was answered by a server that speaks
// only NAT-PMP (a version 0 "unsupported version" reply, RFC 6887 §9).
var errNATPMPOnly = errors.New("ağ geçidi yalnızca NAT-PMP konuşuyor")

// errMalformed is returned for a packet that is not a valid reply.
var errMalformed = errors.New("geçersiz yanıt")

// putAddr16 writes a as a 16-byte (IPv4-mapped for IPv4) address.
func putAddr16(b []byte, a netip.Addr) {
	raw := a.As16() // IPv4 addresses come out IPv4-mapped
	copy(b, raw[:])
}

// pcpHeader writes the common request header.
func pcpHeader(b []byte, op uint8, lifetime uint32, client netip.Addr) {
	b[0] = pcpVersion
	b[1] = op
	b[2], b[3] = 0, 0
	binary.BigEndian.PutUint32(b[4:8], lifetime)
	putAddr16(b[8:24], client)
}

// pcpMapRequest builds a MAP request for UDP. suggest may be the zero
// AddrPort for "no preference".
func pcpMapRequest(client netip.Addr, nonce [pcpNonceLen]byte, internal uint16, suggest netip.AddrPort, lifetime uint32) []byte {
	b := make([]byte, pcpHeaderLen+pcpMapLen)
	pcpHeader(b, pcpOpMap, lifetime, client)
	m := b[pcpHeaderLen:]
	copy(m[0:12], nonce[:])
	m[12] = protoUDP
	binary.BigEndian.PutUint16(m[16:18], internal)
	ext := netip.IPv4Unspecified()
	var port uint16
	if suggest.IsValid() {
		ext, port = suggest.Addr(), suggest.Port()
	}
	binary.BigEndian.PutUint16(m[18:20], port)
	putAddr16(m[20:36], ext)
	return b
}

// pcpAnnounceRequest builds an ANNOUNCE request, used to read the epoch.
func pcpAnnounceRequest(client netip.Addr) []byte {
	b := make([]byte, pcpHeaderLen)
	pcpHeader(b, pcpOpAnnounce, 0, client)
	return b
}

// pcpResponse is a parsed PCP response.
type pcpResponse struct {
	op       uint8
	result   uint8
	lifetime uint32
	epoch    uint32
	// MAP only:
	nonce    [pcpNonceLen]byte
	proto    uint8
	internal uint16
	external netip.AddrPort
}

// parsePCPResponse parses a PCP response. A NAT-PMP "unsupported version"
// reply yields errNATPMPOnly.
func parsePCPResponse(b []byte) (pcpResponse, error) {
	var r pcpResponse
	if len(b) >= 4 && b[0] == natpmpVersion && b[1]&natpmpResponseBit != 0 {
		if binary.BigEndian.Uint16(b[2:4]) == natpmpUnsupportedVersion {
			return r, errNATPMPOnly
		}
		return r, errMalformed
	}
	if len(b) < pcpHeaderLen || len(b) > pcpMaxPacket || len(b)%4 != 0 {
		return r, errMalformed
	}
	if b[0] != pcpVersion || b[1]&pcpResponseBit == 0 {
		return r, errMalformed
	}
	r.op = b[1] &^ pcpResponseBit
	r.result = b[3]
	r.lifetime = binary.BigEndian.Uint32(b[4:8])
	r.epoch = binary.BigEndian.Uint32(b[8:12])
	if r.op != pcpOpMap {
		return r, nil
	}
	if len(b) < pcpHeaderLen+pcpMapLen {
		if r.result != pcpSuccess {
			// Error replies may be shortened (RFC 6887 §8.3 says the
			// opcode payload is copied, but be lenient).
			return r, nil
		}
		return r, errMalformed
	}
	m := b[pcpHeaderLen:]
	copy(r.nonce[:], m[0:12])
	r.proto = m[12]
	r.internal = binary.BigEndian.Uint16(m[16:18])
	port := binary.BigEndian.Uint16(m[18:20])
	var raw [16]byte
	copy(raw[:], m[20:36])
	r.external = netip.AddrPortFrom(netip.AddrFrom16(raw).Unmap(), port)
	return r, nil
}

// pcpError turns a non-success result into an error.
func pcpError(code uint8) error {
	name, ok := pcpResultNames[code]
	if !ok {
		name = "bilinmeyen"
	}
	return fmt.Errorf("PCP hata kodu %d (%s)", code, name)
}
