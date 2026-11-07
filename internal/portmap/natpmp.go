package portmap

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// NAT-PMP (RFC 6886): external address and UDP mapping requests.

const (
	natpmpVersion            = 0
	natpmpOpExternal         = 0
	natpmpOpMapUDP           = 1
	natpmpResponseBit        = 0x80
	natpmpUnsupportedVersion = 1
	natpmpMaxPacket          = 16
)

var natpmpResultNames = map[uint16]string{
	1: "desteklenmeyen sürüm", 2: "yetkisiz/reddedildi", 3: "ağ hatası", 4: "kaynak yok", 5: "desteklenmeyen işlem",
}

// natpmpExternalRequest asks for the gateway's external address.
func natpmpExternalRequest() []byte { return []byte{natpmpVersion, natpmpOpExternal} }

// natpmpMapRequest asks for (or, with lifetime 0, deletes) a UDP mapping.
func natpmpMapRequest(internal, suggest uint16, lifetime uint32) []byte {
	b := make([]byte, 12)
	b[0], b[1] = natpmpVersion, natpmpOpMapUDP
	binary.BigEndian.PutUint16(b[4:6], internal)
	binary.BigEndian.PutUint16(b[6:8], suggest)
	binary.BigEndian.PutUint32(b[8:12], lifetime)
	return b
}

// natpmpResponse is a parsed NAT-PMP response.
type natpmpResponse struct {
	op     uint8
	result uint16
	epoch  uint32
	// external is set for the external address reply.
	external netip.Addr
	// internal, mapped and lifetime are set for the mapping reply.
	internal uint16
	mapped   uint16
	lifetime uint32
}

// parseNATPMPResponse parses a NAT-PMP response.
func parseNATPMPResponse(b []byte) (natpmpResponse, error) {
	var r natpmpResponse
	if len(b) < 8 || len(b) > natpmpMaxPacket || b[0] != natpmpVersion || b[1]&natpmpResponseBit == 0 {
		return r, errMalformed
	}
	r.op = b[1] &^ natpmpResponseBit
	r.result = binary.BigEndian.Uint16(b[2:4])
	r.epoch = binary.BigEndian.Uint32(b[4:8])
	if r.result != 0 {
		return r, nil
	}
	switch r.op {
	case natpmpOpExternal:
		if len(b) != 12 {
			return r, errMalformed
		}
		r.external = netip.AddrFrom4([4]byte(b[8:12]))
	case natpmpOpMapUDP:
		if len(b) != 16 {
			return r, errMalformed
		}
		r.internal = binary.BigEndian.Uint16(b[8:10])
		r.mapped = binary.BigEndian.Uint16(b[10:12])
		r.lifetime = binary.BigEndian.Uint32(b[12:16])
	default:
		return r, errMalformed
	}
	return r, nil
}

// natpmpError turns a non-zero result into an error.
func natpmpError(code uint16) error {
	name, ok := natpmpResultNames[code]
	if !ok {
		name = "bilinmeyen"
	}
	return fmt.Errorf("NAT-PMP hata kodu %d (%s)", code, name)
}
