// Package tpm detects a TPM 2.0 and talks to it with raw TPM 2.0 commands
// (#10, #32, ADR-0124): through tbs.dll on Windows and /dev/tpmrm0 on Linux,
// without a TPM library (ADR-0002).
//
// This version is read-only on purpose: Detect reports whether a TPM is
// present, and Query reads the fixed properties (family, manufacturer,
// firmware) with TPM2_GetCapability. Every transport is wrapped by
// readOnly, which refuses any command code other than the read-only ones
// below, so nothing in this package can create, load or persist objects,
// change hierarchies or touch NV memory. Sealing the device key (#10) and
// attestation with the endorsement key (#32) are designed in ADR-0124 and
// need a real TPM to be developed against.
package tpm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Presence describes what the operating system reports about a TPM.
type Presence struct {
	Present bool
	// Version is "2.0", "1.2" or "" when unknown.
	Version string
	// Interface is the platform's description (Windows TBS interface type,
	// or the Linux device node), for diagnostics only.
	Interface string
}

// Info holds a TPM 2.0's fixed properties.
type Info struct {
	Family          string // "2.0"
	Revision        string // specification revision, e.g. "1.59"
	Manufacturer    string // e.g. "INTC", "AMD", "MSFT", "IFX"
	VendorString    string
	FirmwareVersion string // FIRMWARE_VERSION_1.FIRMWARE_VERSION_2 in hex halves
	Year            uint32
}

// Errors.
var (
	ErrNotFound    = errors.New("no TPM found")
	ErrUnsupported = errors.New("TPM access is not implemented on this system")
	ErrNotAllowed  = errors.New("command is not on the read-only allowlist")
)

// Transport sends one marshalled TPM 2.0 command and returns the response.
type Transport interface {
	Submit(cmd []byte) ([]byte, error)
	Close() error
}

// TPM 2.0 constants (TCG TPM 2.0 Library, Part 2).
const (
	tagNoSessions     = 0x8001
	ccGetCapability   = 0x0000017A
	capTPMProperties  = 0x00000006
	ptFixed           = 0x00000100
	ptFamilyIndicator = ptFixed + 0
	ptRevision        = ptFixed + 2
	ptYear            = ptFixed + 4
	ptManufacturer    = ptFixed + 5
	ptVendorString1   = ptFixed + 6
	ptVendorString4   = ptFixed + 9
	ptFirmware1       = ptFixed + 11
	ptFirmware2       = ptFixed + 12
	maxProperties     = 64
	headerSize        = 10
	// MaxResponse bounds a response buffer (TPM2 responses are at most a
	// few kilobytes; TPM_PT_MAX_RESPONSE_SIZE is typically 4096).
	MaxResponse = 8192
)

// readOnlyCommands is the allowlist: TPM2_GetCapability only.
var readOnlyCommands = map[uint32]bool{ccGetCapability: true}

type readOnly struct{ t Transport }

func (r readOnly) Submit(cmd []byte) ([]byte, error) {
	if len(cmd) < headerSize {
		return nil, errors.New("command too short")
	}
	if cc := binary.BigEndian.Uint32(cmd[6:10]); !readOnlyCommands[cc] {
		return nil, fmt.Errorf("%w: 0x%08X", ErrNotAllowed, cc)
	}
	return r.t.Submit(cmd)
}

func (r readOnly) Close() error { return r.t.Close() }

// ReadOnly wraps t so that only allowlisted read-only commands pass.
func ReadOnly(t Transport) Transport { return readOnly{t: t} }

// encodeGetCapability marshals TPM2_GetCapability(capability, property,
// count) without sessions.
func encodeGetCapability(capability, property, count uint32) []byte {
	cmd := make([]byte, 0, 22)
	cmd = binary.BigEndian.AppendUint16(cmd, tagNoSessions)
	cmd = binary.BigEndian.AppendUint32(cmd, 22)
	cmd = binary.BigEndian.AppendUint32(cmd, ccGetCapability)
	cmd = binary.BigEndian.AppendUint32(cmd, capability)
	cmd = binary.BigEndian.AppendUint32(cmd, property)
	cmd = binary.BigEndian.AppendUint32(cmd, count)
	return cmd
}

// ResponseError is a non-zero TPM response code.
type ResponseError struct{ Code uint32 }

func (e *ResponseError) Error() string { return fmt.Sprintf("TPM response code 0x%08X", e.Code) }

// parseResponseHeader checks a response's header and returns its body.
func parseResponseHeader(resp []byte) ([]byte, error) {
	if len(resp) < headerSize {
		return nil, errors.New("TPM response too short")
	}
	size := binary.BigEndian.Uint32(resp[2:6])
	if int(size) != len(resp) {
		return nil, errors.New("TPM response size mismatch")
	}
	if rc := binary.BigEndian.Uint32(resp[6:10]); rc != 0 {
		return nil, &ResponseError{Code: rc}
	}
	if tag := binary.BigEndian.Uint16(resp[0:2]); tag != tagNoSessions {
		return nil, fmt.Errorf("unexpected TPM response tag 0x%04X", tag)
	}
	return resp[headerSize:], nil
}

// parseTaggedProperties decodes the body of a GetCapability(TPM_PROPERTIES)
// response: moreData, capability, TPML_TAGGED_TPM_PROPERTY.
func parseTaggedProperties(body []byte) (map[uint32]uint32, bool, error) {
	if len(body) < 1+4+4 {
		return nil, false, errors.New("capability data too short")
	}
	more := body[0] != 0
	if binary.BigEndian.Uint32(body[1:5]) != capTPMProperties {
		return nil, false, errors.New("unexpected capability in response")
	}
	count := binary.BigEndian.Uint32(body[5:9])
	rest := body[9:]
	if count > maxProperties*4 || uint64(len(rest)) != uint64(count)*8 {
		return nil, false, errors.New("property list length mismatch")
	}
	props := make(map[uint32]uint32, count)
	for i := uint32(0); i < count; i++ {
		props[binary.BigEndian.Uint32(rest[8*i:])] = binary.BigEndian.Uint32(rest[8*i+4:])
	}
	return props, more, nil
}

// u32String turns a property holding up to four ASCII characters into a
// string without trailing NULs and spaces.
func u32String(v uint32) string {
	b := []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7F {
			sb.WriteByte(c)
		}
	}
	return strings.TrimSpace(sb.String())
}

// Query reads the TPM's fixed properties with TPM2_GetCapability.
func Query(t Transport) (Info, error) {
	resp, err := ReadOnly(t).Submit(encodeGetCapability(capTPMProperties, ptFixed, maxProperties))
	if err != nil {
		return Info{}, err
	}
	if len(resp) > MaxResponse {
		return Info{}, errors.New("TPM response too long")
	}
	body, err := parseResponseHeader(resp)
	if err != nil {
		return Info{}, err
	}
	props, _, err := parseTaggedProperties(body)
	if err != nil {
		return Info{}, err
	}
	return infoFromProperties(props), nil
}

func infoFromProperties(props map[uint32]uint32) Info {
	var info Info
	info.Family = u32String(props[ptFamilyIndicator])
	if r, ok := props[ptRevision]; ok {
		info.Revision = fmt.Sprintf("%d.%02d", r/100, r%100)
	}
	info.Year = props[ptYear]
	info.Manufacturer = u32String(props[ptManufacturer])
	var vendor strings.Builder
	for p := uint32(ptVendorString1); p <= ptVendorString4; p++ {
		vendor.WriteString(u32String(props[p]))
	}
	info.VendorString = vendor.String()
	if f1, ok := props[ptFirmware1]; ok {
		f2 := props[ptFirmware2]
		info.FirmwareVersion = fmt.Sprintf("%d.%d.%d.%d", f1>>16, f1&0xFFFF, f2>>16, f2&0xFFFF)
	}
	return info
}
