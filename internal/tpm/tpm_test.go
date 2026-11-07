package tpm

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

type fakeTPM struct {
	resp []byte
	got  []byte
}

func (f *fakeTPM) Submit(cmd []byte) ([]byte, error) {
	f.got = append([]byte(nil), cmd...)
	return f.resp, nil
}
func (f *fakeTPM) Close() error { return nil }

func capabilityResponse(props [][2]uint32) []byte {
	body := []byte{0}
	body = binary.BigEndian.AppendUint32(body, capTPMProperties)
	body = binary.BigEndian.AppendUint32(body, uint32(len(props)))
	for _, p := range props {
		body = binary.BigEndian.AppendUint32(body, p[0])
		body = binary.BigEndian.AppendUint32(body, p[1])
	}
	resp := binary.BigEndian.AppendUint16(nil, tagNoSessions)
	resp = binary.BigEndian.AppendUint32(resp, uint32(headerSize+len(body)))
	resp = binary.BigEndian.AppendUint32(resp, 0)
	return append(resp, body...)
}

func TestGetCapabilityEncoding(t *testing.T) {
	got := hex.EncodeToString(encodeGetCapability(capTPMProperties, ptFixed, maxProperties))
	want := "8001" + "00000016" + "0000017a" + "00000006" + "00000100" + "00000040"
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestQueryParsesFixedProperties(t *testing.T) {
	f := &fakeTPM{resp: capabilityResponse([][2]uint32{
		{ptFamilyIndicator, 0x322E3000}, // "2.0\0"
		{ptRevision, 159},
		{ptYear, 2023},
		{ptManufacturer, 0x494E5443}, // "INTC"
		{ptVendorString1, 0x496E7465}, {ptVendorString1 + 1, 0x6C000000},
		{ptFirmware1, 0x000B0001}, {ptFirmware2, 0x00020003},
	})}
	info, err := Query(f)
	if err != nil {
		t.Fatal(err)
	}
	if info.Family != "2.0" || info.Revision != "1.59" || info.Manufacturer != "INTC" || info.VendorString != "Intel" ||
		info.FirmwareVersion != "11.1.2.3" || info.Year != 2023 {
		t.Fatalf("got %+v", info)
	}
}

func TestQueryRejectsBadResponses(t *testing.T) {
	good := capabilityResponse([][2]uint32{{ptManufacturer, 1}})
	bad := map[string][]byte{
		"short":     good[:5],
		"size":      append(append([]byte(nil), good...), 0),
		"rc":        func() []byte { b := append([]byte(nil), good...); b[9] = 0x01; return b }(),
		"count":     func() []byte { b := append([]byte(nil), good...); b[headerSize+8] = 9; return b }(),
		"cap":       func() []byte { b := append([]byte(nil), good...); b[headerSize+4] = 7; return b }(),
		"tag":       func() []byte { b := append([]byte(nil), good...); b[1] = 0x02; return b }(),
		"truncated": capabilityResponse(nil)[:headerSize+3],
	}
	for name, resp := range bad {
		if _, err := Query(&fakeTPM{resp: resp}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var re *ResponseError
	b := append([]byte(nil), good...)
	binary.BigEndian.PutUint32(b[6:], 0x101)
	if _, err := Query(&fakeTPM{resp: b}); !errors.As(err, &re) || re.Code != 0x101 {
		t.Errorf("response code: %v", err)
	}
}

func TestReadOnlyAllowlist(t *testing.T) {
	f := &fakeTPM{}
	ro := ReadOnly(f)
	for _, cc := range []uint32{
		0x00000153, // TPM2_Create
		0x00000131, // TPM2_CreatePrimary
		0x00000137, // TPM2_NV_Write
		0x00000126, // TPM2_Clear
		0x00000121, // TPM2_EvictControl
		0x0000015E, // TPM2_Unseal
	} {
		cmd := binary.BigEndian.AppendUint16(nil, tagNoSessions)
		cmd = binary.BigEndian.AppendUint32(cmd, 10)
		cmd = binary.BigEndian.AppendUint32(cmd, cc)
		if _, err := ro.Submit(cmd); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("command 0x%X passed: %v", cc, err)
		}
	}
	if f.got != nil {
		t.Fatal("a refused command reached the transport")
	}
}

// TestProbeThisMachine runs only with OPENSCALE_TPM_PROBE=1. It is read-only:
// Detect asks TBS or sysfs, Query sends TPM2_GetCapability.
func TestProbeThisMachine(t *testing.T) {
	if os.Getenv("OPENSCALE_TPM_PROBE") != "1" {
		t.Skip("set OPENSCALE_TPM_PROBE=1 to probe the local TPM (read-only)")
	}
	p, err := Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	t.Logf("presence: %+v", p)
	if !p.Present || p.Version != "2.0" {
		return
	}
	tr, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer tr.Close()
	info, err := Query(tr)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	t.Logf("info: %+v", info)
}

func FuzzParseCapability(f *testing.F) {
	f.Add(capabilityResponse([][2]uint32{{ptManufacturer, 0x414D4420}}))
	f.Add([]byte{0x80, 0x01, 0, 0, 0, 10, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, resp []byte) {
		info, err := Query(&fakeTPM{resp: resp})
		if err != nil {
			return
		}
		if len(info.Manufacturer) > 4 || len(info.VendorString) > 16 {
			t.Fatal("property strings longer than their fields")
		}
	})
}
