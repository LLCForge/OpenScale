package sysinfo

import (
	"encoding/binary"
	"strings"
)

// EDID (VESA E-EDID 1.3/1.4) parsing for the monitor's model name and
// native mode. The serial number descriptor (0xFF) and the binary serial
// field are never read (ADR-0008).

func parseEDID(b []byte) (Display, bool) {
	header := []byte{0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00}
	if len(b) < 128 || string(b[:8]) != string(header) {
		return Display{}, false
	}
	var d Display
	for i := 0; i < 4; i++ {
		desc := b[54+18*i : 54+18*(i+1)]
		clock := int(binary.LittleEndian.Uint16(desc))
		if clock != 0 {
			if d.W != 0 {
				continue
			}
			hact := int(desc[2]) | int(desc[4]&0xF0)<<4
			hblank := int(desc[3]) | int(desc[4]&0x0F)<<8
			vact := int(desc[5]) | int(desc[7]&0xF0)<<4
			vblank := int(desc[6]) | int(desc[7]&0x0F)<<8
			d.W, d.H = hact, vact
			if total := (hact + hblank) * (vact + vblank); total > 0 {
				d.Hz = (clock*10000 + total/2) / total
			}
			continue
		}
		if desc[3] == 0xFC { // monitor name
			name := string(desc[5:18])
			if j := strings.IndexByte(name, '\n'); j >= 0 {
				name = name[:j]
			}
			d.Name = strings.TrimSpace(name)
		}
	}
	if d.W == 0 || d.H == 0 {
		return Display{}, false
	}
	if d.Name == "" {
		d.Name = edidVendor(b[8], b[9])
	}
	return d, true
}

// edidVendor decodes the three-letter PNP manufacturer code.
func edidVendor(hi, lo byte) string {
	v := uint16(hi)<<8 | uint16(lo)
	r := []byte{byte(v>>10&0x1F) + 'A' - 1, byte(v>>5&0x1F) + 'A' - 1, byte(v&0x1F) + 'A' - 1}
	for _, c := range r {
		if c < 'A' || c > 'Z' {
			return ""
		}
	}
	return string(r)
}
