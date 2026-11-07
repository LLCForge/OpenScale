package sysinfo

import (
	"encoding/binary"
	"strings"
)

// SMBIOS (DMTF DSP0134) table parsing, shared by Windows (the 'RSMB'
// firmware table) and Linux (/sys/firmware/dmi/tables/DMI). Only the
// fields below are read; serial numbers, asset tags and UUIDs are skipped
// on purpose (ADR-0008).

type smbiosInfo struct {
	biosVendor, biosVersion, biosDate string
	sysVendor, sysProduct             string
	boardVendor, boardProduct         string
	cpuMaxMHz, cpuCurMHz              int
	cpuCores, cpuThreads, cpuSockets  int
	memSlots                          int
	modules                           []MemModule
}

const maxSMBIOS = 1 << 20

// parseSMBIOS walks the structure table. Malformed input stops the walk
// and keeps what was read so far.
func parseSMBIOS(t []byte) smbiosInfo {
	var s smbiosInfo
	if len(t) > maxSMBIOS {
		t = t[:maxSMBIOS]
	}
	for len(t) >= 4 {
		typ, length := t[0], int(t[1])
		if length < 4 || length > len(t) {
			break
		}
		formatted := t[:length]
		// The string set follows the formatted area and ends with two NULs.
		end := length
		for end+1 < len(t) && !(t[end] == 0 && t[end+1] == 0) {
			end++
		}
		if end+1 >= len(t) {
			break
		}
		strs := splitSMBIOSStrings(t[length:end])
		s.add(typ, formatted, strs)
		if typ == 127 {
			break
		}
		t = t[end+2:]
	}
	return s
}

func splitSMBIOSStrings(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	return strings.Split(string(b), "\x00")
}

func smbiosStr(f []byte, off int, strs []string) string {
	if off >= len(f) {
		return ""
	}
	i := int(f[off])
	if i == 0 || i > len(strs) {
		return ""
	}
	return strings.TrimSpace(strs[i-1])
}

func smbiosU16(f []byte, off int) int {
	if off+2 > len(f) {
		return 0
	}
	return int(binary.LittleEndian.Uint16(f[off:]))
}

func smbiosU32(f []byte, off int) uint32 {
	if off+4 > len(f) {
		return 0
	}
	return binary.LittleEndian.Uint32(f[off:])
}

func (s *smbiosInfo) add(typ byte, f []byte, strs []string) {
	switch typ {
	case 0: // BIOS
		s.biosVendor = smbiosStr(f, 0x04, strs)
		s.biosVersion = smbiosStr(f, 0x05, strs)
		s.biosDate = smbiosStr(f, 0x08, strs)
	case 1: // System (0x07 serial and 0x08 UUID are not read)
		s.sysVendor = smbiosStr(f, 0x04, strs)
		s.sysProduct = smbiosStr(f, 0x05, strs)
	case 2: // Baseboard (0x07 serial is not read)
		if s.boardVendor == "" {
			s.boardVendor = smbiosStr(f, 0x04, strs)
			s.boardProduct = smbiosStr(f, 0x05, strs)
		}
	case 4: // Processor
		if len(f) > 0x18 && f[0x18]&0x40 == 0 {
			return // socket unpopulated
		}
		s.cpuSockets++
		if v := smbiosU16(f, 0x14); v > s.cpuMaxMHz && v < 20000 {
			s.cpuMaxMHz = v
		}
		if v := smbiosU16(f, 0x16); v > 0 && v < 20000 && s.cpuCurMHz == 0 {
			s.cpuCurMHz = v
		}
		cores, threads := 0, 0
		if len(f) > 0x25 {
			cores, threads = int(f[0x23]), int(f[0x25])
		}
		if cores == 0xFF {
			cores = smbiosU16(f, 0x2A)
		}
		if threads == 0xFF {
			threads = smbiosU16(f, 0x2E)
		}
		s.cpuCores += cores
		s.cpuThreads += threads
	case 16: // Physical memory array, system memory only
		if len(f) > 0x0E && f[0x05] == 0x03 {
			s.memSlots += smbiosU16(f, 0x0D)
		}
	case 17: // Memory device (0x18 serial and 0x19 asset tag are not read)
		if len(f) < 0x15 {
			return
		}
		size := memDeviceSize(f)
		if size == 0 {
			return // empty slot
		}
		m := MemModule{Size: size, Type: memType(f[0x12]), Form: memForm(f[0x0E])}
		speed := smbiosU16(f, 0x15)
		if cfg := smbiosU16(f, 0x20); cfg > 0 && cfg != 0xFFFF {
			speed = cfg
		}
		if speed == 0xFFFF {
			speed = int(smbiosU32(f, 0x54))
		}
		m.MHz = speed
		if len(s.modules) < maxModules {
			s.modules = append(s.modules, m)
		}
	}
}

// memDeviceSize decodes the type 17 size field in bytes; 0 means empty or
// unknown.
func memDeviceSize(f []byte) uint64 {
	v := smbiosU16(f, 0x0C)
	switch {
	case v == 0 || v == 0xFFFF:
		return 0
	case v == 0x7FFF:
		return uint64(smbiosU32(f, 0x1C)&0x7FFFFFFF) << 20
	case v&0x8000 != 0:
		return uint64(v&0x7FFF) << 10
	}
	return uint64(v) << 20
}

func memType(c byte) string {
	switch c {
	case 0x0F:
		return "SDRAM"
	case 0x12:
		return "DDR"
	case 0x13:
		return "DDR2"
	case 0x18:
		return "DDR3"
	case 0x1A:
		return "DDR4"
	case 0x1B:
		return "LPDDR"
	case 0x1C:
		return "LPDDR2"
	case 0x1D:
		return "LPDDR3"
	case 0x1E:
		return "LPDDR4"
	case 0x20:
		return "HBM"
	case 0x21:
		return "HBM2"
	case 0x22:
		return "DDR5"
	case 0x23:
		return "LPDDR5"
	case 0x24:
		return "HBM3"
	}
	return ""
}

func memForm(c byte) string {
	switch c {
	case 0x09:
		return "DIMM"
	case 0x0D:
		return "SODIMM"
	case 0x0B:
		return "RIMM"
	case 0x0F:
		return "FB-DIMM"
	case 0x10:
		return "Die"
	case 0x11:
		return "CAMM"
	}
	return ""
}

// biosDate converts the SMBIOS "MM/DD/YYYY" (or "MM/DD/YY") release date
// to "YYYY-MM-DD"; anything else becomes "".
func biosDate(s string) string {
	parts := strings.Split(strings.TrimSpace(s), "/")
	if len(parts) != 3 || len(parts[0]) != 2 || len(parts[1]) != 2 {
		return ""
	}
	y := parts[2]
	if len(y) == 2 {
		y = "19" + y
		if y < "1980" {
			y = "20" + parts[2]
		}
	}
	d := y + "-" + parts[0] + "-" + parts[1]
	if !validDate(d) {
		return ""
	}
	return d
}

// cleanFirmwareText drops the placeholders firmware vendors leave in
// SMBIOS strings.
func cleanFirmwareText(s string) string {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "to be filled by o.e.m.", "default string", "not applicable", "none", "n/a",
		"system manufacturer", "system product name", "base board manufacturer", "base board product name",
		"not specified", "oem", "o.e.m.", "unknown":
		return ""
	}
	return s
}
